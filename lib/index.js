/**
 * dsh-lan-peers 闁?LAN peer discovery for DeepSeek Harness.
 *
 * What it does
 * ------------
 * 1. Announces this DSH host on the local network over UDP broadcast
 *    (`LAN_PEERS_DISCOVERY_PORT`, default 48901) every few seconds, and listens
 *    for other hosts doing the same.
 * 2. Keeps an auto-maintained peer table (name, ip, http port, version, last
 *    seen, online/offline), persisted under `~/.dsh/lan-peers/peers.json`.
 * 3. Serves a tiny HTTP mailbox on `0.0.0.0:<httpPort>` (default 48902) so a
 *    peer can post a message to *this* agent and read the acknowledgment.
 * 4. Registers four tools so the model can use discovered peers without any
 *    manual peer configuration:
 *      - `lan_peers`      list discovered peers + mailbox status
 *      - `lan_send`       send a message to a peer (resolved by name or id)
 *      - `lan_inbox`      read messages peers sent to this host
 *      - `lan_ping`       re-announce / probe now, useful right after boot
 *
 * Design notes
 * ------------
 * - No `@deepseek-ai/*` imports at runtime: a `link:`-ed plugin is loaded from
 *   its real path, so harness imports would resolve upward from a checkout that
 *   does not exist. Tools are plain object literals, registered through
 *   `ctx.inject(['tools'], ...)` so cold start ordering cannot race us.
 * - The DSH web server itself listens on 127.0.0.1 only, so peer-to-peer traffic
 *   gets its own `0.0.0.0` HTTP listener instead of reusing DSH routes.
 * - Everything this plugin starts is registered as an `ctx.effect` disposer, so
 *   disabling the plugin or hot-reloading the profile closes the sockets and
 *   frees the ports.
 *
 * @module dsh-lan-peers
 */

import dgram from 'node:dgram'
import http from 'node:http'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

export const name = 'dsh-lan-peers'

/** cordis 4.0.5 throws when reading an un-injected service property, so probe defensively. */
function hasService(ctx, name) {
  try {
    return Boolean(ctx && ctx[name])
  } catch {
    return false
  }
}
function bootLine(message) {
  try {
    const home = process.env.DSH_LAN_PEERS_HOME || path.join(os.homedir(), '.dsh', 'lan-peers')
    fs.mkdirSync(home, { recursive: true })
    fs.appendFileSync(path.join(home, 'boot.log'), `[${new Date().toISOString()}] ${message}\n`, 'utf8')
  } catch (error) {
  }
}

/** Open object schema for tool results: every tool returns a JSON object. */
const VALUE_SCHEMA = { type: 'object', additionalProperties: true }

/** Wire format version for announce packets and the HTTP mailbox. */
const PROTOCOL = 1

const DEFAULTS = {
  discoveryPort: 48901,
  httpPort: 48902,
  intervalMs: 7000,
  ttlMs: 30000,
  name: '',
  maxTextChars: 8000,
  maxInbox: 500,
}

/** One runtime per host process; a re-apply disposes the previous one first. */
let current = null

/**
 * Mount the plugin.
 * @param {object} ctx - cordis context carrying `tools`, `logger`.
 * @param {object} config - optional `config:` block from the loader row.
 */
export function apply(ctx, config = {}) {
  try {
    return applyInner(ctx, config)
  } catch (error) {
    throw error
  }
}

function applyInner(ctx, config = {}) {
  let settings
  try {
    settings = resolveConfig(config)
  } catch (error) {
    bootLine(`apply rejected: ${String(error?.message ?? error)}`)
    throw error
  }

  if (current) {
    try {
      current.stop()
    } catch {
      /* previous runtime already torn down */
    }
    current = null
  }

  bootLine(`apply: tools=${hasService(ctx, 'tools')} inject=${typeof ctx?.inject}`)
  const runtime = createRuntime(ctx, settings)
  runtime.start()
  current = runtime
  bootLine(`runtime started: discovery=udp/${settings.discoveryPort} mailbox=http/0.0.0.0:${settings.httpPort} tools=${runtime.toolNames().length}`)

  attachTools(ctx, runtime, settings)

  const dispose = () => {
    runtime.stop()
    if (current === runtime) current = null
  }
  if (typeof ctx.effect === 'function') ctx.effect(() => dispose)
  else if (typeof ctx.on === 'function') ctx.on('dispose', dispose)
}

/** 工具层可能晚于 apply 出现：立刻试、走 ctx.inject 等依赖、再按秒重试。 */
function attachTools(ctx, runtime, settings) {
  const attempt = (toolCtx) => {
    if (runtime.toolNames().length > 0) return true
    runtime.registerToolset(toolCtx)
    if (runtime.toolNames().length > 0) {
      bootLine(`tools registered: ${runtime.toolNames().join(', ')}`)
      return true
    }
    return false
  }
  if (attempt(ctx)) return
  if (typeof ctx.inject === 'function') {
    try {
      ctx.inject(['tools'], (toolCtx) => attempt(toolCtx))
    } catch (error) {
      bootLine(`ctx.inject failed: ${String(error?.message ?? error)}`)
    }
  }
  let tries = 0
  const timer = setInterval(() => {
    tries += 1
    const done = attempt(ctx)
    if (done || tries >= 15) {
      clearInterval(timer)
      if (!done) bootLine('tools never became available')
    }
  }, 1000)
  timer.unref?.()
}

/** Validate and default the loader row's `config:` block. */
function resolveConfig(config) {
  const settings = { ...DEFAULTS }
  for (const key of ['discoveryPort', 'httpPort', 'intervalMs', 'ttlMs', 'maxTextChars', 'maxInbox']) {
    const value = config?.[key]
    if (value === undefined) continue
    if (!Number.isInteger(value) || value < 1) throw new Error(`dsh-lan-peers: ${key} must be a positive integer`)
    settings[key] = value
  }
  if (typeof config?.name === 'string' && config.name.trim()) settings.name = config.name.trim()
  return settings
}

/** Home for identity, the peer table, the log and the inbox. */
function stateDir() {
  const home = process.env.DSH_LAN_PEERS_HOME || path.join(os.homedir(), '.dsh', 'lan-peers')
  fs.mkdirSync(home, { recursive: true })
  return home
}

/** Stable synthetic-free node id, persisted so peers keep recognizing us. */
function loadIdentity(dir) {
  const file = path.join(dir, 'identity.json')
  try {
    const raw = JSON.parse(fs.readFileSync(file, 'utf8'))
    if (typeof raw?.id === 'string' && raw.id) return raw
  } catch {
    /* first run or unreadable file: regenerate below */
  }
  const identity = { id: crypto.randomUUID(), createdAt: new Date().toISOString() }
  writeJson(file, identity)
  return identity
}

function writeJson(file, value) {
  try {
    fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8')
  } catch {
    /* persistence is best effort; never break the agent turn over it */
  }
}

/** Every IPv4 broadcast address this machine can reach (plus the universal one). */
function broadcastAddresses() {
  const out = new Set(['255.255.255.255'])
  for (const list of Object.values(os.networkInterfaces())) {
    for (const entry of list ?? []) {
      if (entry.family !== 'IPv4' || entry.internal) continue
      const ip = entry.address.split('.').map(Number)
      const mask = entry.netmask.split('.').map(Number)
      if (ip.length !== 4 || mask.length !== 4) continue
      out.add(ip.map((part, index) => (part & mask[index]) | (~mask[index] & 255)).join('.'))
    }
  }
  return [...out]
}

/** First non-internal IPv4 address, used as the advertised address. */
function primaryIPv4() {
  for (const list of Object.values(os.networkInterfaces())) {
    for (const entry of list ?? []) {
      if (entry.family === 'IPv4' && !entry.internal) return entry.address
    }
  }
  return '127.0.0.1'
}

function renderToolValue(_args, value) {
  const text = typeof value?.message === 'string' ? value.message : JSON.stringify(value)
  return [{ type: 'text', text }]
}

function createRuntime(ctx, settings) {
  const dir = stateDir()
  const logFile = path.join(dir, 'lan-peers.log')
  const peersFile = path.join(dir, 'peers.json')
  const inboxFile = path.join(dir, 'inbox.jsonl')
  const statusFile = path.join(dir, 'status.json')
  const identity = loadIdentity(dir)
  const displayName = settings.name || os.hostname()

  /** id -> peer record */
  const peers = new Map()
  /** tool names this runtime actually registered with the harness */
  const registered = []
  let udp = null
  let server = null
  let timer = null
  let stopped = false

  function log(message) {
    const line = `[${new Date().toISOString()}] ${message}`
    try {
      fs.appendFileSync(logFile, `${line}\n`, 'utf8')
    } catch {
      /* logging must never throw into the host */
    }
    try {
      ctx.logger?.info?.(`[lan-peers] ${message}`)
    } catch {
      /* logger optional */
    }
  }

  function advertise() {
    if (!udp || stopped) return
    const packet = Buffer.from(
      JSON.stringify({
        v: PROTOCOL,
        kind: 'announce',
        id: identity.id,
        name: displayName,
        version: '0.1.0',
        httpPort: settings.httpPort,
        address: primaryIPv4(),
        tools: ['lan_peers', 'lan_send', 'lan_inbox', 'lan_ping'],
        ts: Date.now(),
      }),
      'utf8',
    )
    for (const address of broadcastAddresses()) {
      try {
        udp.send(packet, 0, packet.length, settings.discoveryPort, address)
      } catch {
        /* an interface without broadcast support is not an error */
      }
    }
  }

  function online(peer) {
    return Date.now() - peer.lastSeen <= settings.ttlMs
  }

  function snapshot() {
    const list = [...peers.values()]
      .map((peer) => ({
        id: peer.id,
        name: peer.name,
        address: peer.address,
        httpPort: peer.httpPort,
        version: peer.version,
        online: online(peer),
        lastSeen: new Date(peer.lastSeen).toISOString(),
        messageUrl: `http://${peer.address}:${peer.httpPort}/lan/message`,
      }))
      .sort((a, b) => Number(b.online) - Number(a.online) || a.name.localeCompare(b.name))
    return list
  }

  function savePeers() {
    writeJson(peersFile, { updatedAt: new Date().toISOString(), self: identity.id, peers: snapshot() })
  }

  function upsertPeer({ id, name: peerName, address, httpPort, version, lastSeen }) {
    if (!id || id === identity.id) return null
    const previous = peers.get(id)
    const usablePort = Number.isInteger(httpPort) && httpPort > 0
    const peer = {
      id,
      name: typeof peerName === 'string' && peerName ? peerName : address || id,
      address: address || previous?.address || '',
      // A message body may omit httpPort; never let that overwrite a known port
      // with 0, or later deliveries would target port 0.
      httpPort: usablePort ? httpPort : previous?.httpPort ?? settings.httpPort,
      version: typeof version === 'string' ? version : 'unknown',
      lastSeen: Number.isFinite(lastSeen) ? lastSeen : Date.now(),
    }
    peers.set(id, peer)
    if (!previous) {
      log(`discovered peer ${peer.name} at ${peer.address}:${peer.httpPort}`)
      savePeers()
    } else if (online(previous) === false) {
      log(`peer back online ${peer.name} at ${peer.address}:${peer.httpPort}`)
      savePeers()
    }
    return peer
  }

  function onPacket(buffer, rinfo) {
    let message
    try {
      message = JSON.parse(buffer.toString('utf8'))
    } catch {
      return
    }
    if (!message || message.v !== PROTOCOL || message.kind !== 'announce') return
    if (message.id === identity.id) return
    const fresh = !peers.has(message.id)
    upsertPeer({
      id: message.id,
      name: message.name,
      address: rinfo.address,
      httpPort: message.httpPort,
      version: message.version,
      lastSeen: Date.now(),
    })
    // Answer a first contact immediately so the other side learns about us fast.
    if (fresh) advertise()
  }

  function appendInbox(entry) {
    try {
      fs.appendFileSync(inboxFile, `${JSON.stringify(entry)}\n`, 'utf8')
    } catch (error) {
      log(`inbox write failed: ${error?.message ?? error}`)
    }
    const all = readInbox()
    if (all.length > settings.maxInbox) {
      const kept = all.slice(all.length - settings.maxInbox)
      try {
        fs.writeFileSync(inboxFile, kept.map((item) => JSON.stringify(item)).join('\n') + '\n', 'utf8')
      } catch {
        /* trimming is best effort */
      }
    }
  }

  function readInbox() {
    let raw = ''
    try {
      raw = fs.readFileSync(inboxFile, 'utf8')
    } catch {
      return []
    }
    const out = []
    for (const line of raw.split('\n')) {
      if (!line.trim()) continue
      try {
        out.push(JSON.parse(line))
      } catch {
        /* skip a torn line */
      }
    }
    return out
  }

  /** Mark messages read by rewriting the JSONL (small file, cheap). */
  function markRead(ids) {
    const all = readInbox()
    const wanted = new Set(ids)
    let changed = 0
    for (const entry of all) {
      if (wanted.has(entry.id) && !entry.read) {
        entry.read = true
        changed += 1
      }
    }
    if (changed > 0) {
      try {
        fs.writeFileSync(inboxFile, all.map((item) => JSON.stringify(item)).join('\n') + '\n', 'utf8')
      } catch {
        /* best effort */
      }
    }
    return changed
  }

  function jsonBody(req) {
    return new Promise((resolve) => {
      const chunks = []
      let size = 0
      req.on('data', (chunk) => {
        size += chunk.length
        if (size > 1_000_000) {
          resolve(null)
          req.destroy()
          return
        }
        chunks.push(chunk)
      })
      req.on('end', () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'))
        } catch {
          resolve(null)
        }
      })
      req.on('error', () => resolve(null))
    })
  }

  function reply(res, status, payload) {
    const body = Buffer.from(JSON.stringify(payload), 'utf8')
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': body.length,
      'Cache-Control': 'no-store',
    })
    res.end(body)
  }

  async function handleRequest(req, res) {
    const url = new URL(req.url || '/', 'http://localhost')
    const route = url.pathname.replace(/\/+$/u, '') || '/'

    if (req.method === 'GET' && route === '/lan/hello') {
      reply(res, 200, {
        ok: true,
        protocol: PROTOCOL,
        id: identity.id,
        name: displayName,
        address: primaryIPv4(),
        httpPort: settings.httpPort,
        tools: ['lan_peers', 'lan_send', 'lan_inbox', 'lan_ping'],
        peers: snapshot().filter((peer) => peer.online).length,
      })
      return
    }

    if (req.method === 'POST' && route === '/lan/message') {
      const body = await jsonBody(req)
      if (!body || typeof body.text !== 'string' || !body.text.trim()) {
        reply(res, 400, { ok: false, error: 'text is required' })
        return
      }
      const from = typeof body.from === 'string' ? body.from : 'unknown'
      const fromName = typeof body.fromName === 'string' ? body.fromName : from
      const entry = {
        id: crypto.randomUUID(),
        from,
        fromName,
        text: body.text.slice(0, settings.maxTextChars),
        receivedAt: new Date().toISOString(),
        read: false,
      }
      appendInbox(entry)
      if (from !== 'unknown') {
        upsertPeer({
          id: from,
          name: fromName,
          address: req.socket.remoteAddress?.replace(/^::ffff:/u, '') || '',
          httpPort: Number.isInteger(body.httpPort) ? body.httpPort : 0,
          version: typeof body.version === 'string' ? body.version : 'unknown',
          lastSeen: Date.now(),
        })
      }
      log(`message from ${fromName} (${from}): ${entry.text.slice(0, 120)}`)
      reply(res, 200, { ok: true, id: entry.id, queued: true, self: identity.id })
      return
    }

    if (req.method === 'GET' && route === '/lan/messages') {
      const limit = Math.min(Number(url.searchParams.get('limit')) || 50, 500)
      const messages = readInbox().slice(-limit)
      reply(res, 200, { ok: true, count: messages.length, messages })
      return
    }

    if (req.method === 'POST' && route === '/lan/ack') {
      const body = await jsonBody(req)
      const ids = Array.isArray(body?.ids) ? body.ids.filter((id) => typeof id === 'string') : []
      reply(res, 200, { ok: true, marked: markRead(ids) })
      return
    }

    reply(res, 404, { ok: false, error: 'not found' })
  }

  function startHttp() {
    server = http.createServer((req, res) => {
      handleRequest(req, res).catch((error) => {
        log(`http handler failed: ${error?.message ?? error}`)
        try {
          reply(res, 500, { ok: false, error: 'internal error' })
        } catch {
          /* response already sent */
        }
      })
    })
    server.on('error', (error) => log(`http listen failed on ${settings.httpPort}: ${error?.message ?? error}`))
    server.listen(settings.httpPort, '0.0.0.0')
  }

  function startUdp() {
    udp = dgram.createSocket({ type: 'udp4', reuseAddr: true })
    udp.on('error', (error) => log(`udp socket error: ${error?.message ?? error}`))
    udp.on('message', onPacket)
    udp.bind(settings.discoveryPort, () => {
      try {
        udp.setBroadcast(true)
      } catch (error) {
        log(`cannot enable broadcast: ${error?.message ?? error}`)
      }
      advertise()
    })
  }

  function tick() {
    advertise()
    const now = Date.now()
    let changed = false
    for (const peer of peers.values()) {
      const isOnline = now - peer.lastSeen <= settings.ttlMs
      if (!isOnline && peer.reportedOnline !== false) {
        peer.reportedOnline = false
        changed = true
        log(`peer offline ${peer.name} at ${peer.address}`)
      } else if (isOnline && peer.reportedOnline !== true) {
        peer.reportedOnline = true
        changed = true
      }
    }
    if (changed) savePeers()
    writeJson(statusFile, {
      updatedAt: new Date().toISOString(),
      self: identity,
      name: displayName,
      discoveryPort: settings.discoveryPort,
      httpPort: settings.httpPort,
      peers: snapshot(),
      tools: [...registered],
      toolsRegistered: registered.length > 0,
    })
  }

  function start() {
    startUdp()
    startHttp()
    timer = setInterval(tick, settings.intervalMs)
    timer.unref?.()
    tick()
    log(`started: announce every ${settings.intervalMs}ms on udp/${settings.discoveryPort}, mailbox http/0.0.0.0:${settings.httpPort}`)
  }

  function stop() {
    if (stopped) return
    stopped = true
    if (timer) clearInterval(timer)
    timer = null
    if (udp) {
      try {
        udp.close()
      } catch {
        /* already closed */
      }
      udp = null
    }
    if (server) {
      try {
        server.close()
      } catch {
        /* already closed */
      }
      server = null
    }
    log('stopped')
  }

  function resolvePeer(target) {
    if (!target) return null
    const wanted = String(target).trim().toLowerCase()
    const list = [...peers.values()]
    return (
      list.find((peer) => peer.id.toLowerCase() === wanted) ||
      list.find((peer) => peer.name.toLowerCase() === wanted) ||
      list.find((peer) => peer.address === wanted) ||
      list.find((peer) => (peer.name || '').toLowerCase().includes(wanted)) ||
      null
    )
  }

  async function deliver(peer, text) {
    const payload = JSON.stringify({
      from: identity.id,
      fromName: displayName,
      version: '0.1.0',
      httpPort: settings.httpPort,
      text,
    })
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 10000)
    try {
      const response = await fetch(`http://${peer.address}:${peer.httpPort}/lan/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload,
        signal: controller.signal,
      })
      const data = await response.json().catch(() => ({}))
      return { ok: response.ok && data?.ok !== false, status: response.status, data }
    } catch (error) {
      return { ok: false, status: 0, error: error?.name === 'AbortError' ? 'timeout after 10s' : String(error?.message ?? error) }
    } finally {
      clearTimeout(timeout)
    }
  }

  function registerTools(toolCtx) {
    // cordis 4.0.5 throws when reading an un-injected service property; probe inside try/catch.
    let tools
    try {
      tools = toolCtx?.tools
    } catch {
      return
    }
    if (!tools || typeof tools.register !== 'function') return
    const add = (def) => {
      if (registered.includes(def.name)) return
      try {
        tools.register(def)
        registered.push(def.name)
      } catch (error) {
        log(`tool registration failed for ${def.name}: ${error?.message ?? error}`)
      }
    }

    add({
      name: 'lan_peers',
      description:
        'List other DeepSeek Harness nodes discovered on the local network (auto-discovery over UDP broadcast), ' +
        'including online state, LAN address and mailbox URL. Use this before lan_send.',
      parameters: {},
      output: { schema: VALUE_SCHEMA, render: renderToolValue },
      isConcurrencySafe: () => true,
      async execute() {
        const onlinePeers = snapshot()
        return {
          ok: true,
          self: { id: identity.id, name: displayName, httpPort: settings.httpPort },
          discoveryPort: settings.discoveryPort,
          peers: onlinePeers,
          online: onlinePeers.filter((peer) => peer.online).length,
          message: onlinePeers.length
            ? onlinePeers.map((peer) => `${peer.name} ${peer.address}:${peer.httpPort} ${peer.online ? 'online' : 'offline'}`).join('\n')
            : 'no peers discovered yet (peers must run dsh-lan-peers on the same LAN)',
        }
      },
    })

    add({
      name: 'lan_send',
      description:
        'Send a text message to another DeepSeek Harness node on the LAN discovered by dsh-lan-peers. ' +
        'The peer is resolved by name, node id or IP, so no manual peer configuration is needed. ' +
        'The message is queued into the peer agent\'s mailbox (read there via lan_inbox).',
      parameters: {
        peer: { type: 'string', description: 'Peer name, node id or LAN IP as shown by lan_peers.' },
        text: { type: 'string', description: 'Message body to deliver.' },
      },
      output: { schema: VALUE_SCHEMA, render: renderToolValue },
      isConcurrencySafe: () => false,
      async execute(args) {
        const text = typeof args?.text === 'string' ? args.text.trim() : ''
        if (!text) throw new Error('lan_send: text is required')
        if (text.length > settings.maxTextChars) throw new Error(`lan_send: text exceeds ${settings.maxTextChars} chars`)
        const peer = resolvePeer(args?.peer)
        if (!peer) throw new Error(`lan_send: unknown peer "${args?.peer ?? ''}" 闁?call lan_peers first`)
        const result = await deliver(peer, text)
        if (result.ok) {
          peer.lastSeen = Date.now()
          savePeers()
          return {
            ok: true,
            peer: peer.name,
            address: peer.address,
            httpPort: peer.httpPort,
            messageId: result.data?.id ?? null,
            status: result.status,
            message: `delivered to ${peer.name} (${peer.address}:${peer.httpPort}) id=${result.data?.id ?? 'n/a'}`,
          }
        }
        peer.reportedOnline = false
        log(`delivery to ${peer.name} failed: ${result.error ?? result.status}`)
        return {
          ok: false,
          peer: peer.name,
          address: peer.address,
          httpPort: peer.httpPort,
          error: result.error ?? `peer answered ${result.status}`,
          message: `failed to deliver to ${peer.name} (${peer.address}:${peer.httpPort}): ${result.error ?? `status ${result.status}`}`,
        }
      },
    })

    add({
      name: 'lan_inbox',
      description:
        'Read messages that other LAN peers sent to this DeepSeek Harness node. ' +
        'Unread messages come first; pass mark_read=true to consume them.',
      parameters: {
        limit: { type: 'number', description: 'How many of the newest messages to return (default 20).' },
        mark_read: { type: 'boolean', description: 'Mark the returned messages as read (default false).' },
      },
      output: { schema: VALUE_SCHEMA, render: renderToolValue },
      isConcurrencySafe: () => true,
      async execute(args) {
        const limit = Math.min(Math.max(Number(args?.limit) || 20, 1), 200)
        const all = readInbox()
        const messages = all.slice(-limit)
        if (args?.mark_read === true) markRead(messages.map((entry) => entry.id))
        const unread = readInbox().filter((entry) => !entry.read).length
        return {
          ok: true,
          unread,
          total: all.length,
          count: messages.length,
          messages: messages.map((entry) => ({
            id: entry.id,
            from: entry.fromName || entry.from,
            fromId: entry.from,
            text: entry.text,
            receivedAt: entry.receivedAt,
            read: entry.read === true,
          })),
          message: messages.length
            ? messages.map((entry) => `[${entry.read ? 'read' : 'unread'}] ${entry.fromName || entry.from}: ${entry.text}`).join('\n')
            : 'inbox is empty',
        }
      },
    })

    add({
      name: 'lan_ping',
      description:
        'Re-announce this node on the LAN and probe every known peer mailbox right now. ' +
        'Useful right after startup when discovery has not settled yet.',
      parameters: {},
      output: { schema: VALUE_SCHEMA, render: renderToolValue },
      isConcurrencySafe: () => true,
      async execute() {
        advertise()
        const probes = await Promise.all(
          [...peers.values()].map(async (peer) => {
            const result = await deliver(peer, `[lan-ping from ${displayName}] hello`)
            return { peer: peer.name, address: peer.address, reachable: result.ok, detail: result.ok ? 'ok' : result.error ?? result.status }
          }),
        )
        return {
          ok: true,
          self: { id: identity.id, name: displayName },
          probed: probes.length,
          reachable: probes.filter((item) => item.reachable).length,
          peers: probes,
          message: probes.length ? probes.map((item) => `${item.peer}: ${item.reachable ? 'reachable' : item.detail}`).join('\n') : 'no peers to probe',
        }
      },
    })
  }

  return {
    start() {
      // Register first so the very first status snapshot already lists the tools.
      registerTools(ctx)
      start()
    },
    stop() {
      stop()
    },
    /** 供晚到的 tools 服务补注册 */
    registerToolset(toolCtx) {
      registerTools(toolCtx)
    },
    /** 已注册的工具名，用于判断工具层是否真的可用 */
    toolNames() {
      return [...registered]
    },
    /** exposed for hot-reload tests */
    peers: () => snapshot(),
  }
}

// 与 dsh-wan-peers 保持一致的导出形状：旧版宿主（cordis 4.0.x）只认 default。
export default { name, apply }
