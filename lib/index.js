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

import {
  deriveShared,
  generateKeyPair,
  hmacBase64,
  open as openBox,
  peerKeys,
  randomToken,
  safeEqual,
  seal,
  signingString,
} from './crypto.js'
import { createKeyStore, createPairingStore } from './pairing.js'

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

/** Wire format version for announce packets and the legacy HTTP mailbox. */
const PROTOCOL = 1

/** Secure channel version: X25519 + HMAC-SHA256 signatures + AES-256-GCM payloads. */
const SECURE_PROTOCOL = 2

/** Tool names, shared by the announce packet, /lan/v2/hello and status.json. */
const TOOL_NAMES = ['lan_peers', 'lan_pair', 'lan_send', 'lan_inbox', 'lan_ping']

const DEFAULTS = {
  discoveryPort: 48901,
  httpPort: 48902,
  intervalMs: 7000,
  ttlMs: 30000,
  name: '',
  maxTextChars: 8000,
  maxInbox: 500,
  // Secure channel is the default: peers must pair before they can talk.
  secure: true,
  pairingCodeLength: 6,
  pairingCodeTtlMs: 600000,
  maxPairAttemptsPerMinute: 5,
  clockSkewMs: 60000,
  nonceTtlMs: 300000,
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
  for (const key of [
    'discoveryPort',
    'httpPort',
    'intervalMs',
    'ttlMs',
    'maxTextChars',
    'maxInbox',
    'pairingCodeLength',
    'pairingCodeTtlMs',
    'maxPairAttemptsPerMinute',
    'clockSkewMs',
    'nonceTtlMs',
  ]) {
    const value = config?.[key]
    if (value === undefined) continue
    if (!Number.isInteger(value) || value < 1) throw new Error(`dsh-lan-peers: ${key} must be a positive integer`)
    settings[key] = value
  }
  if (settings.pairingCodeLength < 4 || settings.pairingCodeLength > 12) {
    throw new Error('dsh-lan-peers: pairingCodeLength must be between 4 and 12')
  }
  if (config?.secure !== undefined) {
    if (typeof config.secure !== 'boolean') throw new Error('dsh-lan-peers: secure must be a boolean')
    settings.secure = config.secure
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

/** Numeric compare of dotted versions; non-numeric parts sort as 0. */
function compareVersion(left, right) {
  const a = String(left).split('.').map((part) => Number.parseInt(part, 10) || 0)
  const b = String(right).split('.').map((part) => Number.parseInt(part, 10) || 0)
  for (let i = 0; i < Math.max(a.length, b.length); i += 1) {
    const diff = (a[i] || 0) - (b[i] || 0)
    if (diff !== 0) return diff > 0 ? 1 : -1
  }
  return 0
}

/** True for 127.0.0.0/8, ::1 and the IPv4-mapped forms Node reports. */
function isLoopback(address) {
  if (!address) return false
  const value = String(address).replace(/^::ffff:/u, '').trim()
  return value === '::1' || value === '::' || value === 'localhost' || value.startsWith('127.')
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
  /** Short-lived pairing codes (stored hashed) and the paired-peer key rings. */
  const pairing = createPairingStore({
    codeTtlMs: settings.pairingCodeTtlMs,
    codeLength: settings.pairingCodeLength,
    maxAttemptsPerMinute: settings.maxPairAttemptsPerMinute,
  })
  const keyStore = createKeyStore(dir)
  /** peerId -> Map(nonce -> seenAt), for replay rejection. */
  const nonces = new Map()
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
    const pairingStatus = pairing.status()
    const packet = Buffer.from(
      JSON.stringify({
        v: PROTOCOL,
        kind: 'announce',
        id: identity.id,
        name: displayName,
        version: '0.3.0',
        httpPort: settings.httpPort,
        address: primaryIPv4(),
        tools: TOOL_NAMES,
        secure: settings.secure,
        securePort: settings.httpPort,
        pairing: pairingStatus.active,
        pairingExpiresAt: pairingStatus.expiresAt,
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
      .map((peer) => {
        const key = keyStore.get(peer.id)
        return {
          id: peer.id,
          name: peer.name,
          address: peer.address,
          httpPort: peer.httpPort,
          version: peer.version,
          online: online(peer),
          lastSeen: new Date(peer.lastSeen).toISOString(),
          secure: peer.secure !== false,
          pairing: peer.pairing === true,
          paired: Boolean(key),
          pairedAt: key?.pairedAt ?? null,
          messageUrl: `http://${peer.address}:${peer.httpPort}/lan/message`,
        }
      })
      .sort((a, b) => Number(b.online) - Number(a.online) || a.name.localeCompare(b.name))
    return list
  }

  function savePeers() {
    writeJson(peersFile, { updatedAt: new Date().toISOString(), self: identity.id, peers: snapshot() })
  }

  function upsertPeer({ id, name: peerName, address, httpPort, version, lastSeen, secure, pairing: pairFlag }) {
    if (!id || id === identity.id) return null
    const previous = peers.get(id)
    // Two runtimes of different versions can share one identity.json (e.g. a
    // stale process that never exited). A weak/old announce must not downgrade
    // what we already know about that node, or deliveries start flapping
    // between ports.
    const downgrade =
      previous &&
      ((previous.secure === true && secure !== true) ||
        (typeof previous.version === 'string' &&
          typeof version === 'string' &&
          previous.version !== 'unknown' &&
          version !== 'unknown' &&
          compareVersion(version, previous.version) < 0))
    const usablePort = !downgrade && Number.isInteger(httpPort) && httpPort > 0
    const peer = {
      id,
      name: typeof peerName === 'string' && peerName ? peerName : address || id,
      address: address || previous?.address || '',
      // A message body may omit httpPort; never let that overwrite a known port
      // with 0, or later deliveries would target port 0.
      httpPort: usablePort ? httpPort : previous?.httpPort ?? settings.httpPort,
      version: downgrade ? previous.version : typeof version === 'string' ? version : 'unknown',
      lastSeen: Number.isFinite(lastSeen) ? lastSeen : Date.now(),
      secure: downgrade ? previous.secure : typeof secure === 'boolean' ? secure : previous?.secure,
      pairing: typeof pairFlag === 'boolean' ? pairFlag : previous?.pairing === true,
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
      secure: typeof message.secure === 'boolean' ? message.secure : undefined,
      pairing: typeof message.pairing === 'boolean' ? message.pairing : undefined,
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

  function rawBody(req) {
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
      req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
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

  /** Drop nonces older than the replay window, then remember this one. */
  function rememberNonce(peerId, nonce) {
    const now = Date.now()
    let map = nonces.get(peerId)
    if (!map) {
      map = new Map()
      nonces.set(peerId, map)
    }
    for (const [value, seenAt] of map) {
      if (now - seenAt > settings.nonceTtlMs) map.delete(value)
    }
    if (map.has(nonce)) return false
    map.set(nonce, now)
    return true
  }

  /**
   * Verify the signature headers of a v2 request against the key of its sender.
   * `path` must be the exact pathname both sides sign.
   */
  function verifySigned(req, raw, path_) {
    const fromId = String(req.headers['x-lan-from'] || '').trim()
    if (!fromId) return { ok: false, status: 401, error: 'missing X-Lan-From' }
    const key = keyStore.get(fromId)
    if (!key) return { ok: false, status: 401, error: 'peer is not paired with this node' }
    const ts = Number(req.headers['x-lan-ts'])
    const nonce = String(req.headers['x-lan-nonce'] || '').trim()
    const sig = String(req.headers['x-lan-sig'] || '').trim()
    if (!Number.isFinite(ts) || !nonce || !sig) return { ok: false, status: 401, error: 'missing signature headers' }
    if (Math.abs(Date.now() - ts) > settings.clockSkewMs) {
      return { ok: false, status: 401, error: 'clock skew too large (check both clocks)' }
    }
    const shared = Buffer.from(key.shared, 'base64')
    const keys = peerKeys(shared, identity.id, fromId)
    const expected = hmacBase64(keys.sigKey, signingString({ method: req.method, path: path_, ts, nonce, body: raw }))
    if (!safeEqual(expected, sig)) return { ok: false, status: 401, error: 'bad signature' }
    if (!rememberNonce(fromId, nonce)) return { ok: false, status: 401, error: 'replayed request' }
    return { ok: true, fromId, key, keys }
  }

  /** POST /lan/v2/pair/start — the only unauthenticated write endpoint. */
  async function handlePairStart(req, res) {
    const raw = await rawBody(req)
    let body = null
    try {
      body = JSON.parse(raw || '{}')
    } catch {
      body = null
    }
    if (!body || body.v !== SECURE_PROTOCOL) {
      reply(res, 400, { ok: false, error: `this node speaks secure protocol v${SECURE_PROTOCOL}` })
      return
    }
    const fromId = String(body.from || '').trim()
    const peerPublicX = String(body.pk || '').trim()
    if (!fromId || !peerPublicX) {
      reply(res, 400, { ok: false, error: 'from and pk are required' })
      return
    }
    const ip = req.socket.remoteAddress?.replace(/^::ffff:/u, '') || 'unknown'
    const consumed = pairing.consume(body.code, ip)
    if (!consumed.ok) {
      log(`pairing rejected from ${fromId} (${ip}): ${consumed.reason}`)
      reply(res, 403, { ok: false, error: consumed.reason })
      return
    }
    const ephemeral = generateKeyPair()
    const shared = deriveShared(ephemeral.privateKey, peerPublicX)
    const keys = peerKeys(shared, identity.id, fromId)
    const proof = hmacBase64(keys.proofKey, `pair|${identity.id}|${fromId}|${ephemeral.publicX}|${peerPublicX}`)
    keyStore.save({
      id: fromId,
      name: typeof body.fromName === 'string' && body.fromName ? body.fromName : fromId,
      address: ip,
      httpPort: Number.isInteger(body.httpPort) ? body.httpPort : 0,
      peerPublicX,
      shared,
    })
    upsertPeer({
      id: fromId,
      name: body.fromName,
      address: ip,
      httpPort: Number.isInteger(body.httpPort) ? body.httpPort : 0,
      lastSeen: Date.now(),
      secure: true,
      pairing: false,
    })
    advertise()
    log(`paired with ${body.fromName || fromId} (${ip})`)
    reply(res, 200, {
      ok: true,
      v: SECURE_PROTOCOL,
      from: identity.id,
      name: displayName,
      httpPort: settings.httpPort,
      pk: ephemeral.publicX,
      proof,
    })
  }

  /** POST /lan/v2/message — signed request, encrypted payload. */
  async function handleSecureMessage(req, res) {
    const path_ = '/lan/v2/message'
    const raw = await rawBody(req)
    const verified = verifySigned(req, raw, path_)
    if (!verified.ok) {
      log(`secure message rejected from ${String(req.headers['x-lan-from'] || '?')}: ${verified.error}`)
      reply(res, verified.status, { ok: false, error: verified.error })
      return
    }
    let payload
    try {
      const box = JSON.parse(raw)
      const aad = `${verified.fromId}|${identity.id}|${path_}`
      payload = JSON.parse(openBox(verified.keys.msgKey, box, aad))
    } catch {
      reply(res, 400, { ok: false, error: 'cannot decrypt payload' })
      return
    }
    const text = typeof payload?.text === 'string' ? payload.text.trim() : ''
    if (!text) {
      reply(res, 400, { ok: false, error: 'text is required' })
      return
    }
    const fromName = verified.key.name || verified.fromId
    const entry = {
      id: crypto.randomUUID(),
      from: verified.fromId,
      fromName,
      text: text.slice(0, settings.maxTextChars),
      receivedAt: new Date().toISOString(),
      read: false,
      secure: true,
    }
    appendInbox(entry)
    upsertPeer({
      id: verified.fromId,
      name: fromName,
      address: req.socket.remoteAddress?.replace(/^::ffff:/u, '') || '',
      httpPort: Number.isInteger(payload.httpPort) ? payload.httpPort : 0,
      lastSeen: Date.now(),
      secure: true,
      pairing: false,
    })
    log(`secure message from ${fromName} (${verified.fromId}): ${entry.text.slice(0, 120)}`)
    reply(res, 200, { ok: true, id: entry.id, queued: true, secure: true, self: identity.id })
  }

  async function handleRequest(req, res) {
    const url = new URL(req.url || '/', 'http://localhost')
    const route = url.pathname.replace(/\/+$/u, '') || '/'

    if (req.method === 'GET' && route === '/lan/v2/hello') {
      reply(res, 200, {
        ok: true,
        secure: true,
        protocol: SECURE_PROTOCOL,
        id: identity.id,
        name: displayName,
        address: primaryIPv4(),
        httpPort: settings.httpPort,
        tools: TOOL_NAMES,
        pairing: pairing.status(),
        peers: snapshot().filter((peer) => peer.online).length,
      })
      return
    }

    // Loopback-only convenience so a human or script on this machine can show a
    // pairing code without going through an agent turn. Remote callers are refused.
    if (req.method === 'POST' && route === '/lan/v2/pair/code') {
      const remote = req.socket.remoteAddress?.replace(/^::ffff:/u, '') || ''
      if (!isLoopback(remote)) {
        reply(res, 403, { ok: false, error: 'pairing codes can only be created from localhost' })
        return
      }
      const created = pairing.createCode()
      advertise()
      log(`pairing code issued locally, valid until ${created.expiresAt}`)
      reply(res, 200, {
        ok: true,
        name: displayName,
        id: identity.id,
        httpPort: settings.httpPort,
        code: created.code,
        expiresAt: created.expiresAt,
      })
      return
    }

    if (req.method === 'POST' && route === '/lan/v2/pair/start') {
      await handlePairStart(req, res)
      return
    }

    if (req.method === 'POST' && route === '/lan/v2/message') {
      await handleSecureMessage(req, res)
      return
    }

    // Plaintext surface stays available only when secure mode is turned off.
    if (settings.secure) {
      reply(res, 426, { ok: false, error: 'this node requires the secure channel (lan/v2); pair first with lan_pair' })
      return
    }

    if (req.method === 'GET' && route === '/lan/hello') {
      reply(res, 200, {
        ok: true,
        protocol: PROTOCOL,
        id: identity.id,
        name: displayName,
        address: primaryIPv4(),
        httpPort: settings.httpPort,
        tools: TOOL_NAMES,
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

  function startHttp(attempt = 0) {
    // A hot reload disposes the old runtime and immediately creates a new one,
    // so the previous listener may still be releasing the port. Retry instead of
    // giving up on the first EADDRINUSE.
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
    server.keepAliveTimeout = 5000
    server.on('error', (error) => {
      const busy = error?.code === 'EADDRINUSE'
      if (busy && attempt < 20) {
        try {
          server.close()
        } catch {
          /* already closed */
        }
        server = null
        setTimeout(() => {
          if (!stopped) startHttp(attempt + 1)
        }, 500).unref?.()
        return
      }
      log(`http listen failed on ${settings.httpPort}: ${error?.message ?? error}`)
    })
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
      secure: settings.secure,
      protocol: settings.secure ? SECURE_PROTOCOL : PROTOCOL,
      pairing: pairing.status(),
      paired: keyStore.list().map((entry) => ({ id: entry.id, name: entry.name, pairedAt: entry.pairedAt })),
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
    log(
      `started: announce every ${settings.intervalMs}ms on udp/${settings.discoveryPort}, mailbox http/0.0.0.0:${settings.httpPort}, ` +
        (settings.secure ? `secure v${SECURE_PROTOCOL} (${keyStore.list().length} paired peer(s))` : 'plaintext v1 (secure=false)'),
    )
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
        // keep-alive sockets would otherwise pin the port through the reload
        server.closeAllConnections?.()
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

  async function deliverLegacy(peer, text) {
    const payload = JSON.stringify({
      from: identity.id,
      fromName: displayName,
      version: '0.3.0',
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

  /** Signed + encrypted delivery over /lan/v2/message. */
  async function deliverSecure(peer, text) {
    const key = keyStore.get(peer.id)
    if (!key) {
      return { ok: false, status: 0, error: `not paired with ${peer.name}; run lan_pair (show on that node, import here)` }
    }
    const path_ = '/lan/v2/message'
    const shared = Buffer.from(key.shared, 'base64')
    const keys = peerKeys(shared, identity.id, peer.id)
    const payload = JSON.stringify({
      text,
      fromName: displayName,
      version: '0.3.0',
      httpPort: settings.httpPort,
    })
    const box = seal(keys.msgKey, payload, `${identity.id}|${peer.id}|${path_}`)
    const body = JSON.stringify({ v: SECURE_PROTOCOL, iv: box.iv, ct: box.ct, tag: box.tag })
    const ts = Date.now()
    const nonce = randomToken(12)
    const sig = hmacBase64(keys.sigKey, signingString({ method: 'POST', path: path_, ts, nonce, body }))
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 10000)
    try {
      const response = await fetch(`http://${peer.address}:${peer.httpPort}${path_}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Lan-From': identity.id,
          'X-Lan-Ts': String(ts),
          'X-Lan-Nonce': nonce,
          'X-Lan-Sig': sig,
        },
        body,
        signal: controller.signal,
      })
      const data = await response.json().catch(() => ({}))
      return { ok: response.ok && data?.ok !== false, status: response.status, data, secure: true }
    } catch (error) {
      return { ok: false, status: 0, error: error?.name === 'AbortError' ? 'timeout after 10s' : String(error?.message ?? error) }
    } finally {
      clearTimeout(timeout)
    }
  }

  /** Delivery entry point: secure channel by default, plaintext only when configured. */
  async function deliver(peer, text) {
    if (settings.secure) return deliverSecure(peer, text)
    return deliverLegacy(peer, text)
  }

  /**
   * Complete a pairing handshake against a discovered peer.
   * The code travels in the request body (LAN-local, single use, short TTL);
   * the resulting key never travels at all — both sides derive it from ECDH.
   */
  async function pairWith(target, code) {
    const peer = resolvePeer(target)
    if (!peer) return { ok: false, error: `unknown peer "${target}"; run lan_peers first` }
    if (!peer.address) return { ok: false, error: `${peer.name} has no known address yet` }
    const keyPair = generateKeyPair()
    const path_ = '/lan/v2/pair/start'
    const body = JSON.stringify({
      v: SECURE_PROTOCOL,
      from: identity.id,
      fromName: displayName,
      httpPort: settings.httpPort,
      code: String(code || '').trim(),
      pk: keyPair.publicX,
    })
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 10000)
    let data
    try {
      const response = await fetch(`http://${peer.address}:${peer.httpPort}${path_}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
        signal: controller.signal,
      })
      data = await response.json().catch(() => ({}))
      if (!response.ok || data?.ok !== true) {
        return { ok: false, error: data?.error || `peer answered ${response.status}` }
      }
    } catch (error) {
      return { ok: false, error: error?.name === 'AbortError' ? 'timeout after 10s' : String(error?.message ?? error) }
    } finally {
      clearTimeout(timeout)
    }
    const peerId = String(data.from || '')
    const peerPublicX = String(data.pk || '')
    if (!peerId || !peerPublicX) return { ok: false, error: 'peer reply is missing its identity or public key' }
    const shared = deriveShared(keyPair.privateKey, peerPublicX)
    const keys = peerKeys(shared, identity.id, peerId)
    const expected = hmacBase64(keys.proofKey, `pair|${peerId}|${identity.id}|${peerPublicX}|${keyPair.publicX}`)
    if (!safeEqual(expected, String(data.proof || ''))) {
      return { ok: false, error: 'peer proof mismatch — refusing to trust this exchange' }
    }
    const record = keyStore.save({
      id: peerId,
      name: typeof data.name === 'string' && data.name ? data.name : peer.name,
      address: peer.address,
      httpPort: Number.isInteger(data.httpPort) ? data.httpPort : peer.httpPort,
      peerPublicX,
      shared,
    })
    upsertPeer({
      id: peerId,
      name: record.name,
      address: peer.address,
      httpPort: record.httpPort || peer.httpPort,
      lastSeen: Date.now(),
      secure: true,
      pairing: false,
    })
    log(`paired with ${record.name} (${peer.address})`)
    return { ok: true, peer: record.name, peerId, pairedAt: record.pairedAt }
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
        const paired = onlinePeers.filter((peer) => peer.paired).length
        const waiting = onlinePeers.filter((peer) => peer.pairing).map((peer) => peer.name)
        return {
          ok: true,
          self: { id: identity.id, name: displayName, httpPort: settings.httpPort },
          secure: settings.secure,
          pairing: pairing.status(),
          discoveryPort: settings.discoveryPort,
          peers: onlinePeers,
          online: onlinePeers.filter((peer) => peer.online).length,
          paired,
          message: [
            onlinePeers.length
              ? onlinePeers
                  .map(
                    (peer) =>
                      `${peer.name} ${peer.address}:${peer.httpPort} ${peer.online ? 'online' : 'offline'}` +
                      `${peer.paired ? ' paired' : ' NOT paired'}${peer.pairing ? ' (showing a pairing code)' : ''}`,
                  )
                  .join('\n')
              : 'no peers discovered yet (peers must run dsh-lan-peers on the same LAN)',
            waiting.length ? `waiting for a pairing code: ${waiting.join(', ')} — run lan_pair action=import` : '',
            settings.secure && !paired ? 'secure mode: pair before lan_send works' : '',
          ]
            .filter(Boolean)
            .join('\n'),
        }
      },
    })

    add({
      name: 'lan_pair',
      description:
        'Pair this node with another LAN node so the secure channel can carry messages. ' +
        'action=show prints a one-time code (10 minutes, single use) that the other machine imports; ' +
        'action=import takes that code plus the peer name/IP; action=list shows paired peers; ' +
        'action=forget removes one peer key; action=reset drops every peer key.',
      parameters: {
        action: { type: 'string', description: 'show | import | list | forget | reset', enum: ['show', 'import', 'list', 'forget', 'reset'] },
        peer: { type: 'string', description: 'For action=import/forget: peer name, node id or LAN IP.' },
        code: { type: 'string', description: 'For action=import: the code the other node printed with action=show.' },
      },
      output: { schema: VALUE_SCHEMA, render: renderToolValue },
      isConcurrencySafe: () => false,
      async execute(args) {
        const action = String(args?.action || 'show').toLowerCase()
        if (action === 'show') {
          const created = pairing.createCode()
          advertise()
          return {
            ok: true,
            action: 'show',
            code: created.code,
            expiresAt: created.expiresAt,
            self: { id: identity.id, name: displayName, address: primaryIPv4(), httpPort: settings.httpPort },
            message:
              `pairing code ${created.code} (valid until ${created.expiresAt}).\n` +
              `On the other node run: lan_pair action=import peer=${displayName} code=${created.code}`,
          }
        }
        if (action === 'import') {
          const code = typeof args?.code === 'string' ? args.code.trim() : ''
          if (!code) throw new Error('lan_pair: code is required for action=import')
          const result = await pairWith(args?.peer, code)
          if (!result.ok) {
            return { ok: false, action: 'import', peer: args?.peer ?? null, error: result.error, message: `pairing failed: ${result.error}` }
          }
          return {
            ok: true,
            action: 'import',
            peer: result.peer,
            peerId: result.peerId,
            pairedAt: result.pairedAt,
            message: `paired with ${result.peer}; lan_send now works over the encrypted channel`,
          }
        }
        if (action === 'list') {
          const keys = keyStore.list()
          return {
            ok: true,
            action: 'list',
            count: keys.length,
            peers: keys.map((entry) => ({
              id: entry.id,
              name: entry.name,
              address: entry.address,
              httpPort: entry.httpPort,
              pairedAt: entry.pairedAt,
            })),
            message: keys.length
              ? keys.map((entry) => `${entry.name} ${entry.address}:${entry.httpPort} paired ${entry.pairedAt}`).join('\n')
              : 'no paired peers yet (lan_pair action=show on the other node, then action=import here)',
          }
        }
        if (action === 'forget') {
          const peer = resolvePeer(args?.peer)
          const id = peer?.id || String(args?.peer || '')
          if (!id) throw new Error('lan_pair: peer is required for action=forget')
          const removed = keyStore.remove(id)
          return {
            ok: removed,
            action: 'forget',
            peer: id,
            message: removed ? `removed the key for ${peer?.name || id}` : `no key stored for ${peer?.name || id}`,
          }
        }
        if (action === 'reset') {
          pairing.clear()
          const removed = keyStore.clear()
          return { ok: true, action: 'reset', removed, message: `cleared ${removed} peer key(s); every peer must pair again` }
        }
        throw new Error(`lan_pair: unknown action "${action}"`)
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
            const target = settings.secure ? '/lan/v2/hello' : '/lan/hello'
            const controller = new AbortController()
            const timeout = setTimeout(() => controller.abort(), 5000)
            try {
              const response = await fetch(`http://${peer.address}:${peer.httpPort}${target}`, { signal: controller.signal })
              const data = await response.json().catch(() => ({}))
              const key = keyStore.get(peer.id)
              const detail = response.ok
                ? [data.secure ? 'secure' : 'plaintext', key ? 'paired' : 'not paired'].join(', ')
                : `HTTP ${response.status}`
              return {
                peer: peer.name,
                address: peer.address,
                reachable: response.ok,
                secure: Boolean(data.secure),
                paired: Boolean(key),
                detail,
              }
            } catch (error) {
              return {
                peer: peer.name,
                address: peer.address,
                reachable: false,
                detail: error?.name === 'AbortError' ? 'timeout after 5s' : String(error?.message ?? error),
              }
            } finally {
              clearTimeout(timeout)
            }
          }),
        )
        return {
          ok: true,
          self: { id: identity.id, name: displayName },
          secure: settings.secure,
          probed: probes.length,
          reachable: probes.filter((item) => item.reachable).length,
          paired: probes.filter((item) => item.paired).length,
          peers: probes,
          message: probes.length
            ? probes.map((item) => `${item.peer}: ${item.reachable ? 'reachable' : item.detail}${item.reachable ? ` (${item.detail})` : ''}`).join('\n')
            : 'no peers to probe',
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
