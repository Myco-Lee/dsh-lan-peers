// A second dsh-lan-peers node implemented directly on the wire protocol (v2).
// Used by smoke.mjs to exercise discovery + pairing + the encrypted channel
// without booting a second DSH host.
import dgram from 'node:dgram'
import http from 'node:http'
import crypto from 'node:crypto'
import {
  generateKeyPair,
  deriveShared,
  peerKeys,
  hmacBase64,
  signingString,
  seal,
  open,
  randomToken,
  safeEqual,
} from '../lib/crypto.js'

const readBody = (req) =>
  new Promise((resolve, reject) => {
    let body = ''
    req.on('data', (chunk) => {
      body += chunk
      if (body.length > 1_000_000) reject(new Error('body too large'))
    })
    req.on('end', () => resolve(body))
    req.on('error', reject)
  })

export async function startMockPeer({ port, discoveryPort, name = 'mock-peer-b', log = () => {} }) {
  const identity = { id: crypto.randomUUID(), name }
  const keys = new Map() // peerId -> { shared, name }
  let paired = null
  const inbox = []
  const seen = new Map()

  const rememberNonce = (peerId, nonce) => {
    const map = seen.get(peerId) ?? new Map()
    seen.set(peerId, map)
    if (map.has(nonce)) return false
    map.set(nonce, Date.now())
    return true
  }

  const server = http.createServer(async (req, res) => {
    const send = (status, payload) => {
      res.writeHead(status, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(payload))
    }
    const route = (req.url || '/').split('?')[0].replace(/\/+$/u, '') || '/'
    try {
      if (req.method === 'POST' && route === '/lan/v2/pair/start') {
        const body = JSON.parse((await readBody(req)) || '{}')
        const ephemeral = generateKeyPair()
        const shared = deriveShared(ephemeral.privateKey, String(body.pk || ''))
        const derived = peerKeys(shared, identity.id, String(body.from || ''))
        const proof = hmacBase64(
          derived.proofKey,
          `pair|${identity.id}|${body.from}|${ephemeral.publicX}|${body.pk}`,
        )
        keys.set(String(body.from), { shared, name: body.fromName || body.from })
        paired = String(body.from)
        log(`mock paired with ${body.fromName || body.from}`)
        send(200, {
          ok: true,
          v: 2,
          from: identity.id,
          name: identity.name,
          httpPort: port,
          pk: ephemeral.publicX,
          proof,
        })
        return
      }

      if (req.method === 'POST' && route === '/lan/v2/message') {
        const raw = await readBody(req)
        const fromId = String(req.headers['x-lan-from'] || '')
        const entry = keys.get(fromId)
        if (!entry) return send(401, { ok: false, error: 'not paired' })
        const path_ = '/lan/v2/message'
        const derived = peerKeys(entry.shared, identity.id, fromId)
        const ts = Number(req.headers['x-lan-ts'])
        const nonce = String(req.headers['x-lan-nonce'] || '')
        const sig = String(req.headers['x-lan-sig'] || '')
        const expected = hmacBase64(derived.sigKey, signingString({ method: 'POST', path: path_, ts, nonce, body: raw }))
        if (!safeEqual(expected, sig)) return send(401, { ok: false, error: 'bad signature' })
        if (!rememberNonce(fromId, nonce)) return send(401, { ok: false, error: 'replayed' })
        const box = JSON.parse(raw)
        const payload = JSON.parse(open(derived.msgKey, box, `${fromId}|${identity.id}|${path_}`))
        inbox.push({ from: fromId, text: payload.text, secure: true })
        log(`mock received secure message: ${payload.text}`)
        return send(200, { ok: true, id: crypto.randomUUID(), queued: true, secure: true, self: identity.id })
      }

      send(404, { ok: false, error: 'not found' })
    } catch (error) {
      send(500, { ok: false, error: String(error?.message ?? error) })
    }
  })

  await new Promise((resolve) => server.listen(port, '0.0.0.0', resolve))

  const udp = dgram.createSocket({ type: 'udp4', reuseAddr: true })
  await new Promise((resolve) => udp.bind(discoveryPort, resolve))
  udp.setBroadcast(true)
  const announce = (pairing = '') =>
    udp.send(
      Buffer.from(
        JSON.stringify({
          v: 1,
          kind: 'announce',
          id: identity.id,
          name: identity.name,
          version: '0.3.0',
          httpPort: port,
          secure: true,
          pairing,
          ts: Date.now(),
        }),
      ),
      discoveryPort,
      '255.255.255.255',
    )
  announce()
  const timer = setInterval(() => announce(), 1000)
  timer.unref?.()

  return {
    id: identity.id,
    name: identity.name,
    port,
    inbox,
    get paired() {
      return paired
    },
    announce,
    /** Mock acts as the node that imports a code shown on the other side. */
    async pairWith(targetAddress, targetPort, code) {
      const keyPair = generateKeyPair()
      const response = await fetch(`http://${targetAddress}:${targetPort}/lan/v2/pair/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          v: 2,
          from: identity.id,
          fromName: identity.name,
          httpPort: port,
          code,
          pk: keyPair.publicX,
        }),
      })
      const data = await response.json().catch(() => ({}))
      if (!response.ok || data?.ok !== true) return { ok: false, status: response.status, error: data?.error }
      const peerPublicX = String(data.pk || '')
      const shared = deriveShared(keyPair.privateKey, peerPublicX)
      const derived = peerKeys(shared, identity.id, String(data.from))
      const expected = hmacBase64(
        derived.proofKey,
        `pair|${data.from}|${identity.id}|${peerPublicX}|${keyPair.publicX}`,
      )
      if (!safeEqual(expected, String(data.proof || ''))) {
        return { ok: false, error: 'proof mismatch' }
      }
      keys.set(String(data.from), { shared, name: data.name })
      paired = String(data.from)
      return { ok: true, peer: data.name, peerId: data.from, httpPort: data.httpPort }
    },
    /** Send a signed + encrypted message back to the paired node. */
    async sendSecure(targetAddress, targetPort, text) {
      const entry = [...keys.entries()][0]
      if (!entry) return { ok: false, error: 'mock is not paired' }
      const [peerId, value] = entry
      const path_ = '/lan/v2/message'
      const derived = peerKeys(value.shared, identity.id, peerId)
      const box = seal(derived.msgKey, JSON.stringify({ text, fromName: identity.name, httpPort: port }), `${identity.id}|${peerId}|${path_}`)
      const body = JSON.stringify({ v: 2, iv: box.iv, ct: box.ct, tag: box.tag })
      const ts = Date.now()
      const nonce = randomToken(12)
      const sig = hmacBase64(derived.sigKey, signingString({ method: 'POST', path: path_, ts, nonce, body }))
      const response = await fetch(`http://${targetAddress}:${targetPort}${path_}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Lan-From': identity.id,
          'X-Lan-Ts': String(ts),
          'X-Lan-Nonce': nonce,
          'X-Lan-Sig': sig,
        },
        body,
      })
      const data = await response.json().catch(() => ({}))
      return { ok: response.ok && data?.ok === true, status: response.status, data }
    },
    async stop() {
      clearInterval(timer)
      udp.close()
      await new Promise((resolve) => server.close(resolve))
    },
  }
}
