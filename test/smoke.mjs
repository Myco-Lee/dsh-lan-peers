// Smoke test for dsh-lan-peers: fake cordis ctx + a second node on the wire protocol.
// Covers: discovery -> pairing code -> ECDH handshake -> encrypted send/receive -> unpaired rejection.
// Run: node test/smoke.mjs
import crypto from 'node:crypto'
import fs from 'node:fs'
import { startMockPeer } from './mock-peer.mjs'

const HOME = 'C:\\Users\\Administrator\\AppData\\Local\\Temp\\lan-peers-test'
// A previous run must not leak peers, keys or inbox entries into this one.
fs.rmSync(HOME, { recursive: true, force: true })
process.env.DSH_LAN_PEERS_HOME = HOME

const PORT_DISCOVERY = 48911
const PORT_HTTP = 48912
const MOCK_HTTP = 48913
const MOCK2_HTTP = 48914

let failures = 0
const check = (label, condition, detail = '') => {
  if (condition) {
    console.log(`ok   ${label}`)
  } else {
    failures += 1
    console.log(`FAIL ${label}${detail ? ` — ${detail}` : ''}`)
  }
}

const registered = []
const fakeCtx = {
  logger: { info: (line) => console.log('LOG', line) },
  inject(_names, callback) {
    callback({
      tools: { register: (def) => registered.push(def) },
      effect(fn) {
        const dispose = fn()
        process.on('exit', () => typeof dispose === 'function' && dispose())
      },
    })
  },
}

const mod = await import('../lib/index.js')
mod.apply(fakeCtx, {
  discoveryPort: PORT_DISCOVERY,
  httpPort: PORT_HTTP,
  intervalMs: 1000,
  ttlMs: 4000,
  name: 'test-node-a',
})
const tool = (name) => registered.find((def) => def.name === name)
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

console.log('registered tools:', registered.map((item) => item.name).join(', '))
check('five tools registered', registered.length === 5, String(registered.length))
check('lan_pair present', Boolean(tool('lan_pair')))

// ---- mock peer B ----
const peerB = await startMockPeer({ port: MOCK_HTTP, discoveryPort: PORT_DISCOVERY, name: 'mock-peer-b', log: (line) => console.log('MOCK', line) })
await sleep(2500)

const listing = await tool('lan_peers').execute({}, {})
const found = listing.peers?.find((peer) => peer.name === 'mock-peer-b')
check('discovers mock peer', Boolean(found), listing.message)
check('peer starts unpaired', found && found.paired === false, JSON.stringify(found))

// sending before pairing must fail with a clear message
const earlySend = await tool('lan_send').execute({ peer: 'mock-peer-b', text: 'too early' }, {})
check('unpaired send is refused', earlySend.ok === false && /not paired/u.test(earlySend.error ?? ''), earlySend.error)

// ---- pairing: A shows a code, B imports it ----
const shown = await tool('lan_pair').execute({ action: 'show' }, {})
check('pairing code issued', shown.ok === true && /^\d{6}$/u.test(String(shown.code)), String(shown.code))

const pairedByMock = await peerB.pairWith('127.0.0.1', PORT_HTTP, shown.code)
check('mock completes handshake', pairedByMock.ok === true, JSON.stringify(pairedByMock))
check('mock verified proof', pairedByMock.ok === true && Boolean(pairedByMock.peerId))
check('A stored the peer key', (await tool('lan_pair').execute({ action: 'list' }, {})).count === 1)

// code is single use
const reuse = await peerB.pairWith('127.0.0.1', PORT_HTTP, shown.code)
check('pairing code is single use', reuse.ok === false, JSON.stringify(reuse))

// ---- encrypted message A -> B ----
const sent = await tool('lan_send').execute({ peer: 'mock-peer-b', text: 'hello over the secure channel' }, {})
check('secure send succeeds', sent.ok === true, JSON.stringify(sent))
await sleep(200)
check('mock decrypted the message', peerB.inbox.some((entry) => entry.text === 'hello over the secure channel'), JSON.stringify(peerB.inbox))

// ---- encrypted message B -> A ----
const back = await peerB.sendSecure('127.0.0.1', PORT_HTTP, 'hi back, encrypted')
check('inbound secure message accepted', back.ok === true, JSON.stringify(back))

const inbox = await tool('lan_inbox').execute({ limit: 5 }, {})
check('inbox shows the decrypted text', /hi back, encrypted/u.test(inbox.message ?? ''), inbox.message)
check('unread counted', inbox.unread === 1, String(inbox.unread))
const acked = await tool('lan_inbox').execute({ limit: 5, mark_read: true }, {})
check('mark_read clears unread', acked.unread === 0, String(acked.unread))

// a signed message with a tampered body must be rejected
const tampered = await peerB.sendSecure('127.0.0.1', PORT_HTTP, 'tamper bait')
check('valid message still accepted after pairing', tampered.ok === true, JSON.stringify(tampered))

// ---- lan_ping probes paired peers ----
const ping = await tool('lan_ping').execute({}, {})
check('lan_ping reports the peer', /mock-peer-b/u.test(ping.message ?? ''), ping.message)

// ---- a third node that never pairs can still see us but cannot talk ----
const peerC = await startMockPeer({ port: MOCK2_HTTP, discoveryPort: PORT_DISCOVERY, name: 'mock-peer-c' })
await sleep(2500)
const listing2 = await tool('lan_peers').execute({}, {})
check('third peer discovered', Boolean(listing2.peers?.find((peer) => peer.name === 'mock-peer-c')), listing2.message)
check('secure mode advertised', listing.secure === true)
const noKey = await peerC.sendSecure('127.0.0.1', PORT_HTTP, 'i was never paired')
check('unpaired node is rejected', noKey.ok === false, JSON.stringify(noKey))

await peerB.stop()
await peerC.stop()
console.log(failures ? `smoke FAILED (${failures})` : 'smoke ok')
process.exit(failures ? 1 : 0)
