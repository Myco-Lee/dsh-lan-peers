// Smoke test for dsh-lan-peers: fake cordis ctx + a second mock node on the LAN.
// Run: node test/smoke.mjs
import dgram from 'node:dgram'
import http from 'node:http'
import crypto from 'node:crypto'

process.env.DSH_LAN_PEERS_HOME = 'C:\\Users\\Administrator\\AppData\\Local\\Temp\\lan-peers-test'

const PORT_DISCOVERY = 48911
const PORT_HTTP = 48912
const MOCK_HTTP = 48913

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
const config = { discoveryPort: PORT_DISCOVERY, httpPort: PORT_HTTP, intervalMs: 1000, ttlMs: 4000, name: 'test-node-a' }
mod.apply(fakeCtx, config)
console.log('registered tools:', registered.map((tool) => tool.name).join(', '))

// ---- mock peer node ----
const mockId = crypto.randomUUID()
const mockUdp = dgram.createSocket({ type: 'udp4', reuseAddr: true })
const mockServer = http.createServer((req, res) => {
  let body = ''
  req.on('data', (chunk) => (body += chunk))
  req.on('end', () => {
    console.log('MOCK received', req.method, req.url, body.slice(0, 200))
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ ok: true, id: crypto.randomUUID() }))
  })
})
await new Promise((resolve) => mockServer.listen(MOCK_HTTP, '0.0.0.0', resolve))
await new Promise((resolve) => mockUdp.bind(PORT_DISCOVERY, resolve))
mockUdp.setBroadcast(true)
mockUdp.on('message', (buffer, rinfo) => {
  const msg = JSON.parse(buffer.toString())
  console.log('MOCK saw announce from', msg.name, rinfo.address)
})
const announce = () =>
  mockUdp.send(
    Buffer.from(JSON.stringify({ v: 1, kind: 'announce', id: mockId, name: 'mock-peer-b', version: '0.1.0', httpPort: MOCK_HTTP, ts: Date.now() })),
    PORT_DISCOVERY,
    '255.255.255.255',
  )
announce()
const timer = setInterval(announce, 1000)

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
await sleep(3500)

const hello = await (await fetch(`http://127.0.0.1:${PORT_HTTP}/lan/hello`)).json()
console.log('hello:', JSON.stringify(hello))

const tool = (toolName) => registered.find((def) => def.name === toolName)
const list = await tool('lan_peers').execute({}, {})
console.log('lan_peers:', list.message)

const selfPeer = list.peers.find((peer) => peer.name === 'mock-peer-b')
console.log('mock peer discovered:', Boolean(selfPeer), selfPeer?.address, selfPeer?.httpPort)

const sent = await tool('lan_send').execute({ peer: 'mock-peer-b', text: 'hello from test node a' }, {})
console.log('lan_send:', JSON.stringify(sent))

// peer -> us
const posted = await (
  await fetch(`http://127.0.0.1:${PORT_HTTP}/lan/message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: mockId, fromName: 'mock-peer-b', text: 'hi back from mock' }),
  })
).json()
console.log('inbound post:', JSON.stringify(posted))

const inbox = await tool('lan_inbox').execute({ limit: 5 }, {})
console.log('lan_inbox:', inbox.message)
const acked = await tool('lan_inbox').execute({ limit: 5, mark_read: true }, {})
console.log('after mark_read:', acked.unread)
const ping = await tool('lan_ping').execute({}, {})
console.log('lan_ping:', ping.message)

clearInterval(timer)
mockUdp.close()
mockServer.close()
process.exit(0)
