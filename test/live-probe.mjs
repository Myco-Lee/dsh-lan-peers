// Live integration probe against the running DSH host (plugin already mounted).
// Announces a fake peer on udp/48901, listens on http/48903, then checks that the
// host discovered it and that the host mailbox accepts our message.
import dgram from 'node:dgram'
import http from 'node:http'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'

const DISCOVERY = 48901
const HOST_HTTP = 48902
const MOCK_HTTP = 48903
const stateDir = path.join(os.homedir(), '.dsh', 'lan-peers')
const mockId = crypto.randomUUID()

const seen = []
const server = http.createServer((req, res) => {
  let body = ''
  req.on('data', (c) => (body += c))
  req.on('end', () => {
    console.log('MOCK-HTTP', req.method, req.url, body.slice(0, 160))
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ ok: true, id: crypto.randomUUID() }))
  })
})
await new Promise((r) => server.listen(MOCK_HTTP, '0.0.0.0', r))

const udp = dgram.createSocket({ type: 'udp4', reuseAddr: true })
await new Promise((r) => udp.bind(DISCOVERY, r))
udp.setBroadcast(true)
udp.on('message', (buf, rinfo) => {
  const msg = JSON.parse(buf.toString())
  if (msg.id === mockId) return
  seen.push({ name: msg.name, from: rinfo.address, httpPort: msg.httpPort })
})
const announce = () =>
  udp.send(
    Buffer.from(
      JSON.stringify({ v: 1, kind: 'announce', id: mockId, name: 'mock-peer-live', version: '0.1.0', httpPort: MOCK_HTTP, ts: Date.now() }),
    ),
    DISCOVERY,
    '255.255.255.255',
  )
announce()
const timer = setInterval(announce, 1500)
await new Promise((r) => setTimeout(r, 9000))
clearInterval(timer)

const status = JSON.parse(fs.readFileSync(path.join(stateDir, 'status.json'), 'utf8'))
console.log('host name:', status.name, '| self id:', status.self.id)
console.log('host saw announces from:', JSON.stringify(seen.slice(0, 3)))
console.log('host peer table:', JSON.stringify(status.peers))

const posted = await (
  await fetch(`http://127.0.0.1:${HOST_HTTP}/lan/message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: mockId, fromName: 'mock-peer-live', httpPort: MOCK_HTTP, text: 'live integration ping from mock-peer-live' }),
  })
).json()
console.log('post to host mailbox:', JSON.stringify(posted))

const inbox = fs.readFileSync(path.join(stateDir, 'inbox.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l))
console.log('host inbox tail:', JSON.stringify(inbox.slice(-1)))

const messages = await (await fetch(`http://127.0.0.1:${HOST_HTTP}/lan/messages?limit=3`)).json()
console.log('GET /lan/messages ok:', messages.ok, 'count:', messages.count)

udp.close()
server.close()
process.exit(0)
