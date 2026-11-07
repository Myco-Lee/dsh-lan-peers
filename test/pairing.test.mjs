// Unit tests for lib/pairing.js — run: node test/pairing.test.mjs
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import { createPairingStore, createKeyStore } from '../lib/pairing.js'

let failures = 0
const check = (label, condition, detail = '') => {
  if (condition) console.log(`ok   ${label}`)
  else {
    failures += 1
    console.log(`FAIL ${label}${detail ? ` — ${detail}` : ''}`)
  }
}

// ---- pairing codes ----
const store = createPairingStore({ codeTtlMs: 60_000, codeLength: 6, maxAttemptsPerMinute: 3 })
check('starts with no active code', store.status().active === false)

const issued = store.createCode()
check('code is six digits', /^\d{6}$/u.test(issued.code), issued.code)
check('code is active', store.status().active === true)
check('wrong code rejected', store.consume('000000'.padStart(6, '9')).ok === false)
check('code still active after a wrong guess', store.status().active === true)

const good = store.consume(issued.code)
check('correct code accepted', good.ok === true, good.reason)
check('code burned after use', store.status().active === false)
check('second use of the same code rejected', store.consume(issued.code).ok === false)

// rate limit: 3 attempts per minute per ip
const limited = createPairingStore({ codeTtlMs: 60_000, maxAttemptsPerMinute: 3 })
limited.createCode()
const results = [1, 2, 3, 4].map(() => limited.consume('nope', '10.0.0.9'))
check('allows the configured number of attempts', results.slice(0, 3).every((item) => !/too many/u.test(item.reason)))
check('blocks further attempts from the same ip', /too many/u.test(results[3].reason), results[3].reason)
check('another ip is unaffected', !/too many/u.test(limited.consume('nope', '10.0.0.10').reason))

// expiry
const shortLived = createPairingStore({ codeTtlMs: 20, maxAttemptsPerMinute: 5 })
const expiring = shortLived.createCode()
await new Promise((resolve) => setTimeout(resolve, 60))
check('expired code is inactive', shortLived.status().active === false)
check('expired code is rejected', shortLived.consume(expiring.code).ok === false)

// creating a new code invalidates the previous one
const rotating = createPairingStore({ codeTtlMs: 60_000 })
const firstCode = rotating.createCode()
const secondCode = rotating.createCode()
check('new code replaces the old one', rotating.consume(firstCode.code).ok === false && firstCode.code !== secondCode.code)

// ---- key store ----
const home = path.join(os.tmpdir(), `lan-peers-keys-${crypto.randomUUID()}`)
const keyStore = createKeyStore(home)
check('empty key store lists nothing', keyStore.list().length === 0)

const shared = crypto.randomBytes(32)
const saved = keyStore.save({ id: 'peer-1', name: 'LMM', address: '192.168.8.164', httpPort: 48902, peerPublicX: 'abc', shared })
check('save returns a record', saved.id === 'peer-1' && Boolean(saved.pairedAt))
check('key file exists', fs.existsSync(path.join(keyStore.keyDir, 'peer-1.json')))
check('shared secret round-trips', Buffer.from(keyStore.get('peer-1').shared, 'base64').equals(shared))
check('list returns the peer', keyStore.list().length === 1 && keyStore.list()[0].name === 'LMM')
check('unknown id returns null', keyStore.get('nobody') === null)

keyStore.save({ id: 'peer-2', name: 'other', shared: crypto.randomBytes(32) })
check('two peers listed', keyStore.list().length === 2)
check('remove works', keyStore.remove('peer-2') === true && keyStore.list().length === 1)
check('removing an unknown id is false', keyStore.remove('peer-2') === false)
check('clear removes everything', keyStore.clear() === 1 && keyStore.list().length === 0)

if (process.platform !== 'win32') {
  const mode = fs.statSync(path.join(keyStore.keyDir, '..')).mode & 0o777
  check('state dir is private (0700)', (mode & 0o077) === 0, mode.toString(8))
}

fs.rmSync(home, { recursive: true, force: true })
console.log(failures ? `pairing FAILED (${failures})` : 'pairing ok')
process.exit(failures ? 1 : 0)
