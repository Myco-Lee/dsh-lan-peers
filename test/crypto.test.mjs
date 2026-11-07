// Unit tests for lib/crypto.js — run: node test/crypto.test.mjs
import crypto from 'node:crypto'
import {
  generateKeyPair,
  deriveShared,
  peerKeys,
  hmacBase64,
  seal,
  open,
  signingString,
  safeEqual,
  numericCode,
  randomToken,
  sha256Hex,
} from '../lib/crypto.js'

let failures = 0
const check = (label, condition, detail = '') => {
  if (condition) console.log(`ok   ${label}`)
  else {
    failures += 1
    console.log(`FAIL ${label}${detail ? ` — ${detail}` : ''}`)
  }
}

// --- ECDH agreement + symmetric derivation ---
const alice = generateKeyPair()
const bob = generateKeyPair()
const sharedA = deriveShared(alice.privateKey, bob.publicX)
const sharedB = deriveShared(bob.privateKey, alice.publicX)
check('ECDH shared secrets match', sharedA.equals(sharedB))
check('shared secret is 32 bytes', sharedA.length === 32, String(sharedA.length))

const keysA = peerKeys(sharedA, 'id-a', 'id-b')
const keysB = peerKeys(sharedB, 'id-b', 'id-a')
check('sigKey symmetric across peers', keysA.sigKey.equals(keysB.sigKey))
check('msgKey symmetric across peers', keysA.msgKey.equals(keysB.msgKey))
check('proofKey symmetric across peers', keysA.proofKey.equals(keysB.proofKey))
check('different peer pair gives different key', !peerKeys(sharedA, 'id-a', 'id-c').msgKey.equals(keysA.msgKey))

// --- sealing ---
const aad = 'id-a|id-b|/lan/v2/message'
const box = seal(keysA.msgKey, JSON.stringify({ text: '絕密 / secret' }), aad)
check('ciphertext differs from plaintext', !box.ct.includes('secret'))
const round = JSON.parse(open(keysB.msgKey, box, aad))
check('open() recovers the plaintext', round.text === '絕密 / secret', JSON.stringify(round))

let tampered = false
try {
  open(keysB.msgKey, { ...box, ct: Buffer.from('AAAA', 'base64url').toString('base64url') }, aad)
} catch {
  tampered = true
}
check('tampered ciphertext is rejected', tampered)

let wrongAad = false
try {
  open(keysB.msgKey, box, 'id-a|id-c|/lan/v2/message')
} catch {
  wrongAad = true
}
check('wrong AAD is rejected', wrongAad)

let wrongKey = false
try {
  open(crypto.randomBytes(32), box, aad)
} catch {
  wrongKey = true
}
check('wrong key is rejected', wrongKey)

// --- signing ---
const ts = 1_700_000_000_000
const nonce = randomToken(12)
const sigBody = '{"v":2}'
const line = signingString({ method: 'POST', path: '/lan/v2/message', ts, nonce, body: sigBody })
check('signing string is stable', line === `POST\n/lan/v2/message\n${ts}\n${nonce}\n${sha256Hex(sigBody)}`, JSON.stringify(line))
check('verifying signature with own key works', safeEqual(hmacBase64(keysA.sigKey, line), hmacBase64(keysB.sigKey, line)))
check('signature differs from a foreign key', !safeEqual(hmacBase64(keysA.sigKey, line), hmacBase64(crypto.randomBytes(32), line)))

// --- helpers ---
const code = numericCode(6)
check('numeric code is six digits', /^\d{6}$/u.test(code), code)
check('random tokens differ', randomToken(12) !== randomToken(12))
check('safeEqual rejects different lengths', safeEqual('abc', 'abcd') === false)

console.log(failures ? `crypto FAILED (${failures})` : 'crypto ok')
process.exit(failures ? 1 : 0)
