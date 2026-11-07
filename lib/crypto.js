/**
 * Crypto helpers for dsh-lan-peers v2.
 *
 * Everything here is built on node:crypto only — no third-party dependency.
 *
 * - X25519 ephemeral key exchange (ECDH)
 * - HKDF-SHA256 to derive purpose-bound keys from the shared secret
 * - HMAC-SHA256 request signatures
 * - AES-256-GCM payload encryption
 */

import crypto from 'node:crypto'

/** Random URL-safe token, `bytes` of entropy. */
export function randomToken(bytes = 16) {
  return crypto.randomBytes(bytes).toString('base64url')
}

/** Numeric pairing code, leading zeros preserved. */
export function numericCode(length = 6) {
  const digits = '0123456789'
  let out = ''
  for (let i = 0; i < length; i += 1) out += digits[crypto.randomInt(0, 10)]
  return out
}

/** sha256 hex digest — used to store pairing codes so the code itself is never persisted. */
export function sha256Hex(value) {
  return crypto.createHash('sha256').update(String(value), 'utf8').digest('hex')
}

/** Constant-time comparison for two equal-length hex strings. */
export function safeEqual(a, b) {
  const left = Buffer.from(String(a), 'utf8')
  const right = Buffer.from(String(b), 'utf8')
  if (left.length !== right.length) return false
  return crypto.timingSafeEqual(left, right)
}

/** Fresh X25519 key pair; the public half is serialised as the raw JWK x value. */
export function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519')
  const jwk = publicKey.export({ format: 'jwk' })
  return { privateKey, publicX: jwk.x }
}

function importPublicX(x) {
  return crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x }, format: 'jwk' })
}

/** ECDH shared secret (32 bytes) between our private key and a peer's raw public x. */
export function deriveShared(privateKey, peerPublicX) {
  return crypto.diffieHellman({ privateKey, publicKey: importPublicX(peerPublicX) })
}

/** Purpose-bound key derivation from the ECDH secret. */
export function deriveKey(shared, salt, info) {
  const out = crypto.hkdfSync('sha256', shared, Buffer.from(salt, 'utf8'), Buffer.from(info, 'utf8'), 32)
  return Buffer.from(out)
}

export function hmac(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest()
}

export function hmacBase64(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest('base64url')
}

/** AES-256-GCM seal; returns { iv, ct } as base64url strings. */
export function seal(key, plaintext, aad) {
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
  cipher.setAAD(Buffer.from(aad, 'utf8'))
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()])
  const tag = cipher.getAuthTag()
  return { iv: iv.toString('base64url'), ct: ct.toString('base64url'), tag: tag.toString('base64url') }
}

/** AES-256-GCM open; throws when the payload was tampered with. */
export function open(key, box, aad) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(box.iv, 'base64url'))
  decipher.setAAD(Buffer.from(aad, 'utf8'))
  decipher.setAuthTag(Buffer.from(box.tag, 'base64url'))
  const out = Buffer.concat([decipher.update(Buffer.from(box.ct, 'base64url')), decipher.final()])
  return out.toString('utf8')
}

/**
 * Canonical string that gets signed for every request.
 * The body is hashed, so the signature covers the exact bytes that were sent.
 */
export function signingString({ method, path: reqPath, ts, nonce, body }) {
  const bodyHash = crypto.createHash('sha256').update(body ?? '', 'utf8').digest('hex')
  return `${String(method).toUpperCase()}\n${reqPath}\n${ts}\n${nonce}\n${bodyHash}`
}

/** Two keys per paired peer: one to sign, one to encrypt. */
export function peerKeys(shared, selfId, peerId) {
  const salt = [selfId, peerId].sort().join('|')
  return {
    sigKey: deriveKey(shared, salt, 'lan-peers/v2/sig'),
    msgKey: deriveKey(shared, salt, 'lan-peers/v2/msg'),
    proofKey: deriveKey(shared, salt, 'lan-peers/v2/proof'),
  }
}
