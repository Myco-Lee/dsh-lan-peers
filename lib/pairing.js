/**
 * Pairing state for dsh-lan-peers v2.
 *
 * Two separate concerns:
 *  - the short-lived pairing code a node shows to a human (stored hashed, single use)
 *  - the long-lived per-peer keys written after a successful handshake
 *
 * Nothing here talks to the network; index.js owns the HTTP surface.
 */

import fs from 'node:fs'
import path from 'node:path'
import { numericCode, randomToken, safeEqual, sha256Hex } from './crypto.js'

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
}

function writeSecure(file, text) {
  ensureDir(path.dirname(file))
  fs.writeFileSync(file, text, { encoding: 'utf8', mode: 0o600 })
}

export function createPairingStore({ codeTtlMs = 600_000, codeLength = 6, maxAttemptsPerMinute = 5 } = {}) {
  /** @type {{ hash: string, expiresAt: number, code: string } | null} */
  let pending = null
  let attempts = []

  function now() {
    return Date.now()
  }

  function active() {
    if (!pending) return null
    if (pending.expiresAt <= now()) {
      pending = null
      return null
    }
    return pending
  }

  function createCode() {
    const code = numericCode(codeLength)
    pending = { code, hash: sha256Hex(code), expiresAt: now() + codeTtlMs }
    attempts = []
    return { code, expiresAt: new Date(pending.expiresAt).toISOString(), ttlMs: codeTtlMs }
  }

  function clear() {
    pending = null
    attempts = []
  }

  function status() {
    const current = active()
    return {
      active: Boolean(current),
      expiresAt: current ? new Date(current.expiresAt).toISOString() : null,
      codeLength,
    }
  }

  function throttle(ip) {
    const cutoff = now() - 60_000
    attempts = attempts.filter((item) => item.at > cutoff)
    const recent = attempts.filter((item) => item.ip === ip).length
    return recent < maxAttemptsPerMinute
  }

  /**
   * Check a presented code. Returns { ok, reason }. A success burns the code,
   * which is what makes it one-time.
   */
  function consume(code, ip = 'unknown') {
    const current = active()
    if (!current) return { ok: false, reason: 'no active pairing code' }
    if (!throttle(ip)) return { ok: false, reason: 'too many pairing attempts, try again in a minute' }
    attempts.push({ ip, at: now() })
    if (!safeEqual(sha256Hex(String(code).trim()), current.hash)) {
      return { ok: false, reason: 'pairing code does not match' }
    }
    pending = null
    attempts = []
    return { ok: true, reason: 'paired' }
  }

  return { createCode, consume, clear, status, active }
}

export function createKeyStore(dir) {
  const keyDir = path.join(dir, 'peers.d')

  function fileFor(id) {
    const safe = String(id).replace(/[^A-Za-z0-9_.-]/gu, '_').slice(0, 120)
    return path.join(keyDir, `${safe}.json`)
  }

  function list() {
    let names = []
    try {
      names = fs.readdirSync(keyDir).filter((name) => name.endsWith('.json'))
    } catch {
      return []
    }
    const out = []
    for (const name of names) {
      try {
        const raw = JSON.parse(fs.readFileSync(path.join(keyDir, name), 'utf8'))
        if (raw && typeof raw.id === 'string' && typeof raw.shared === 'string') out.push(raw)
      } catch {
        /* a corrupt key file must not break the tool */
      }
    }
    return out.sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')))
  }

  function get(id) {
    try {
      const raw = JSON.parse(fs.readFileSync(fileFor(id), 'utf8'))
      return raw && typeof raw.shared === 'string' ? raw : null
    } catch {
      return null
    }
  }

  function save(entry) {
    const record = {
      id: entry.id,
      name: entry.name || entry.id,
      address: entry.address || '',
      httpPort: entry.httpPort || 0,
      peerPublicX: entry.peerPublicX || '',
      shared: Buffer.from(entry.shared).toString('base64'),
      pairedAt: entry.pairedAt || new Date().toISOString(),
      token: entry.token || randomToken(8),
    }
    writeSecure(fileFor(record.id), `${JSON.stringify(record, null, 2)}\n`)
    return record
  }

  function remove(id) {
    try {
      fs.unlinkSync(fileFor(id))
      return true
    } catch {
      return false
    }
  }

  function clear() {
    let removed = 0
    for (const entry of list()) {
      if (remove(entry.id)) removed += 1
    }
    return removed
  }

  return { list, get, save, remove, clear, keyDir }
}
