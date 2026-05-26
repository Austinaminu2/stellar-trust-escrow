/**
 * Session Service
 *
 * Tracks active JWT sessions in PostgreSQL (via Prisma) so tokens can be
 * individually or globally revoked. Falls back to an in-memory store when
 * the DB is unavailable (e.g. during tests).
 *
 * Each session record stores:
 *   - jti       — unique JWT ID (uuid v4)
 *   - address   — Stellar public key
 *   - userAgent — browser/client identifier
 *   - ipAddress — originating IP
 *   - createdAt — when the session was created
 *   - expiresAt — when the JWT expires
 *   - revokedAt — null until revoked
 */

import crypto from 'crypto';
import prisma from '../lib/prisma.js';

// In-memory fallback (used when DB is unavailable or in tests)
const memSessions = new Map(); // jti → session

// ── Helpers ───────────────────────────────────────────────────────────────────

function nowPlusSeconds(seconds) {
  return new Date(Date.now() + seconds * 1000);
}

function parseExpiresIn(expiresIn) {
  if (typeof expiresIn === 'number') return expiresIn;
  const match = String(expiresIn).match(/^(\d+)([smhd])$/);
  if (!match) return 86400;
  const [, n, unit] = match;
  const multipliers = { s: 1, m: 60, h: 3600, d: 86400 };
  return parseInt(n) * multipliers[unit];
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Creates a new session record and returns the jti.
 */
export async function createSession({ address, userAgent, ipAddress, expiresIn = '24h' }) {
  const jti = crypto.randomUUID();
  const expiresAt = nowPlusSeconds(parseExpiresIn(expiresIn));

  try {
    await prisma.session.create({
      data: { jti, address, userAgent: userAgent ?? '', ipAddress: ipAddress ?? '', expiresAt },
    });
  } catch {
    // DB unavailable — use memory fallback
    memSessions.set(jti, { jti, address, userAgent, ipAddress, expiresAt, revokedAt: null, createdAt: new Date() });
  }

  return jti;
}

/**
 * Returns true if the session is valid (exists, not revoked, not expired).
 */
export async function isSessionValid(jti) {
  try {
    const session = await prisma.session.findUnique({ where: { jti } });
    if (!session) return false;
    if (session.revokedAt) return false;
    if (session.expiresAt < new Date()) return false;
    return true;
  } catch {
    const s = memSessions.get(jti);
    if (!s) return false;
    if (s.revokedAt) return false;
    if (s.expiresAt < new Date()) return false;
    return true;
  }
}

/**
 * Lists all active (non-revoked, non-expired) sessions for an address.
 */
export async function listSessions(address) {
  try {
    return prisma.session.findMany({
      where: { address, revokedAt: null, expiresAt: { gt: new Date() } },
      orderBy: { createdAt: 'desc' },
      select: { jti: true, userAgent: true, ipAddress: true, createdAt: true, expiresAt: true },
    });
  } catch {
    return [...memSessions.values()].filter(
      s => s.address === address && !s.revokedAt && s.expiresAt > new Date(),
    );
  }
}

/**
 * Revokes a specific session by jti.
 */
export async function revokeSession(jti) {
  try {
    await prisma.session.update({ where: { jti }, data: { revokedAt: new Date() } });
  } catch {
    const s = memSessions.get(jti);
    if (s) s.revokedAt = new Date();
  }
}

/**
 * Revokes all sessions for an address (global logout).
 */
export async function revokeAllSessions(address) {
  try {
    await prisma.session.updateMany({
      where: { address, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  } catch {
    for (const s of memSessions.values()) {
      if (s.address === address) s.revokedAt = new Date();
    }
  }
}

export default { createSession, isSessionValid, listSessions, revokeSession, revokeAllSessions };
