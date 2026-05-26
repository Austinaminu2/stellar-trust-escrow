/**
 * Transaction Utilities
 *
 * Wraps Prisma $transaction with:
 *   - Deadlock detection (PostgreSQL code 40P01, serialization failure 40001)
 *   - Exponential backoff retry
 *   - Configurable isolation level
 *
 * Usage:
 *   import { withTransaction, withRetry } from '../lib/transaction.js';
 *
 *   const result = await withTransaction(async (tx) => {
 *     await tx.escrow.update(...);
 *     await tx.milestone.updateMany(...);
 *     return result;
 *   });
 */

import prisma from './prisma.js';

// PostgreSQL error codes that indicate a retryable conflict
const RETRYABLE_CODES = new Set(['40P01', '40001']); // deadlock, serialization failure

const DEFAULT_MAX_RETRIES = parseInt(process.env.TX_MAX_RETRIES || '3', 10);
const DEFAULT_BASE_DELAY_MS = parseInt(process.env.TX_BASE_DELAY_MS || '50', 10);
const DEFAULT_ISOLATION = process.env.TX_ISOLATION_LEVEL || 'ReadCommitted';

/**
 * Returns true if the error is a retryable PostgreSQL deadlock or
 * serialization failure.
 */
export function isDeadlock(err) {
  const code = err?.code ?? err?.meta?.code;
  return RETRYABLE_CODES.has(code);
}

/**
 * Sleeps for `ms` milliseconds with ±20% jitter to avoid thundering herd.
 */
function sleep(ms) {
  const jitter = ms * 0.2 * (Math.random() * 2 - 1);
  return new Promise((r) => setTimeout(r, Math.max(0, ms + jitter)));
}

/**
 * Retries `fn` up to `maxRetries` times on deadlock/serialization errors,
 * using exponential backoff.
 *
 * @template T
 * @param {() => Promise<T>} fn
 * @param {object} [opts]
 * @param {number} [opts.maxRetries]
 * @param {number} [opts.baseDelayMs]
 * @returns {Promise<T>}
 */
export async function withRetry(fn, { maxRetries = DEFAULT_MAX_RETRIES, baseDelayMs = DEFAULT_BASE_DELAY_MS } = {}) {
  let attempt = 0;
  while (true) {
    try {
      return await fn();
    } catch (err) {
      attempt++;
      if (!isDeadlock(err) || attempt > maxRetries) throw err;
      const delay = baseDelayMs * 2 ** (attempt - 1);
      console.warn(`[TX] Deadlock detected (attempt ${attempt}/${maxRetries}), retrying in ${delay}ms`);
      await sleep(delay);
    }
  }
}

/**
 * Runs `fn` inside a Prisma interactive transaction with the configured
 * isolation level, retrying on deadlock.
 *
 * @template T
 * @param {(tx: import('@prisma/client').PrismaClient) => Promise<T>} fn
 * @param {object} [opts]
 * @param {string} [opts.isolationLevel]
 * @param {number} [opts.maxRetries]
 * @param {number} [opts.baseDelayMs]
 * @param {number} [opts.timeout]  — transaction timeout in ms (default 10s)
 * @returns {Promise<T>}
 */
export async function withTransaction(fn, {
  isolationLevel = DEFAULT_ISOLATION,
  maxRetries = DEFAULT_MAX_RETRIES,
  baseDelayMs = DEFAULT_BASE_DELAY_MS,
  timeout = 10_000,
} = {}) {
  return withRetry(
    () => prisma.$transaction(fn, { isolationLevel, timeout }),
    { maxRetries, baseDelayMs },
  );
}

export default { withTransaction, withRetry, isDeadlock };
