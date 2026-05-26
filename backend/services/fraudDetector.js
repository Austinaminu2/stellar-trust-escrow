/**
 * Fraud Detection Service
 *
 * Runs on escrow completion to detect collusive or wash-trading patterns.
 * Produces a numeric suspicion score (0–100). Escrows above the threshold
 * are flagged as Suspicious and reputation updates are suspended.
 *
 * ## Signals and weights (configurable via env)
 *
 * | Signal                          | Default weight |
 * |---------------------------------|---------------|
 * | Same IP for client + freelancer | 40             |
 * | Rapid completion (< 1 hour)     | 20             |
 * | Repeated pair (> 3 escrows)     | 25             |
 * | Round-number amount             | 10             |
 * | Zero milestones                 | 5              |
 *
 * Threshold: FRAUD_SCORE_THRESHOLD (default 50)
 */

import prisma from '../lib/prisma.js';

// ── Config ────────────────────────────────────────────────────────────────────

const THRESHOLD = parseInt(process.env.FRAUD_SCORE_THRESHOLD || '50', 10);
const RAPID_COMPLETION_MS = parseInt(process.env.FRAUD_RAPID_MS || String(60 * 60 * 1000), 10);
const REPEATED_PAIR_COUNT = parseInt(process.env.FRAUD_REPEATED_PAIR || '3', 10);

const WEIGHTS = {
  sameIp:          parseInt(process.env.FRAUD_W_SAME_IP || '40', 10),
  rapidCompletion: parseInt(process.env.FRAUD_W_RAPID   || '20', 10),
  repeatedPair:    parseInt(process.env.FRAUD_W_PAIR    || '25', 10),
  roundAmount:     parseInt(process.env.FRAUD_W_ROUND   || '10', 10),
  zeroMilestones:  parseInt(process.env.FRAUD_W_ZERO_MS || '5',  10),
};

// ── Signal detectors ──────────────────────────────────────────────────────────

/**
 * Checks if client and freelancer share the same last-known IP address.
 * IP addresses are stored on the Session model.
 */
async function checkSameIp(clientAddress, freelancerAddress) {
  try {
    const [clientSession, freelancerSession] = await Promise.all([
      prisma.session.findFirst({
        where: { address: clientAddress, revokedAt: null },
        orderBy: { createdAt: 'desc' },
        select: { ipAddress: true },
      }),
      prisma.session.findFirst({
        where: { address: freelancerAddress, revokedAt: null },
        orderBy: { createdAt: 'desc' },
        select: { ipAddress: true },
      }),
    ]);
    if (!clientSession?.ipAddress || !freelancerSession?.ipAddress) return false;
    return clientSession.ipAddress === freelancerSession.ipAddress;
  } catch {
    return false;
  }
}

/**
 * Checks if the escrow was completed suspiciously fast.
 */
function checkRapidCompletion(createdAt, completedAt) {
  if (!createdAt || !completedAt) return false;
  return new Date(completedAt) - new Date(createdAt) < RAPID_COMPLETION_MS;
}

/**
 * Checks if this client-freelancer pair has completed many escrows together.
 */
async function checkRepeatedPair(clientAddress, freelancerAddress, currentEscrowId) {
  try {
    const count = await prisma.escrow.count({
      where: {
        clientAddress,
        freelancerAddress,
        status: 'Completed',
        id: { not: BigInt(currentEscrowId) },
      },
    });
    return count >= REPEATED_PAIR_COUNT;
  } catch {
    return false;
  }
}

/**
 * Checks if the escrow amount is suspiciously round (divisible by 1M stroops).
 */
function checkRoundAmount(totalAmount) {
  try {
    const n = BigInt(totalAmount);
    return n > 0n && n % 1_000_000n === 0n;
  } catch {
    return false;
  }
}

// ── Main scorer ───────────────────────────────────────────────────────────────

/**
 * Computes a fraud suspicion score for a completed escrow.
 *
 * @param {object} escrow — Prisma Escrow record
 * @returns {Promise<{ score: number, signals: string[], flagged: boolean }>}
 */
export async function scoreEscrow(escrow) {
  const signals = [];
  let score = 0;

  const [sameIp, repeatedPair] = await Promise.all([
    checkSameIp(escrow.clientAddress, escrow.freelancerAddress),
    checkRepeatedPair(escrow.clientAddress, escrow.freelancerAddress, escrow.id),
  ]);

  if (sameIp) {
    score += WEIGHTS.sameIp;
    signals.push('SAME_IP');
  }

  if (checkRapidCompletion(escrow.createdAt, escrow.updatedAt)) {
    score += WEIGHTS.rapidCompletion;
    signals.push('RAPID_COMPLETION');
  }

  if (repeatedPair) {
    score += WEIGHTS.repeatedPair;
    signals.push('REPEATED_PAIR');
  }

  if (checkRoundAmount(escrow.totalAmount)) {
    score += WEIGHTS.roundAmount;
    signals.push('ROUND_AMOUNT');
  }

  // Zero milestones check
  const milestoneCount = await prisma.milestone.count({ where: { escrowId: escrow.id } }).catch(() => 0);
  if (milestoneCount === 0) {
    score += WEIGHTS.zeroMilestones;
    signals.push('ZERO_MILESTONES');
  }

  const flagged = score >= THRESHOLD;
  return { score, signals, flagged };
}

/**
 * Runs fraud detection on a completed escrow.
 * If flagged:
 *   - Marks the escrow with a fraud flag in the audit log
 *   - Suspends reputation updates for both parties
 *   - Notifies moderators via the audit log
 *
 * @param {bigint|string} escrowId
 * @returns {Promise<{ score: number, flagged: boolean, signals: string[] }>}
 */
export async function runFraudCheck(escrowId) {
  const escrow = await prisma.escrow.findUnique({
    where: { id: BigInt(escrowId) },
  });

  if (!escrow) throw new Error(`Escrow ${escrowId} not found`);

  const result = await scoreEscrow(escrow);

  if (result.flagged) {
    const reason = `Fraud signals: ${result.signals.join(', ')} (score: ${result.score})`;

    // Log for moderator review
    await prisma.adminAuditLog.create({
      data: {
        action: 'FRAUD_FLAGGED',
        targetAddress: escrow.clientAddress,
        reason,
        performedBy: 'system:fraud-detector',
        performedAt: new Date(),
      },
    });

    // Suspend reputation updates by marking both addresses in audit log
    await Promise.all([
      prisma.adminAuditLog.create({
        data: {
          action: 'REPUTATION_SUSPENDED',
          targetAddress: escrow.clientAddress,
          reason: `Pending fraud review for escrow ${escrowId}`,
          performedBy: 'system:fraud-detector',
          performedAt: new Date(),
        },
      }),
      prisma.adminAuditLog.create({
        data: {
          action: 'REPUTATION_SUSPENDED',
          targetAddress: escrow.freelancerAddress,
          reason: `Pending fraud review for escrow ${escrowId}`,
          performedBy: 'system:fraud-detector',
          performedAt: new Date(),
        },
      }),
    ]);

    console.warn(`[FraudDetector] Escrow ${escrowId} flagged — score=${result.score} signals=${result.signals.join(',')}`);
  }

  return result;
}

/**
 * Checks if reputation updates are suspended for an address.
 * Returns true if a REPUTATION_SUSPENDED log exists with no subsequent REPUTATION_RESTORED.
 */
export async function isReputationSuspended(address) {
  try {
    const latest = await prisma.adminAuditLog.findFirst({
      where: {
        targetAddress: address,
        action: { in: ['REPUTATION_SUSPENDED', 'REPUTATION_RESTORED'] },
      },
      orderBy: { performedAt: 'desc' },
    });
    return latest?.action === 'REPUTATION_SUSPENDED';
  } catch {
    return false;
  }
}

export default { runFraudCheck, scoreEscrow, isReputationSuspended };
