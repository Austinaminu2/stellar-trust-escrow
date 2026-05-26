/**
 * Auth Middleware
 *
 * Validates the Bearer JWT and checks the jti against the session store.
 * Attaches req.user = { address, jti } on success.
 *
 * Performance: session validity check is a single indexed PK lookup.
 * For high-traffic routes, consider a short-lived in-process cache.
 */

import jwt from 'jsonwebtoken';
import sessionService from '../../services/sessionService.js';

const JWT_SECRET = process.env.JWT_SECRET || 'change_this_in_production';

export default async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const payload = jwt.verify(authHeader.slice(7), JWT_SECRET);

    // Check session is still active (not revoked)
    if (payload.jti) {
      const valid = await sessionService.isSessionValid(payload.jti);
      if (!valid) {
        return res.status(401).json({ error: 'Session revoked or expired. Please log in again.' });
      }
    }

    req.user = { address: payload.address, jti: payload.jti };
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    return res.status(401).json({ error: 'Invalid token' });
  }
}
