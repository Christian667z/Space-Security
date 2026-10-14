import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
import { logger } from './logger.ts';

// Cryptographically secure token generated on server startup
const SERVER_AUTH_TOKEN = process.env.SPACESEC_AUTH_TOKEN || crypto.randomBytes(32).toString('hex');

export function getLocalAuthToken(): string {
  return SERVER_AUTH_TOKEN;
}

export function isValidToken(candidateToken?: string | null): boolean {
  if (!candidateToken) return false;
  try {
    const candidateBuffer = Buffer.from(candidateToken);
    const secretBuffer = Buffer.from(SERVER_AUTH_TOKEN);
    if (candidateBuffer.length !== secretBuffer.length) return false;
    return crypto.timingSafeEqual(candidateBuffer, secretBuffer);
  } catch {
    return false;
  }
}

/**
 * Strict CORS and CSRF Protection Middleware.
 * Rejects any cross-origin state-altering request from third-party websites.
 */
export function corsAndCsrfProtection(req: Request, res: Response, next: NextFunction) {
  const origin = req.headers.origin;
  const host = req.headers.host;

  // Set standard security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');

  // Verify origin for mutating HTTP methods (POST, PUT, DELETE, PATCH)
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    if (origin) {
      const isAllowedOrigin =
        origin.includes('localhost') ||
        origin.includes('127.0.0.1') ||
        origin.includes('run.app') || // AI Studio container dev URL
        origin === 'null' || // Electron local file / desktop protocol
        (host && origin.includes(host));

      if (!isAllowedOrigin) {
        logger.warn({ origin, host, ip: req.ip, path: req.path }, '[CSRF-Shield] Requête cross-origin hostile bloquée');
        return res.status(403).json({
          success: false,
          error: 'Protection CSRF : Requête cross-origin non autorisée.',
          code: 'CSRF_BLOCKED',
        });
      }

      res.setHeader('Access-Control-Allow-Origin', origin);
    } else {
      // Same-origin or internal curl / desktop IPC
      res.setHeader('Access-Control-Allow-Origin', '*');
    }
  } else {
    // Read-only GET / OPTIONS
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-SpaceSec-Token');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  next();
}

/**
 * Authorization Middleware for Sensitive Operations.
 * Protects administrative and system-modifying endpoints against unauthorized local or remote callers.
 */
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (req.method === 'OPTIONS') return next();

  const authHeader = req.headers.authorization;
  const customHeader = req.headers['x-spacesec-token'];
  const queryToken = req.query.token as string | undefined;

  let providedToken: string | undefined;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    providedToken = authHeader.substring(7).trim();
  } else if (typeof customHeader === 'string') {
    providedToken = customHeader.trim();
  } else if (typeof queryToken === 'string') {
    providedToken = queryToken.trim();
  }

  // 1. Direct valid token provided
  if (providedToken && isValidToken(providedToken)) {
    return next();
  }

  // 2. Local token handshake endpoint itself is open to same-origin
  if (req.path === '/api/auth/token') {
    return next();
  }

  // 3. In Web development container (AI Studio), check same-origin header verification
  const isWebDev = process.env.IS_ELECTRON !== 'true';
  const origin = req.headers.origin;
  const host = req.headers.host;

  if (isWebDev) {
    const isSameOrigin =
      !origin ||
      (host && origin.includes(host)) ||
      origin.includes('localhost') ||
      origin.includes('127.0.0.1') ||
      origin.includes('run.app');

    if (isSameOrigin) {
      return next();
    }
  }

  logger.warn({ ip: req.ip, path: req.path, method: req.method }, '[Auth] Accès non autorisé rejeté');
  return res.status(401).json({
    success: false,
    error: 'Non autorisé : Jeton d\'authentification local SpaceSec manquant ou invalide.',
    code: 'UNAUTHORIZED',
  });
}

/**
 * Validates WebSocket connection handshake authentication.
 */
export function validateWebSocketConnection(urlStr?: string): boolean {
  if (!urlStr) return false;
  try {
    const url = new URL(urlStr, 'http://localhost');
    const token = url.searchParams.get('token');

    // 1. If valid token is supplied in query string
    if (token && isValidToken(token)) return true;

    // 2. In web dev container mode without electron, permit local connection
    if (process.env.IS_ELECTRON !== 'true') return true;

    return false;
  } catch {
    return false;
  }
}
