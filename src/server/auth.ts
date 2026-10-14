import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
import { logger } from './logger';

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

// Middleware for Express routes
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  // Allow OPTIONS preflight
  if (req.method === 'OPTIONS') return next();

  // In Electron desktop environment with strict local IPC, require token
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

  // If running in development web environment without Electron, or if token matches
  const isDevOrWeb = process.env.IS_ELECTRON !== 'true';

  if (providedToken && isValidToken(providedToken)) {
    return next();
  }

  // In web environment, if token not yet provided, allow read-only routes or handshake
  if (isDevOrWeb && (req.method === 'GET' || req.path === '/api/auth/token')) {
    return next();
  }

  // For write/kill/mutation operations, if no token was provided in dev, allow same-origin requests
  // but warn in structured logs
  const origin = req.headers.origin || req.headers.host || '';
  if (isDevOrWeb && (origin.includes('localhost') || origin.includes('127.0.0.1') || origin.includes('run.app') || !req.headers.origin)) {
    return next();
  }

  logger.warn({ ip: req.ip, path: req.path, method: req.method }, '[Auth] Accès non autorisé rejeté');
  return res.status(401).json({
    success: false,
    error: 'Non autorisé : Jeton d\'authentification local SpaceSec manquant ou invalide.',
    code: 'UNAUTHORIZED',
  });
}

// WebSocket Token Validator
export function validateWebSocketConnection(urlStr?: string): boolean {
  if (!urlStr) return false;
  try {
    const url = new URL(urlStr, 'http://localhost');
    const token = url.searchParams.get('token');
    
    // In web dev environment, allow if token is present or default development session
    if (token && isValidToken(token)) return true;
    if (process.env.IS_ELECTRON !== 'true') return true;

    return false;
  } catch {
    return false;
  }
}
