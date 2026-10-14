import crypto from 'crypto';
import type { Request, Response, NextFunction } from 'express';
import type http from 'http';
import { logger } from './logger.ts';

// Cryptographically secure tokens generated on server startup
const SERVER_AUTH_TOKEN = process.env.SPACESEC_AUTH_TOKEN || crypto.randomBytes(32).toString('hex');
const EDR_AGENT_TOKEN = process.env.SPACESEC_EDR_TOKEN || crypto.randomBytes(32).toString('hex');

export function getLocalAuthToken(): string {
  return SERVER_AUTH_TOKEN;
}

export function getEdrAgentToken(): string {
  return EDR_AGENT_TOKEN;
}

export function isValidToken(candidateToken?: string | null): boolean {
  if (!candidateToken || typeof candidateToken !== 'string') return false;
  try {
    const candidateBuffer = Buffer.from(candidateToken);
    const secretBuffer = Buffer.from(SERVER_AUTH_TOKEN);
    if (candidateBuffer.length !== secretBuffer.length) return false;
    return crypto.timingSafeEqual(candidateBuffer, secretBuffer);
  } catch {
    return false;
  }
}

export function isValidEdrAgentToken(candidateToken?: string | null): boolean {
  if (!candidateToken || typeof candidateToken !== 'string') return false;
  try {
    const candidateBuffer = Buffer.from(candidateToken);
    const secretBuffer = Buffer.from(EDR_AGENT_TOKEN);
    if (candidateBuffer.length !== secretBuffer.length) return false;
    return crypto.timingSafeEqual(candidateBuffer, secretBuffer);
  } catch {
    return false;
  }
}

// =========================================================================
// HOST & ORIGIN WHITELISTING (DNS REBINDING & CSRF PROTECTION)
// =========================================================================

const DEFAULT_ALLOWED_HOSTNAMES = new Set([
  'localhost',
  '127.0.0.1',
  '::1',
  '[::1]',
]);

/**
 * Validates a hostname against the strict whitelist.
 * Protects against DNS Rebinding and Host Header Injection.
 */
export function isAllowedHost(hostnameOrHost?: string | null): boolean {
  if (!hostnameOrHost || typeof hostnameOrHost !== 'string') return false;

  let hostClean = hostnameOrHost.trim().toLowerCase();

  // Strip IPv6 bracket notation if present
  if (hostClean.startsWith('[') && hostClean.includes(']')) {
    const closingIdx = hostClean.indexOf(']');
    hostClean = hostClean.substring(1, closingIdx);
  } else if (hostClean.includes(':')) {
    // Strip port
    hostClean = hostClean.split(':')[0];
  }

  if (DEFAULT_ALLOWED_HOSTNAMES.has(hostClean)) {
    return true;
  }

  // Check additional allowed hosts configured in environment variable
  const envAllowed = process.env.SPACESEC_ALLOWED_HOSTS;
  if (envAllowed) {
    const customHosts = envAllowed.split(',').map((h) => h.trim().toLowerCase());
    if (customHosts.includes(hostClean)) {
      return true;
    }
  }

  // Allow Cloud Run dev URLs only if explicitly enabled in environment, with strict anchor
  if (process.env.ALLOW_CLOUD_RUN === 'true') {
    if (hostClean === 'run.app' || hostClean.endsWith('.run.app')) {
      return true;
    }
  }

  return false;
}

/**
 * Strict Host, CORS and CSRF Protection Middleware.
 * Rejects any DNS-rebinding requests and unauthorized cross-origin requests.
 */
export function corsAndCsrfProtection(req: Request, res: Response, next: NextFunction) {
  const origin = req.headers.origin;
  const host = req.headers.host;

  // Set standard security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // 1. DNS Rebinding Protection: Verify Host header
  if (!host || !isAllowedHost(host)) {
    logger.warn({ host, ip: req.ip, path: req.path }, '[DNS-Rebinding-Shield] Requête avec Host hostile rejetée');
    return res.status(400).json({
      success: false,
      error: 'Protection DNS Rebinding : En-tête Host non autorisé.',
      code: 'DNS_REBINDING_BLOCKED',
    });
  }

  // 2. CSRF & Origin Validation
  if (origin) {
    let isAllowedOrigin = false;

    // Electron local file protocol / desktop package
    if (origin === 'null' && (process.env.IS_ELECTRON === 'true' || process.env.NODE_ENV === 'development')) {
      isAllowedOrigin = true;
    } else {
      try {
        const parsedOrigin = new URL(origin);
        if (['http:', 'https:', 'vscode-webview:'].includes(parsedOrigin.protocol)) {
          isAllowedOrigin = isAllowedHost(parsedOrigin.hostname);
        }
      } catch {
        isAllowedOrigin = false;
      }
    }

    if (!isAllowedOrigin) {
      logger.warn({ origin, host, ip: req.ip, path: req.path }, '[CSRF-Shield] Requête cross-origin non autorisée bloquée');
      return res.status(403).json({
        success: false,
        error: 'Protection CSRF : Origine cross-origin non autorisée.',
        code: 'CSRF_BLOCKED',
      });
    }

    // Set strict CORS response headers for the allowed origin (never wildcard '*' when credentials enabled)
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, X-SpaceSec-Token, X-Session-Id, X-Operator-Role, X-Operator-Name, Sec-WebSocket-Protocol'
  );
  res.setHeader('Access-Control-Max-Age', '86400');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  next();
}

// =========================================================================
// SESSIONS & RBAC (ROLE-BASED ACCESS CONTROL)
// =========================================================================

export type OperatorRole = 'admin' | 'analyste' | 'lecture_seule';

export interface AuthenticatedOperator {
  id: string;
  name: string;
  role: OperatorRole;
  ip: string;
  verified: boolean;
  sessionId?: string;
}

export interface Session {
  id: string;
  operator: AuthenticatedOperator;
  createdAt: number;
  lastSeenAt: number;
  expiresAt: number;
}

const activeSessions = new Map<string, Session>();
const DEFAULT_SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

export function createSession(
  operatorInfo: { id?: string; name?: string; role?: OperatorRole },
  ip: string = '127.0.0.1',
  ttlMs: number = DEFAULT_SESSION_TTL_MS
): Session {
  const sessionId = 'sess_' + crypto.randomBytes(32).toString('hex');
  const role: OperatorRole = operatorInfo.role || 'lecture_seule';
  const opId = operatorInfo.id || `OP-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  const now = Date.now();

  const operator: AuthenticatedOperator = {
    id: opId,
    name: operatorInfo.name || (role === 'admin' ? 'Administrateur SOC' : role === 'analyste' ? 'Analyste SOC' : 'Observateur SOC'),
    role,
    ip,
    verified: role === 'admin' || role === 'analyste',
    sessionId,
  };

  const session: Session = {
    id: sessionId,
    operator,
    createdAt: now,
    lastSeenAt: now,
    expiresAt: now + ttlMs,
  };

  activeSessions.set(sessionId, session);
  return session;
}

export function getSession(sessionId?: string | null): Session | null {
  if (!sessionId) return null;
  const session = activeSessions.get(sessionId);
  if (!session) return null;

  if (Date.now() > session.expiresAt) {
    activeSessions.delete(sessionId);
    return null;
  }

  return session;
}

export function touchSession(sessionId: string): void {
  const session = activeSessions.get(sessionId);
  if (session) {
    session.lastSeenAt = Date.now();
  }
}

export function revokeSession(sessionId: string): boolean {
  return activeSessions.delete(sessionId);
}

export function listActiveSessions(): Session[] {
  const now = Date.now();
  const valid: Session[] = [];
  for (const [id, session] of activeSessions.entries()) {
    if (now > session.expiresAt) {
      activeSessions.delete(id);
    } else {
      valid.push(session);
    }
  }
  return valid;
}

// Clean up expired sessions periodically (every 15 minutes)
setInterval(() => {
  const now = Date.now();
  for (const [id, s] of activeSessions.entries()) {
    if (now > s.expiresAt) {
      activeSessions.delete(id);
    }
  }
}, 15 * 60 * 1000).unref();

// =========================================================================
// WEBSOCKET SINGLE-USE TICKETS
// =========================================================================

interface WebSocketTicketEntry {
  ticket: string;
  operator: AuthenticatedOperator;
  expiresAt: number;
}

const wsTickets = new Map<string, WebSocketTicketEntry>();
const WS_TICKET_TTL_MS = 60 * 1000; // 60 seconds

export function createWebSocketTicket(operator: AuthenticatedOperator, ttlSeconds = 60): string {
  const ticket = 'wst_' + crypto.randomBytes(24).toString('hex');
  wsTickets.set(ticket, {
    ticket,
    operator,
    expiresAt: Date.now() + ttlSeconds * 1000,
  });
  return ticket;
}

export function consumeWebSocketTicket(ticket?: string | null): AuthenticatedOperator | null {
  if (!ticket || typeof ticket !== 'string') return null;
  const entry = wsTickets.get(ticket);
  if (!entry) return null;

  // Single-use guarantee: delete immediately upon consumption
  wsTickets.delete(ticket);

  if (Date.now() > entry.expiresAt) {
    return null; // Expired ticket
  }

  return entry.operator;
}

// Periodically purge stale WebSocket tickets
setInterval(() => {
  const now = Date.now();
  for (const [t, entry] of wsTickets.entries()) {
    if (now > entry.expiresAt) {
      wsTickets.delete(t);
    }
  }
}, 30 * 1000).unref();

/**
 * Authoritative WebSocket authentication validator.
 * Accepts:
 *  1. One-time single-use ticket in URL query string (?ticket=wst_...)
 *  2. Headers (Authorization Bearer, X-SpaceSec-Token, X-Session-Id)
 *  3. Sec-WebSocket-Protocol (spacesec-ticket or spacesec-token)
 *  4. Packaged Electron loopback IPC mode
 * Returns the AuthenticatedOperator or null.
 */
export function validateWebSocketRequest(req: http.IncomingMessage): AuthenticatedOperator | null {
  // Validate Host header against DNS rebinding
  if (!isAllowedHost(req.headers.host)) {
    logger.warn({ host: req.headers.host }, '[WebSocket] Host non autorisé (protection DNS rebinding)');
    return null;
  }

  // 1. One-time ticket in query (?ticket=wst_...)
  if (req.url) {
    try {
      const parsedUrl = new URL(req.url, 'http://127.0.0.1');
      const ticket = parsedUrl.searchParams.get('ticket');
      if (ticket) {
        const op = consumeWebSocketTicket(ticket);
        if (op) {
          logger.info({ op: op.name, role: op.role }, '[WebSocket] Connexion authentifiée via ticket à usage unique');
          return op;
        }
      }
    } catch {}
  }

  // 2. Bearer Authorization or Custom Token / Session Headers
  const authHeader = req.headers['authorization'];
  const customHeader = req.headers['x-spacesec-token'] as string | undefined;
  const sessionHeader = req.headers['x-session-id'] as string | undefined;

  let candidateToken: string | undefined;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    candidateToken = authHeader.substring(7).trim();
  } else if (customHeader) {
    candidateToken = customHeader.trim();
  } else if (sessionHeader) {
    candidateToken = sessionHeader.trim();
  }

  // 3. Sec-WebSocket-Protocol subprotocols
  const subprotocols = req.headers['sec-websocket-protocol'];
  if (subprotocols) {
    const parts = subprotocols.split(',').map((p) => p.trim());
    const ticketIdx = parts.indexOf('spacesec-ticket');
    if (ticketIdx !== -1 && parts[ticketIdx + 1]) {
      const op = consumeWebSocketTicket(parts[ticketIdx + 1]);
      if (op) return op;
    }
    const tokenIdx = parts.indexOf('spacesec-token');
    if (tokenIdx !== -1 && parts[tokenIdx + 1]) {
      candidateToken = parts[tokenIdx + 1];
    }
  }

  if (candidateToken) {
    // Check active sessions
    const session = getSession(candidateToken);
    if (session) {
      touchSession(candidateToken);
      return session.operator;
    }

    // Check master server token
    if (isValidToken(candidateToken)) {
      return {
        id: 'OP-MASTER-ADMIN',
        name: 'Administrateur SOC (Master Key)',
        role: 'admin',
        ip: req.socket.remoteAddress || '127.0.0.1',
        verified: true,
      };
    }
  }

  // 4. In Desktop Electron packaged mode, allow strict loopback IPC
  if (process.env.IS_ELECTRON === 'true') {
    const clientIp = req.socket.remoteAddress || '';
    const isLoopback = clientIp === '127.0.0.1' || clientIp === '::1' || clientIp.includes('127.0.0.1');
    if (isLoopback) {
      return {
        id: 'OP-DESKTOP-LOCAL',
        name: 'Administrateur SOC (Bureau Electron)',
        role: 'admin',
        ip: '127.0.0.1',
        verified: true,
      };
    }
  }

  // 5. Legacy query token fallback with security warning
  if (req.url) {
    try {
      const parsedUrl = new URL(req.url, 'http://127.0.0.1');
      const legacyToken = parsedUrl.searchParams.get('token');
      if (legacyToken) {
        if (isValidToken(legacyToken)) {
          logger.warn('[WebSocket] Token passé dans l\'URL (déprécié). Utilisez un ticket à usage unique.');
          return {
            id: 'OP-LEGACY-TOKEN',
            name: 'Administrateur SOC (Token URL)',
            role: 'admin',
            ip: req.socket.remoteAddress || '127.0.0.1',
            verified: true,
          };
        }
        const sess = getSession(legacyToken);
        if (sess) {
          return sess.operator;
        }
      }
    } catch {}
  }

  return null;
}

/**
 * Backward compatibility helper for WebSocket connection validation.
 */
export function validateWebSocketConnection(urlStr?: string): boolean {
  if (!urlStr) return false;
  try {
    const url = new URL(urlStr, 'http://127.0.0.1');
    const ticket = url.searchParams.get('ticket');
    if (ticket && consumeWebSocketTicket(ticket)) {
      return true;
    }
    const token = url.searchParams.get('token');
    if (token && (isValidToken(token) || getSession(token) !== null)) {
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

// =========================================================================
// OPERATOR RESOLUTION & MIDDLEWARE
// =========================================================================

const RESERVED_OPERATOR_NAMES = [
  'system kernel',
  'trustedinstaller',
  'nt authority',
  'system',
  'system-monitor',
  'soc-core',
  'root',
  'administrator',
  'administrateur',
];

export function resolveAuthenticatedOperator(req: Request): AuthenticatedOperator {
  if ((req as any).authenticatedOperator) {
    return (req as any).authenticatedOperator;
  }

  const rawIp = (req.ip || (req.socket && req.socket.remoteAddress) || '127.0.0.1').toString();
  const cleanIp = rawIp.replace(/^.*:/, '') || '127.0.0.1';

  const clientSuggested =
    (typeof req.headers['x-operator-name'] === 'string' && req.headers['x-operator-name'].trim()) ||
    (req.body && req.body.operator && typeof req.body.operator.name === 'string' && req.body.operator.name.trim()) ||
    (req.body && typeof req.body.operatorName === 'string' && req.body.operatorName.trim()) ||
    '';

  let sanitizedHandle = clientSuggested.replace(/[^\w\s\-#.]/gi, '').trim().slice(0, 24);
  if (sanitizedHandle && RESERVED_OPERATOR_NAMES.some((r) => sanitizedHandle.toLowerCase().includes(r))) {
    sanitizedHandle = '';
  }

  // Unauthenticated requests default strictly to read-only observer
  return {
    id: `OP-OBS-${cleanIp.replace(/\./g, '')}`,
    name: sanitizedHandle ? `${sanitizedHandle} [Observateur]` : `Observateur [${cleanIp}]`,
    role: 'lecture_seule',
    ip: cleanIp,
    verified: false,
  };
}

/**
 * Authorization Middleware for Sensitive Endpoints.
 * Strictly verifies Session Tokens or the Master SpaceSec Server Token.
 * Rejects unauthenticated requests with HTTP 401 Unauthorized.
 */
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (req.method === 'OPTIONS') return next();

  const authHeader = req.headers.authorization;
  const customHeader = req.headers['x-spacesec-token'];
  const sessionHeader = req.headers['x-session-id'];
  const queryToken = req.query.token as string | undefined;

  let providedToken: string | undefined;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    providedToken = authHeader.substring(7).trim();
  } else if (typeof customHeader === 'string') {
    providedToken = customHeader.trim();
  } else if (typeof sessionHeader === 'string') {
    providedToken = sessionHeader.trim();
  } else if (typeof queryToken === 'string') {
    providedToken = queryToken.trim();
  }

  // 1. Session Token Validation
  if (providedToken) {
    const session = getSession(providedToken);
    if (session) {
      touchSession(providedToken);
      (req as any).authenticatedOperator = session.operator;
      (req as any).session = session;
      return next();
    }

    // 2. Master Server Auth Token
    if (isValidToken(providedToken)) {
      (req as any).authenticatedOperator = {
        id: 'OP-MASTER-ADMIN',
        name: 'Administrateur SOC (Master)',
        role: 'admin' as OperatorRole,
        ip: req.ip || '127.0.0.1',
        verified: true,
      };
      return next();
    }
  }

  // 3. Desktop Electron packaged mode loopback IPC
  const isElectron = process.env.IS_ELECTRON === 'true';
  const clientIp = req.ip || req.socket.remoteAddress || '';
  const isLoopback = clientIp === '127.0.0.1' || clientIp === '::1' || clientIp.includes('127.0.0.1');

  if (isElectron && isLoopback) {
    (req as any).authenticatedOperator = {
      id: 'OP-DESKTOP-LOCAL',
      name: 'Administrateur SOC (Bureau Electron)',
      role: 'admin' as OperatorRole,
      ip: '127.0.0.1',
      verified: true,
    };
    return next();
  }

  logger.warn(
    { ip: clientIp, path: req.path, method: req.method },
    '[Auth] Accès non autorisé rejeté (jeton de session manquant ou invalide)'
  );
  return res.status(401).json({
    success: false,
    error: 'Non autorisé : Jeton d\'authentification ou de session SpaceSec manquant ou invalide.',
    code: 'UNAUTHORIZED',
  });
}

/**
 * Role-Based Access Control (RBAC) Middleware.
 * Enforces permissions: 'admin', 'analyste', or 'lecture_seule'.
 */
export function requireRole(...allowedRoles: OperatorRole[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const operator = (req as any).authenticatedOperator as AuthenticatedOperator | undefined;
    if (!operator) {
      return res.status(401).json({
        success: false,
        error: 'Non autorisé : Authentification requise.',
        code: 'UNAUTHORIZED',
      });
    }

    if (!allowedRoles.includes(operator.role)) {
      logger.warn(
        { operator: operator.name, role: operator.role, required: allowedRoles, path: req.path, method: req.method },
        '[RBAC] Accès refusé - permissions insuffisantes pour ce rôle'
      );
      return res.status(403).json({
        success: false,
        error: `Accès refusé : privilèges insuffisants. Rôle requis : ${allowedRoles.join(' ou ')} (rôle actuel : ${operator.role}).`,
        code: 'FORBIDDEN_ROLE',
      });
    }

    next();
  };
}

/**
 * Middleware for EDR Ingestion Endpoints.
 * Accepts either:
 *  - Scoped EDR Agent Token
 *  - Master Server Auth Token
 *  - Active Admin/Analyste Session
 */
export function requireEdrAuth(req: Request, res: Response, next: NextFunction) {
  if (req.method === 'OPTIONS') return next();

  const authHeader = req.headers.authorization;
  const customHeader = req.headers['x-spacesec-token'];
  let token: string | undefined;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7).trim();
  } else if (typeof customHeader === 'string') {
    token = customHeader.trim();
  }

  if (token) {
    if (isValidEdrAgentToken(token)) {
      (req as any).authenticatedOperator = {
        id: 'EDR-AGENT',
        name: 'Agent EDR Télémétrie',
        role: 'analyste' as OperatorRole,
        ip: req.ip || '127.0.0.1',
        verified: true,
      };
      return next();
    }

    if (isValidToken(token)) {
      (req as any).authenticatedOperator = {
        id: 'OP-MASTER-ADMIN',
        name: 'Administrateur SOC (Master)',
        role: 'admin' as OperatorRole,
        ip: req.ip || '127.0.0.1',
        verified: true,
      };
      return next();
    }

    const session = getSession(token);
    if (session && (session.operator.role === 'admin' || session.operator.role === 'analyste')) {
      (req as any).authenticatedOperator = session.operator;
      return next();
    }
  }

  // In Electron desktop mode on loopback
  if (process.env.IS_ELECTRON === 'true') {
    const clientIp = req.ip || req.socket.remoteAddress || '';
    if (clientIp === '127.0.0.1' || clientIp === '::1' || clientIp.includes('127.0.0.1')) {
      return next();
    }
  }

  logger.warn({ ip: req.ip, path: req.path }, '[EDR Gateway] Accès télémétrie non autorisé rejeté');
  return res.status(401).json({
    success: false,
    error: 'Non autorisé : Jeton d\'authentification d\'agent EDR invalide ou manquant.',
    code: 'UNAUTHORIZED_EDR_AGENT',
  });
}
