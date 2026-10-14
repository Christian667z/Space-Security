/**
 * Space Security - Centralized API & Networking Utility
 * Guarantees zero "Failed to fetch" errors whether running under Vite dev,
 * embedded Electron, packaged portable executable, or file:// protocol.
 * Implements Session Management, RBAC headers, and One-Time WebSocket Tickets.
 */

let cachedAuthToken: string = '';
let cachedRole: string = 'lecture_seule';

const STORAGE_KEY = 'spacesec_session_token';

// Retrieve cached session token from localStorage if in browser
if (typeof window !== 'undefined' && window.localStorage) {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      cachedAuthToken = saved;
    }
  } catch {}
}

export function setAuthToken(token: string, role?: string) {
  cachedAuthToken = token;
  if (role) cachedRole = role;
  if (typeof window !== 'undefined' && window.localStorage) {
    try {
      if (token) {
        localStorage.setItem(STORAGE_KEY, token);
      } else {
        localStorage.removeItem(STORAGE_KEY);
      }
    } catch {}
  }
}

export function getAuthToken(): string {
  return cachedAuthToken;
}

export function getOperatorRole(): string {
  return cachedRole;
}

let initPromise: Promise<string> | null = null;

export async function initAuthToken(): Promise<string> {
  if (cachedAuthToken) return cachedAuthToken;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    try {
      // 1. Electron IPC Check
      if (typeof window !== 'undefined') {
        const desktop = (window as any).desktopApp;
        if (desktop && typeof desktop.getAuthToken === 'function') {
          const tok = await desktop.getAuthToken();
          if (tok) {
            setAuthToken(tok, 'admin');
            return tok;
          }
        }
      }

      // 2. Session bootstrap handshake via POST /api/auth/session
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (cachedAuthToken) {
        headers['Authorization'] = `Bearer ${cachedAuthToken}`;
        headers['X-SpaceSec-Token'] = cachedAuthToken;
      }

      const res = await fetch(`${getApiBaseUrl()}/api/auth/session`, {
        method: 'POST',
        headers,
        credentials: 'include',
      });

      if (res.ok) {
        const data = await res.json();
        if (data.success && (data.token || (data.session && data.session.id))) {
          const token = data.token || data.session.id;
          const role = data.session?.operator?.role || 'lecture_seule';
          setAuthToken(token, role);
        }
      }
    } catch (err) {
      console.warn('[API] Erreur d\'initialisation du jeton de session:', err);
    }
    return cachedAuthToken;
  })();

  try {
    return await initPromise;
  } finally {
    initPromise = null;
  }
}

// Auto-initialize session on client load
if (typeof window !== 'undefined') {
  initAuthToken().catch(() => {});
}

export function getApiBaseUrl(): string {
  if (typeof window === 'undefined') return 'http://127.0.0.1:3000';
  if (window.location.protocol === 'file:' || !window.location.host) {
    return 'http://127.0.0.1:3000';
  }
  return '';
}

/**
 * Requests a secure single-use ticket for WebSocket authentication.
 * Prevents exposing long-lived secret tokens in logged WebSocket URLs.
 */
export async function createWsTicket(): Promise<string | null> {
  try {
    if (!cachedAuthToken) {
      await initAuthToken();
    }
    const res = await apiFetch('/api/auth/ws-ticket', { method: 'POST' });
    if (res.ok) {
      const data = await res.json();
      if (data.success && data.ticket) {
        return data.ticket;
      }
    }
  } catch (err) {
    console.warn('[API] Impossible de générer un ticket WebSocket unique:', err);
  }
  return null;
}

/**
 * Returns a secure WebSocket URL with a single-use ticket.
 */
export async function getWsUrl(): Promise<string> {
  const ticket = await createWsTicket();
  const ticketQuery = ticket ? `?ticket=${encodeURIComponent(ticket)}` : '';

  if (typeof window === 'undefined') {
    return `ws://127.0.0.1:3000/ws${ticketQuery}`;
  }
  if (window.location.protocol === 'file:' || !window.location.host) {
    return `ws://127.0.0.1:3000/ws${ticketQuery}`;
  }
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${window.location.host}/ws${ticketQuery}`;
}

export async function apiFetch(path: string, options?: RequestInit): Promise<Response> {
  if (!cachedAuthToken && path !== '/api/auth/session' && path !== '/api/auth/login') {
    await initAuthToken();
  }

  const baseUrl = getApiBaseUrl();
  const cleanPath = path.startsWith('/') ? path : `/${path}`;
  const fullUrl = `${baseUrl}${cleanPath}`;

  const headers = new Headers(options?.headers || {});
  if (cachedAuthToken && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${cachedAuthToken}`);
  }
  if (cachedAuthToken && !headers.has('X-SpaceSec-Token')) {
    headers.set('X-SpaceSec-Token', cachedAuthToken);
  }
  if (cachedAuthToken && !headers.has('X-Session-Id')) {
    headers.set('X-Session-Id', cachedAuthToken);
  }

  return fetch(fullUrl, {
    ...options,
    headers,
    credentials: 'include',
  });
}

/**
 * Login / Elevate permissions using the master token or administrator key.
 */
export async function login(token?: string, name?: string, role?: string): Promise<boolean> {
  try {
    const res = await fetch(`${getApiBaseUrl()}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, name, role }),
      credentials: 'include',
    });
    if (res.ok) {
      const data = await res.json();
      if (data.success && data.token) {
        setAuthToken(data.token, data.session?.operator?.role);
        return true;
      }
    }
  } catch {}
  return false;
}

/**
 * Logout and invalidate current session.
 */
export async function logout(): Promise<void> {
  try {
    await apiFetch('/api/auth/logout', { method: 'POST' });
  } catch {}
  setAuthToken('', 'lecture_seule');
}
