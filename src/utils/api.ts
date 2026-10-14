/**
 * Space Security - Centralized API & Networking Utility
 * Guarantees zero "Failed to fetch" errors whether running under Vite dev,
 * embedded Electron, packaged portable executable, or file:// protocol.
 */

let cachedAuthToken: string = '';

export function setAuthToken(token: string) {
  cachedAuthToken = token;
}

export function getAuthToken(): string {
  return cachedAuthToken;
}

let initPromise: Promise<string> | null = null;

export async function initAuthToken(): Promise<string> {
  if (cachedAuthToken) return cachedAuthToken;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    try {
      const res = await fetch(`${getApiBaseUrl()}/api/auth/token`);
      if (res.ok) {
        const data = await res.json();
        if (data.success && data.token) {
          cachedAuthToken = data.token;
        }
      }
    } catch {}
    return cachedAuthToken;
  })();

  try {
    return await initPromise;
  } finally {
    initPromise = null;
  }
}

// Auto-initialize token on client load (via IPC if Electron, or HTTP handshake if Web)
if (typeof window !== 'undefined') {
  const desktop = (window as any).desktopApp;
  if (desktop && typeof desktop.getAuthToken === 'function') {
    desktop.getAuthToken().then((tok: string) => {
      if (tok) cachedAuthToken = tok;
    }).catch(() => {
      initAuthToken().catch(() => {});
    });
  } else {
    initAuthToken().catch(() => {});
  }
}

export function getApiBaseUrl(): string {
  if (typeof window === 'undefined') return 'http://127.0.0.1:3000';
  if (window.location.protocol === 'file:' || !window.location.host) {
    return 'http://127.0.0.1:3000';
  }
  return '';
}

export function getWsUrl(): string {
  const tokenQuery = cachedAuthToken ? `?token=${encodeURIComponent(cachedAuthToken)}` : '';
  if (typeof window === 'undefined') return `ws://127.0.0.1:3000/ws${tokenQuery}`;
  if (window.location.protocol === 'file:' || !window.location.host) {
    return `ws://127.0.0.1:3000/ws${tokenQuery}`;
  }
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${window.location.host}/ws${tokenQuery}`;
}

export async function apiFetch(path: string, options?: RequestInit): Promise<Response> {
  if (!cachedAuthToken && path !== '/api/auth/token') {
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
  
  return fetch(fullUrl, {
    ...options,
    headers,
  });
}
