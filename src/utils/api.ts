/**
 * Space Security - Centralized API & Networking Utility
 * Guarantees zero "Failed to fetch" errors whether running under Vite dev,
 * embedded Electron, packaged portable executable, or file:// protocol.
 */

export function getApiBaseUrl(): string {
  if (typeof window === 'undefined') return 'http://127.0.0.1:3000';
  if (window.location.protocol === 'file:' || !window.location.host) {
    return 'http://127.0.0.1:3000';
  }
  return '';
}

export function getWsUrl(): string {
  if (typeof window === 'undefined') return 'ws://127.0.0.1:3000/ws';
  if (window.location.protocol === 'file:' || !window.location.host) {
    return 'ws://127.0.0.1:3000/ws';
  }
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${window.location.host}/ws`;
}

export async function apiFetch(path: string, options?: RequestInit): Promise<Response> {
  const baseUrl = getApiBaseUrl();
  const cleanPath = path.startsWith('/') ? path : `/${path}`;
  const fullUrl = `${baseUrl}${cleanPath}`;
  return fetch(fullUrl, options);
}
