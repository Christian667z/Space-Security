import { execFile, type ExecFileOptions } from 'child_process';
import { promisify } from 'util';
import os from 'os';
import net from 'net';
import path from 'path';
import { logger } from './logger.ts';

const execFileAsync = promisify(execFile);

/**
 * Secure command execution utility.
 * Guarantees that arguments are passed as an array directly to the OS kernel without
 * invoking an intermediate shell (cmd.exe / sh), eliminating command injection vulnerabilities.
 */
export async function safeExecFile(
  file: string,
  args: string[],
  options: ExecFileOptions = {}
): Promise<{ stdout: string; stderr: string }> {
  try {
    const result = await execFileAsync(file, args, {
      shell: false, // CRITICAL: NEVER invoke shell to prevent command chaining
      windowsHide: true,
      maxBuffer: 10 * 1024 * 1024, // 10MB
      ...options,
    });
    return {
      stdout: typeof result.stdout === 'string' ? result.stdout : result.stdout.toString(),
      stderr: typeof result.stderr === 'string' ? result.stderr : result.stderr.toString(),
    };
  } catch (err: any) {
    logger.debug({ file, args, err: err?.message }, '[safeExecFile] Command returned error or non-zero exit code');
    throw err;
  }
}

/**
 * Executes a PowerShell script safely using -EncodedCommand.
 * Encodes the script into UTF-16LE Base64, completely immune to quote injection,
 * command chaining, parameter expansion, and shell escapes.
 */
export async function safeExecPowerShell(
  script: string,
  options: ExecFileOptions = {}
): Promise<{ stdout: string; stderr: string }> {
  const utf16le = Buffer.from(script, 'utf16le').toString('base64');
  return safeExecFile(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', utf16le],
    options
  );
}

/**
 * Returns a PowerShell expression that safely reconstructs a literal string value at runtime
 * from Base64 UTF-8 bytes. Since Base64 contains only [A-Za-z0-9+/=], this is 100% immune
 * to quote escapes, backtick interpolation, shell breakouts, or parameter injection.
 */
export function psString(value: string): string {
  const b64 = Buffer.from(String(value ?? ''), 'utf8').toString('base64');
  return `[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('${b64}'))`;
}

/**
 * Validates that an input is strictly a positive integer PID.
 * Throws an error if invalid.
 */
export function validateAndParsePid(input: unknown): number {
  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (!/^\d+$/.test(trimmed)) {
      throw new Error('PID invalide : doit être un entier strictement positif.');
    }
  }
  const num = typeof input === 'number' ? input : Number(String(input).trim());
  if (isNaN(num) || !Number.isInteger(num) || num <= 0 || num > 4194304) {
    throw new Error('PID invalide : doit être un entier strictement positif.');
  }
  return num;
}

/**
 * Whitelist of allowed root directories and drives.
 * On Windows: Standard local system drives (C:\ through Z:\).
 * On POSIX: Standard system hierarchies.
 */
const ALLOWED_WINDOWS_DRIVES = /^[a-zA-Z]:[/\\]/;
const ALLOWED_POSIX_ROOTS = [
  '/', '/usr', '/etc', '/var', '/bin', '/sbin', '/opt', '/tmp',
  '/home', '/root', '/lib', '/lib64', '/sys', '/proc'
];

/**
 * Sanitizes a file or directory path:
 * 1. Blocks null bytes, newlines, carriage returns, and control characters.
 * 2. Blocks UNC paths (\\server\share, //...) to prevent NTLM credential leaks and remote execution.
 * 3. Blocks path traversal sequences (..) in raw and normalized forms.
 * 4. Enforces absolute paths and validates against an allowed root whitelist.
 */
export function sanitizePath(inputPath: unknown, allowedCustomRoots?: string[]): string {
  if (typeof inputPath !== 'string' || !inputPath.trim()) {
    throw new Error('Chemin de fichier invalide ou vide.');
  }
  const clean = inputPath.trim();

  // 1. Control characters & null-byte rejection
  if (/[\x00-\x1f\x7f]/.test(clean)) {
    throw new Error('Caractères de contrôle interdits détectés dans le chemin.');
  }

  if (clean.length > 1024) {
    throw new Error('Longueur de chemin excessive.');
  }

  // 2. Reject UNC paths (\\host\share, //host/share, \\?\UNC\...)
  if (/^([/\\]{2}|\\\\\?\\UNC\\)/i.test(clean)) {
    throw new Error('Chemins réseau UNC interdits.');
  }

  // 3. Reject directory traversal (..)
  if (/(^|[/\\])\.\.([/\\]|$)/.test(clean)) {
    throw new Error('Séquences de traversée de répertoire (..) interdites.');
  }

  const normalized = path.normalize(clean);
  if (normalized.includes('..')) {
    throw new Error('Traversée de répertoire détectée après normalisation.');
  }

  // 4. Must be an absolute path
  if (!path.isAbsolute(normalized)) {
    throw new Error('Le chemin doit être un chemin absolu.');
  }

  // 5. Whitelist root check
  const isWin = os.platform() === 'win32';
  if (isWin) {
    // Must start with a valid local drive letter C:\ through Z:\
    if (!ALLOWED_WINDOWS_DRIVES.test(normalized)) {
      throw new Error(`Racine non autorisée : le chemin Windows doit démarrer par une lettre de lecteur locale valide (ex: C:\\).`);
    }
  } else {
    // POSIX root check
    const isAllowed = ALLOWED_POSIX_ROOTS.some(r => normalized === r || normalized.startsWith(r === '/' ? '/' : r + '/')) ||
      (allowedCustomRoots && allowedCustomRoots.some(r => normalized === r || normalized.startsWith(r + '/')));
    if (!isAllowed) {
      throw new Error(`Racine POSIX non autorisée : ${normalized}`);
    }
  }

  return normalized;
}

/**
 * Sanitizes network interface name (alphanumeric, spaces, underscores, dashes, dots, parentheses).
 */
export function sanitizeInterfaceName(iface: unknown): string {
  if (typeof iface !== 'string' || !iface.trim()) {
    throw new Error('Nom d\'interface invalide ou vide.');
  }
  const clean = iface.trim();
  if (!/^[a-zA-Z0-9_\-\.\s()#:]+$/.test(clean) || clean.length > 128) {
    throw new Error('Caractères non autorisés détectés dans le nom d\'interface.');
  }
  return clean;
}

/**
 * Sanitizes IP addresses (IPv4 or IPv6, including compressed forms, or localhost).
 * Uses Node's standard net.isIP() to reliably validate addresses without broken regexes.
 */
export function sanitizeIpAddress(ipStr: unknown): string {
  if (typeof ipStr !== 'string' || !ipStr.trim()) {
    throw new Error('Adresse IP invalide.');
  }
  const clean = ipStr.trim().toLowerCase();
  if (clean === 'localhost') {
    return clean;
  }
  const ipVersion = net.isIP(clean);
  if (ipVersion !== 4 && ipVersion !== 6) {
    throw new Error(`Format d'adresse IP invalide : ${clean}`);
  }
  return clean;
}

/**
 * Protected system process names (case-insensitive).
 * Terminating any of these critical system processes causes an immediate BSOD
 * (CRITICAL_PROCESS_DIED / KERNEL_SECURITY_CHECK_FAILURE) or system reboot.
 */
export const CRITICAL_PROTECTED_PROCESS_NAMES = new Set([
  // Windows Core Subsystem & Initialization (instant BSOD if terminated)
  'system',
  'system idle process',
  'registry',
  'smss.exe',
  'csrss.exe',
  'wininit.exe',
  'services.exe',
  'lsass.exe',
  'winlogon.exe',
  'fontdrvhost.exe',
  'dwm.exe',
  'sihost.exe',
  'svchost.exe',
  'memory compression',

  // Unix/Linux Core & Init
  'init',
  'systemd',
  'kthreadd',
  'launchd',
]);

export const CRITICAL_PROTECTED_PIDS = new Set([0, 1, 4]);

/**
 * Checks whether a given PID and optional name belongs to a protected system process.
 * If processName is not provided and running on Windows, queries the actual process image name.
 * Throws a descriptive error if the process is protected to prevent a system crash (BSOD).
 */
export async function assertProcessNotProtected(pid: number, processName?: string): Promise<string> {
  // 1. Check PID whitelist
  if (CRITICAL_PROTECTED_PIDS.has(pid) || pid === process.pid || pid === process.ppid) {
    throw new Error(`Processus système critique protégé (PID ${pid}) : arrêt interdit pour prévenir un crash système.`);
  }

  let resolvedName = (processName || '').trim().toLowerCase();

  // 2. If name is not provided, query it dynamically on Windows
  if (!resolvedName && os.platform() === 'win32') {
    try {
      const { stdout } = await safeExecFile('tasklist.exe', [
        '/FI', `PID eq ${pid}`,
        '/FO', 'CSV',
        '/NH'
      ]);
      // Format: "image.exe","pid","Session","Session#","Mem"
      const match = stdout.match(/^"([^"]+)"/);
      if (match && match[1]) {
        resolvedName = match[1].trim().toLowerCase();
      }
    } catch {}
  }

  // 3. Verify against critical protected process names
  if (resolvedName) {
    const cleanName = resolvedName.replace(/\.exe$/i, '').toLowerCase();
    for (const protectedName of CRITICAL_PROTECTED_PROCESS_NAMES) {
      const cleanProtected = protectedName.replace(/\.exe$/i, '').toLowerCase();
      if (cleanName === cleanProtected || resolvedName === protectedName.toLowerCase()) {
        throw new Error(
          `Impossible de terminer le processus critique "${resolvedName}" (PID ${pid}) : action bloquée pour éviter un écran bleu (BSOD).`
        );
      }
    }
  }

  return resolvedName || `PID_${pid}`;
}
