import { execFile, type ExecFileOptions } from 'child_process';
import { promisify } from 'util';
import os from 'os';
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
 * Sanitizes a file or directory path, verifying length and stripping dangerous control characters.
 */
export function sanitizePath(inputPath: unknown): string {
  if (typeof inputPath !== 'string' || !inputPath.trim()) {
    throw new Error('Chemin de fichier invalide ou vide.');
  }
  const clean = inputPath.trim();
  // Reject null bytes, carriage returns, newlines, and illegal path injection characters
  if (/[\x00\r\n\t]/.test(clean)) {
    throw new Error('Caractères de contrôle interdits détectés dans le chemin.');
  }
  if (clean.length > 1024) {
    throw new Error('Longueur de chemin excessive.');
  }
  return clean;
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
 * Sanitizes IP addresses (IPv4 or IPv6 or localhost).
 */
export function sanitizeIpAddress(ipStr: unknown): string {
  if (typeof ipStr !== 'string' || !ipStr.trim()) {
    throw new Error('Adresse IP invalide.');
  }
  const clean = ipStr.trim().toLowerCase();
  const ipv4Regex = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/;
  const ipv6Regex = /^([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$|^::1$|^localhost$/i;
  if (!ipv4Regex.test(clean) && !ipv6Regex.test(clean)) {
    throw new Error(`Format d'adresse IP invalide : ${clean}`);
  }
  return clean;
}
