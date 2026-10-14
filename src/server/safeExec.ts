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
 * Validates that an input is strictly a positive integer PID.
 * Throws an error if invalid.
 */
export function validateAndParsePid(input: unknown): number {
  const num = typeof input === 'number' ? input : parseInt(String(input).trim(), 10);
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
