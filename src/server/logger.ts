import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const currentDir = typeof __dirname !== 'undefined' ? __dirname : path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(currentDir, '..', '..');
const logsDir = path.join(rootDir, 'logs');

if (!fs.existsSync(logsDir)) {
  try {
    fs.mkdirSync(logsDir, { recursive: true });
  } catch (err) {
    console.error('[Logger] Failed to create logs directory:', err);
  }
}

const logFilePath = path.join(logsDir, 'spacesec.log');
const logStream = fs.createWriteStream(logFilePath, { flags: 'a' });

function writeLog(level: string, objOrMsg: any, msg?: string) {
  const time = new Date().toISOString();
  let details: Record<string, any> = {};
  let message = '';
  if (typeof objOrMsg === 'string') {
    message = objOrMsg;
  } else {
    details = objOrMsg || {};
    message = msg || '';
  }
  const entry = { time, level: level.toUpperCase(), msg: message, ...details };
  const str = JSON.stringify(entry);
  try {
    logStream.write(str + '\n');
  } catch {}

  const hasDetails = Object.keys(details).length > 0;
  if (level === 'error' || level === 'fatal') {
    console.error(`[${time}] [${level.toUpperCase()}] ${message}`, hasDetails ? details : '');
  } else if (level === 'warn') {
    console.warn(`[${time}] [${level.toUpperCase()}] ${message}`, hasDetails ? details : '');
  } else {
    console.log(`[${time}] [${level.toUpperCase()}] ${message}`, hasDetails ? details : '');
  }
}

export const logger = {
  info: (objOrMsg: any, msg?: string) => writeLog('info', objOrMsg, msg),
  warn: (objOrMsg: any, msg?: string) => writeLog('warn', objOrMsg, msg),
  error: (objOrMsg: any, msg?: string) => writeLog('error', objOrMsg, msg),
  debug: (objOrMsg: any, msg?: string) => writeLog('debug', objOrMsg, msg),
  fatal: (objOrMsg: any, msg?: string) => writeLog('fatal', objOrMsg, msg),
};

export function getLogFilePath(): string {
  return logFilePath;
}
