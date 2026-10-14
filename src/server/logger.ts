import pino from 'pino';
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

// Structured pino instance with fallback destination
export const logger = pino(
  {
    level: process.env.LOG_LEVEL || 'info',
    timestamp: pino.stdTimeFunctions.isoTime,
    formatters: {
      level: (label) => ({ level: label.toUpperCase() }),
    },
  },
  pino.multistream([
    { stream: process.stdout },
    { stream: logStream },
  ])
);

export function getLogFilePath(): string {
  return logFilePath;
}
