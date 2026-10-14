import { Router } from 'express';
import os from 'os';
import fs from 'fs';
import { dbManager } from '../db.ts';
import { logger, getLogFilePath } from '../logger.ts';
import { getLocalAuthToken, requireAuth } from '../auth.ts';
import { checkHashReputation, checkIpReputation } from '../threatIntel.ts';
import { backgroundScheduler } from '../scheduler.ts';
import { settingsUpdateSchema, threatIntelCheckSchema, validateBody } from '../validators.ts';
import rateLimit from 'express-rate-limit';

export const intelRouter = Router();

const intelLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 45,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Quota de requêtes Threat Intel atteint pour cette minute.', code: 'RATE_LIMIT_EXCEEDED' },
});

// POST /api/intel/check-ip
intelRouter.post('/check-ip', intelLimiter, validateBody(threatIntelCheckSchema), async (req, res, next) => {
  try {
    const result = await checkIpReputation(req.body.target);
    res.json({ success: true, intel: result });
  } catch (err) {
    next(err);
  }
});

// POST /api/intel/check-hash
intelRouter.post('/check-hash', intelLimiter, validateBody(threatIntelCheckSchema), async (req, res, next) => {
  try {
    const result = await checkHashReputation(req.body.target);
    res.json({ success: true, intel: result });
  } catch (err) {
    next(err);
  }
});

// GET /api/intel/status
intelRouter.get('/status', (req, res) => {
  const settings = dbManager.getAllSettings();
  const vtConfigured = Boolean((process.env.VIRUSTOTAL_API_KEY && process.env.VIRUSTOTAL_API_KEY.trim().length > 10) || (settings.virusTotalApiKey && settings.virusTotalApiKey.trim().length > 10));
  const abuseConfigured = Boolean((process.env.ABUSEIPDB_API_KEY && process.env.ABUSEIPDB_API_KEY.trim().length > 10) || (settings.abuseIpDbApiKey && settings.abuseIpDbApiKey.trim().length > 10));
  
  res.json({
    success: true,
    virusTotal: {
      configured: vtConfigured,
      source: process.env.VIRUSTOTAL_API_KEY ? 'ENVIRONMENT_VARIABLE' : (settings.virusTotalApiKey ? 'PERSISTENT_SETTINGS' : 'NONE'),
      mode: vtConfigured ? 'LIVE_API_V3' : 'LOCAL_HEURISTICS_ENGINE',
      provider: 'VirusTotal Intelligence API v3',
    },
    abuseIpDb: {
      configured: abuseConfigured,
      source: process.env.ABUSEIPDB_API_KEY ? 'ENVIRONMENT_VARIABLE' : (settings.abuseIpDbApiKey ? 'PERSISTENT_SETTINGS' : 'NONE'),
      mode: abuseConfigured ? 'LIVE_API_V2' : 'LOCAL_HEURISTICS_ENGINE',
      provider: 'AbuseIPDB Threat Intelligence API v2',
    },
    threatCacheCount: dbManager.scalar('SELECT COUNT(*) FROM threat_intel_cache'),
  });
});

// GET /api/health
intelRouter.get('/health', (req, res) => {
  res.json({
    status: 'UP',
    service: 'Space Security CyberDefense Engine',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    uptimeSec: Math.round(process.uptime()),
    database: {
      engine: 'SQLite (sql.js / WebAssembly)',
      file: 'spacesec.sqlite',
      status: 'CONNECTED',
      ...dbManager.getStats(),
    },
    scheduler: backgroundScheduler.getStatus(),
    process: {
      pid: process.pid,
      platform: os.platform(),
      arch: os.arch(),
      nodeVersion: process.version,
      memoryUsage: process.memoryUsage(),
    },
  });
});

// GET /api/auth/token
intelRouter.get('/auth/token', (req, res) => {
  res.json({
    success: true,
    token: getLocalAuthToken(),
    mode: process.env.IS_ELECTRON === 'true' ? 'ELECTRON_LOCAL_IPC' : 'WEB_DEVELOPMENT',
  });
});

// GET /api/settings
intelRouter.get('/settings', (req, res) => {
  res.json({
    success: true,
    settings: dbManager.getAllSettings(),
  });
});

// POST /api/settings
intelRouter.post('/settings', requireAuth, validateBody(settingsUpdateSchema), (req, res) => {
  const updated = dbManager.updateSettings(req.body);
  if (req.body.autoScanInterval) {
    backgroundScheduler.configureInterval(req.body.autoScanInterval);
  }
  logger.info({ settings: req.body }, '[Settings] Préférences utilisateur enregistrées dans SQLite');
  res.json({
    success: true,
    message: 'Préférences utilisateur enregistrées avec succès.',
    settings: updated,
  });
});

// GET /api/updates/check
intelRouter.get('/updates/check', async (req, res) => {
  const currentVersion = '1.0.0';
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    const response = await fetch('https://api.github.com/repos/Christian667z/Space-Security/releases/latest', {
      headers: { 'User-Agent': 'SpaceSecurity-CyberDefense' },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (response.ok) {
      const data = await response.json();
      const latestTag = (data.tag_name || '').replace(/^v/, '');
      const updateAvailable = Boolean(latestTag && latestTag !== currentVersion);
      return res.json({
        success: true,
        currentVersion,
        latestVersion: latestTag || currentVersion,
        updateAvailable,
        releaseNotes: data.body || 'Mise à jour disponible sur le dépôt officiel.',
        downloadUrl: data.html_url || 'https://github.com/Christian667z/Space-Security/releases',
        publishedAt: data.published_at,
      });
    }
  } catch {}

  res.json({
    success: true,
    currentVersion,
    latestVersion: currentVersion,
    updateAvailable: false,
    releaseNotes: 'Version actuelle à jour. Aucune mise à jour critique en attente.',
    downloadUrl: 'https://github.com/Christian667z/Space-Security/releases',
  });
});

// GET /api/logs/download
intelRouter.get('/logs/download', (req, res) => {
  const logFile = getLogFilePath();
  if (fs.existsSync(logFile)) {
    res.download(logFile, 'spacesec-forensic-audit.log');
  } else {
    res.status(404).json({ success: false, error: 'Fichier journal introuvable.' });
  }
});
