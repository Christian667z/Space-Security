import initSqlJs, { Database, SqlValue } from 'sql.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { logger } from './logger';

const currentDir = typeof __dirname !== 'undefined' ? __dirname : path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(currentDir, '..', '..');
const dataDir = path.join(rootDir, 'data');
const dbFilePath = path.join(dataDir, 'spacesec.sqlite');

export interface ThreatRecord {
  id: string;
  name: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  targetPath: string;
  mitreTechnique: string;
  lockedBySystem: boolean;
  trustedInstallerLocked: boolean;
  description: string;
  status: 'ACTIVE' | 'NEUTRALIZED' | 'DISMISSED';
  detectedAt?: string;
  resolvedAt?: string | null;
}

export interface QuarantineRecord {
  id: string;
  originalPath: string;
  quarantinePath: string;
  fileHash: string;
  fileName: string;
  sizeBytes: number;
  quarantinedAt: string;
  reason: string;
  status: 'ISOLATED' | 'RESTORED' | 'PURGED';
}

export interface AuditLogRecord {
  id: string;
  timestamp: string;
  level: string;
  tag?: string;
  text: string;
  operatorName?: string;
  createdAt?: string;
}

export interface ScanHistoryRecord {
  id: string;
  scanType: string;
  totalScanned: number;
  threatsFound: number;
  durationMs: number;
  scannedAt: string;
  summaryJson: string;
}

export interface UserSettings {
  alertThreshold: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  excludedFolders: string[];
  language: 'fr' | 'en';
  autoScanInterval: 'disabled' | '5m' | '15m' | '30m' | '1h';
  notifyOnCritical: boolean;
  soundAlerts: boolean;
  strictNetworkKillSwitch: boolean;
  autoQuarantineMalware: boolean;
  virusTotalApiKey?: string;
  abuseIpDbApiKey?: string;
  theme: 'dark-cyber' | 'stealth';
}

export const DEFAULT_SETTINGS: UserSettings = {
  alertThreshold: 'HIGH',
  excludedFolders: ['C:\\Windows\\System32\\', 'C:\\Program Files\\Windows Defender\\'],
  language: 'fr',
  autoScanInterval: '15m',
  notifyOnCritical: true,
  soundAlerts: false,
  strictNetworkKillSwitch: false,
  autoQuarantineMalware: false,
  theme: 'dark-cyber',
};

class SQLiteDatabaseManager {
  private db: Database | null = null;
  private initialized = false;
  private saveTimeout: NodeJS.Timeout | null = null;

  async init(): Promise<void> {
    if (this.initialized) return;

    if (!fs.existsSync(dataDir)) {
      try {
        fs.mkdirSync(dataDir, { recursive: true });
      } catch (err) {
        logger.error({ err }, '[Database] Failed to create data directory');
      }
    }

    const SQL = await initSqlJs();

    if (fs.existsSync(dbFilePath)) {
      try {
        const fileBuffer = fs.readFileSync(dbFilePath);
        this.db = new SQL.Database(fileBuffer);
        logger.info({ path: dbFilePath }, '[Database] Loaded existing SQLite database from disk');
      } catch (err) {
        logger.warn({ err }, '[Database] Failed to read existing SQLite file, creating fresh database');
        this.db = new SQL.Database();
      }
    } else {
      this.db = new SQL.Database();
      logger.info({ path: dbFilePath }, '[Database] Created new SQLite database in memory');
    }

    this.createSchemas();
    this.seedDefaults();
    this.saveToDiskSync();
    this.initialized = true;
  }

  private createSchemas(): void {
    if (!this.db) return;

    this.db.run(`
      CREATE TABLE IF NOT EXISTS threats (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        targetPath TEXT NOT NULL,
        mitreTechnique TEXT NOT NULL,
        lockedBySystem INTEGER NOT NULL DEFAULT 0,
        trustedInstallerLocked INTEGER NOT NULL DEFAULT 0,
        description TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        detectedAt TEXT NOT NULL,
        resolvedAt TEXT
      );

      CREATE TABLE IF NOT EXISTS quarantine (
        id TEXT PRIMARY KEY,
        originalPath TEXT NOT NULL,
        quarantinePath TEXT NOT NULL,
        fileHash TEXT NOT NULL,
        fileName TEXT NOT NULL,
        sizeBytes INTEGER NOT NULL,
        quarantinedAt TEXT NOT NULL,
        reason TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'ISOLATED'
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        level TEXT NOT NULL,
        tag TEXT,
        text TEXT NOT NULL,
        operatorName TEXT,
        createdAt TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS scan_history (
        id TEXT PRIMARY KEY,
        scanType TEXT NOT NULL,
        totalScanned INTEGER NOT NULL,
        threatsFound INTEGER NOT NULL,
        durationMs INTEGER NOT NULL,
        scannedAt TEXT NOT NULL,
        summaryJson TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS user_settings (
        key TEXT PRIMARY KEY,
        valueJson TEXT NOT NULL,
        updatedAt TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS blocked_entities (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        value TEXT NOT NULL,
        reason TEXT,
        blockedAt TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS threat_intel_cache (
        target TEXT PRIMARY KEY,
        targetType TEXT NOT NULL,
        score INTEGER NOT NULL,
        verdict TEXT NOT NULL,
        dataJson TEXT NOT NULL,
        cachedAt TEXT NOT NULL
      );
    `);
  }

  private seedDefaults(): void {
    if (!this.db) return;

    // Seed default settings if empty
    const settingsCount = this.scalar('SELECT COUNT(*) FROM user_settings');
    if (settingsCount === 0) {
      const now = new Date().toISOString();
      for (const [k, v] of Object.entries(DEFAULT_SETTINGS)) {
        this.db.run(
          'INSERT INTO user_settings (key, valueJson, updatedAt) VALUES (?, ?, ?)',
          [k, JSON.stringify(v), now]
        );
      }
      logger.info('[Database] Seeded default user settings');
    }

    // Seed initial audit log if empty
    const logsCount = this.scalar('SELECT COUNT(*) FROM audit_logs');
    if (logsCount === 0) {
      const now = new Date().toISOString();
      const initialLogs = [
        {
          id: 'log-boot-1',
          timestamp: new Date().toLocaleTimeString('fr-FR'),
          level: 'INFO',
          tag: 'INITIALISATION',
          text: 'Space Security CyberDefense Engine v3.0 démarré avec persistance SQLite active.',
          operatorName: 'System Kernel',
          createdAt: now,
        },
        {
          id: 'log-boot-2',
          timestamp: new Date().toLocaleTimeString('fr-FR'),
          level: 'OK',
          tag: 'STORAGE',
          text: `Base de données locale SQLite initialisée (${dbFilePath}).`,
          operatorName: 'System Kernel',
          createdAt: now,
        },
      ];

      for (const log of initialLogs) {
        this.db.run(
          'INSERT INTO audit_logs (id, timestamp, level, tag, text, operatorName, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)',
          [log.id, log.timestamp, log.level, log.tag, log.text, log.operatorName, log.createdAt]
        );
      }
    }
  }

  // Synchronous flush to disk
  saveToDiskSync(): void {
    if (!this.db) return;
    try {
      const data = this.db.export();
      fs.writeFileSync(dbFilePath, Buffer.from(data));
    } catch (err) {
      logger.error({ err }, '[Database] Failed to write SQLite file to disk');
    }
  }

  // Debounced async flush
  scheduleSave(): void {
    if (this.saveTimeout) return;
    this.saveTimeout = setTimeout(() => {
      this.saveTimeout = null;
      this.saveToDiskSync();
    }, 500);
  }

  private scalar(sql: string, params: SqlValue[] = []): any {
    if (!this.db) return 0;
    const res = this.db.exec(sql, params);
    if (res.length > 0 && res[0].values.length > 0) {
      return res[0].values[0][0];
    }
    return 0;
  }

  // --- THREATS API ---
  getThreats(): ThreatRecord[] {
    if (!this.db) return [];
    const res = this.db.exec('SELECT id, name, category, severity, targetPath, mitreTechnique, lockedBySystem, trustedInstallerLocked, description, status, detectedAt, resolvedAt FROM threats ORDER BY detectedAt DESC');
    if (res.length === 0) return [];
    return res[0].values.map(row => ({
      id: String(row[0]),
      name: String(row[1]),
      category: String(row[2]),
      severity: String(row[3]) as any,
      targetPath: String(row[4]),
      mitreTechnique: String(row[5]),
      lockedBySystem: Boolean(row[6]),
      trustedInstallerLocked: Boolean(row[7]),
      description: String(row[8]),
      status: String(row[9]) as any,
      detectedAt: String(row[10]),
      resolvedAt: row[11] ? String(row[11]) : null,
    }));
  }

  saveThreat(threat: ThreatRecord): void {
    if (!this.db) return;
    this.db.run(
      `INSERT OR REPLACE INTO threats 
       (id, name, category, severity, targetPath, mitreTechnique, lockedBySystem, trustedInstallerLocked, description, status, detectedAt, resolvedAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        threat.id,
        threat.name,
        threat.category,
        threat.severity,
        threat.targetPath,
        threat.mitreTechnique,
        threat.lockedBySystem ? 1 : 0,
        threat.trustedInstallerLocked ? 1 : 0,
        threat.description,
        threat.status,
        threat.detectedAt || new Date().toISOString(),
        threat.resolvedAt || null,
      ]
    );
    this.scheduleSave();
  }

  updateThreatStatus(threatId: string, status: ThreatRecord['status'], targetPath?: string): void {
    if (!this.db) return;
    const resolvedAt = status === 'NEUTRALIZED' ? new Date().toISOString() : null;
    if (targetPath) {
      this.db.run('UPDATE threats SET status = ?, resolvedAt = ? WHERE id = ? OR targetPath = ?', [status, resolvedAt, threatId, targetPath]);
    } else {
      this.db.run('UPDATE threats SET status = ?, resolvedAt = ? WHERE id = ?', [status, resolvedAt, threatId]);
    }
    this.scheduleSave();
  }

  bulkUpdateThreatStatus(threatIds: string[], status: ThreatRecord['status']): void {
    if (!this.db || threatIds.length === 0) return;
    const resolvedAt = status === 'NEUTRALIZED' ? new Date().toISOString() : null;
    for (const id of threatIds) {
      this.db.run('UPDATE threats SET status = ?, resolvedAt = ? WHERE id = ?', [status, resolvedAt, id]);
    }
    this.scheduleSave();
  }

  dismissThreats(threatIds: string[]): void {
    this.bulkUpdateThreatStatus(threatIds, 'DISMISSED');
  }

  resetThreats(): void {
    if (!this.db) return;
    this.db.run("UPDATE threats SET status = 'ACTIVE', resolvedAt = NULL");
    this.scheduleSave();
  }

  // --- QUARANTINE API ---
  getQuarantine(): QuarantineRecord[] {
    if (!this.db) return [];
    const res = this.db.exec('SELECT id, originalPath, quarantinePath, fileHash, fileName, sizeBytes, quarantinedAt, reason, status FROM quarantine ORDER BY quarantinedAt DESC');
    if (res.length === 0) return [];
    return res[0].values.map(row => ({
      id: String(row[0]),
      originalPath: String(row[1]),
      quarantinePath: String(row[2]),
      fileHash: String(row[3]),
      fileName: String(row[4]),
      sizeBytes: Number(row[5]),
      quarantinedAt: String(row[6]),
      reason: String(row[7]),
      status: String(row[8]) as any,
    }));
  }

  addQuarantineItem(item: QuarantineRecord): void {
    if (!this.db) return;
    this.db.run(
      `INSERT OR REPLACE INTO quarantine 
       (id, originalPath, quarantinePath, fileHash, fileName, sizeBytes, quarantinedAt, reason, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        item.id,
        item.originalPath,
        item.quarantinePath,
        item.fileHash,
        item.fileName,
        item.sizeBytes,
        item.quarantinedAt,
        item.reason,
        item.status,
      ]
    );
    this.scheduleSave();
  }

  updateQuarantineStatus(id: string, status: QuarantineRecord['status']): void {
    if (!this.db) return;
    this.db.run('UPDATE quarantine SET status = ? WHERE id = ?', [status, id]);
    this.scheduleSave();
  }

  // --- AUDIT LOGS API ---
  getAuditLogs(limit = 100): AuditLogRecord[] {
    if (!this.db) return [];
    const res = this.db.exec(
      'SELECT id, timestamp, level, tag, text, operatorName, createdAt FROM audit_logs ORDER BY createdAt DESC LIMIT ?',
      [limit]
    );
    if (res.length === 0) return [];
    return res[0].values.map(row => ({
      id: String(row[0]),
      timestamp: String(row[1]),
      level: String(row[2]),
      tag: row[3] ? String(row[3]) : '',
      text: String(row[4]),
      operatorName: row[5] ? String(row[5]) : undefined,
      createdAt: String(row[6]),
    })).reverse();
  }

  addAuditLog(log: AuditLogRecord): void {
    if (!this.db) return;
    const createdAt = log.createdAt || new Date().toISOString();
    this.db.run(
      'INSERT INTO audit_logs (id, timestamp, level, tag, text, operatorName, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [log.id, log.timestamp, log.level, log.tag || '', log.text, log.operatorName || 'System', createdAt]
    );
    // Keep max 500 audit logs to prevent database bloating
    this.db.run('DELETE FROM audit_logs WHERE id NOT IN (SELECT id FROM audit_logs ORDER BY createdAt DESC LIMIT 500)');
    this.scheduleSave();
  }

  clearAuditLogs(): void {
    if (!this.db) return;
    this.db.run('DELETE FROM audit_logs');
    this.scheduleSave();
  }

  // --- SCAN HISTORY API ---
  getScanHistory(limit = 20): ScanHistoryRecord[] {
    if (!this.db) return [];
    const res = this.db.exec(
      'SELECT id, scanType, totalScanned, threatsFound, durationMs, scannedAt, summaryJson FROM scan_history ORDER BY scannedAt DESC LIMIT ?',
      [limit]
    );
    if (res.length === 0) return [];
    return res[0].values.map(row => ({
      id: String(row[0]),
      scanType: String(row[1]),
      totalScanned: Number(row[2]),
      threatsFound: Number(row[3]),
      durationMs: Number(row[4]),
      scannedAt: String(row[5]),
      summaryJson: String(row[6]),
    }));
  }

  recordScan(scan: ScanHistoryRecord): void {
    if (!this.db) return;
    this.db.run(
      'INSERT INTO scan_history (id, scanType, totalScanned, threatsFound, durationMs, scannedAt, summaryJson) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [scan.id, scan.scanType, scan.totalScanned, scan.threatsFound, scan.durationMs, scan.scannedAt, scan.summaryJson]
    );
    this.scheduleSave();
  }

  // --- USER SETTINGS API ---
  getAllSettings(): UserSettings {
    if (!this.db) return DEFAULT_SETTINGS;
    const res = this.db.exec('SELECT key, valueJson FROM user_settings');
    const settings: any = { ...DEFAULT_SETTINGS };
    if (res.length > 0) {
      for (const row of res[0].values) {
        try {
          settings[String(row[0])] = JSON.parse(String(row[1]));
        } catch {}
      }
    }
    return settings as UserSettings;
  }

  updateSettings(partial: Partial<UserSettings>): UserSettings {
    if (!this.db) return DEFAULT_SETTINGS;
    const now = new Date().toISOString();
    for (const [k, v] of Object.entries(partial)) {
      this.db.run(
        'INSERT OR REPLACE INTO user_settings (key, valueJson, updatedAt) VALUES (?, ?, ?)',
        [k, JSON.stringify(v), now]
      );
    }
    this.scheduleSave();
    return this.getAllSettings();
  }

  // --- BLOCKED ENTITIES API ---
  getBlockedList(type: 'IP' | 'WIFI'): string[] {
    if (!this.db) return [];
    const res = this.db.exec('SELECT value FROM blocked_entities WHERE type = ?', [type]);
    if (res.length === 0) return [];
    return res[0].values.map(r => String(r[0]));
  }

  addBlockedEntity(type: 'IP' | 'WIFI', value: string, reason = ''): void {
    if (!this.db) return;
    const id = `${type.toLowerCase()}-${value.replace(/[^a-zA-Z0-9]/g, '_')}`;
    this.db.run(
      'INSERT OR REPLACE INTO blocked_entities (id, type, value, reason, blockedAt) VALUES (?, ?, ?, ?, ?)',
      [id, type, value, reason, new Date().toISOString()]
    );
    this.scheduleSave();
  }

  removeBlockedEntity(type: 'IP' | 'WIFI', value: string): void {
    if (!this.db) return;
    this.db.run('DELETE FROM blocked_entities WHERE type = ? AND value = ?', [type, value]);
    this.scheduleSave();
  }

  // --- THREAT INTEL CACHE ---
  getIntelCache(target: string): any | null {
    if (!this.db) return null;
    const res = this.db.exec('SELECT dataJson, cachedAt FROM threat_intel_cache WHERE target = ?', [target]);
    if (res.length === 0 || res[0].values.length === 0) return null;
    try {
      const data = JSON.parse(String(res[0].values[0][0]));
      const cachedAt = new Date(String(res[0].values[0][1])).getTime();
      // Cache valid for 24 hours
      if (Date.now() - cachedAt < 24 * 60 * 60 * 1000) {
        return data;
      }
    } catch {}
    return null;
  }

  setIntelCache(target: string, targetType: 'IP' | 'HASH', score: number, verdict: string, data: any): void {
    if (!this.db) return;
    this.db.run(
      'INSERT OR REPLACE INTO threat_intel_cache (target, targetType, score, verdict, dataJson, cachedAt) VALUES (?, ?, ?, ?, ?, ?)',
      [target, targetType, score, verdict, JSON.stringify(data), new Date().toISOString()]
    );
    this.scheduleSave();
  }

  getStats(): { threatsCount: number; quarantineCount: number; logsCount: number; scansCount: number } {
    return {
      threatsCount: this.scalar('SELECT COUNT(*) FROM threats'),
      quarantineCount: this.scalar('SELECT COUNT(*) FROM quarantine'),
      logsCount: this.scalar('SELECT COUNT(*) FROM audit_logs'),
      scansCount: this.scalar('SELECT COUNT(*) FROM scan_history'),
    };
  }

  close(): void {
    if (this.db) {
      this.saveToDiskSync();
      this.db.close();
      this.db = null;
      this.initialized = false;
      logger.info('[Database] SQLite database closed cleanly');
    }
  }
}

export const dbManager = new SQLiteDatabaseManager();
