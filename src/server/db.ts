import initSqlJs, { type Database, type SqlValue } from 'sql.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { logger } from './logger.ts';
import type { EdrEndpoint, EdrTelemetryEvent, EdrCommand } from '../types/cyberdefense.ts';

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
  status: 'ACTIVE' | 'QUARANTINED' | 'SCHEDULED_BOOT_DELETE' | 'NEUTRALIZED' | 'DISMISSED';
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
  activeThreats: number;
  neutralizedThreats: number;
  score: number;
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
        activeThreats INTEGER NOT NULL DEFAULT 0,
        neutralizedThreats INTEGER NOT NULL DEFAULT 0,
        score INTEGER NOT NULL DEFAULT 100,
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

      CREATE TABLE IF NOT EXISTS edr_endpoints (
        id TEXT PRIMARY KEY,
        hostname TEXT NOT NULL,
        ipAddress TEXT NOT NULL,
        publicIp TEXT,
        macAddress TEXT,
        osVersion TEXT NOT NULL,
        agentVersion TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'ONLINE',
        lastSeen TEXT NOT NULL,
        registeredAt TEXT NOT NULL,
        healthScore INTEGER NOT NULL DEFAULT 100,
        activeThreatsCount INTEGER NOT NULL DEFAULT 0,
        networkIsolated INTEGER NOT NULL DEFAULT 0,
        cpuUsagePercent INTEGER NOT NULL DEFAULT 0,
        ramUsagePercent INTEGER NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS edr_telemetry_events (
        id TEXT PRIMARY KEY,
        endpointId TEXT NOT NULL,
        hostname TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        summary TEXT NOT NULL,
        detailsJson TEXT,
        mitreTechnique TEXT
      );

      CREATE TABLE IF NOT EXISTS edr_commands (
        id TEXT PRIMARY KEY,
        endpointId TEXT NOT NULL,
        hostname TEXT NOT NULL,
        commandType TEXT NOT NULL,
        payloadJson TEXT,
        status TEXT NOT NULL DEFAULT 'PENDING',
        createdAt TEXT NOT NULL,
        executedAt TEXT,
        resultJson TEXT
      );
    `);

    // Dynamic schema migrations for existing databases
    try {
      this.db.run('ALTER TABLE scan_history ADD COLUMN activeThreats INTEGER NOT NULL DEFAULT 0');
    } catch {}
    try {
      this.db.run('ALTER TABLE scan_history ADD COLUMN neutralizedThreats INTEGER NOT NULL DEFAULT 0');
    } catch {}
    try {
      this.db.run('ALTER TABLE scan_history ADD COLUMN score INTEGER NOT NULL DEFAULT 100');
    } catch {}
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

    // Seed initial EDR Fleet endpoints if empty
    const endpointsCount = this.scalar('SELECT COUNT(*) FROM edr_endpoints');
    if (endpointsCount === 0) {
      const now = new Date().toISOString();
      const initialEndpoints = [
        {
          id: 'ep-win11-exec-03',
          hostname: 'EXEC-LAPTOP-03',
          ipAddress: '192.168.1.145',
          publicIp: '82.65.14.92',
          macAddress: '00:1A:2B:3C:4D:5E',
          osVersion: 'Windows 11 Enterprise 23H2 (Build 22631.3296)',
          agentVersion: 'v3.0.0-EDR-LIGHT',
          status: 'CRITICAL',
          lastSeen: now,
          registeredAt: new Date(Date.now() - 3600000 * 48).toISOString(),
          healthScore: 35,
          activeThreatsCount: 2,
          networkIsolated: 0,
          cpuUsagePercent: 78,
          ramUsagePercent: 82,
        },
        {
          id: 'ep-win11-finance-01',
          hostname: 'CORP-FINANCE-W11',
          ipAddress: '192.168.1.112',
          publicIp: '82.65.14.92',
          macAddress: '00:50:56:C0:00:08',
          osVersion: 'Windows 11 Pro 23H2 (Build 22631.3296)',
          agentVersion: 'v3.0.0-EDR-LIGHT',
          status: 'WARNING',
          lastSeen: now,
          registeredAt: new Date(Date.now() - 3600000 * 72).toISOString(),
          healthScore: 68,
          activeThreatsCount: 1,
          networkIsolated: 0,
          cpuUsagePercent: 32,
          ramUsagePercent: 54,
        },
        {
          id: 'ep-winsrv-dc01',
          hostname: 'PROD-SRV-AD01',
          ipAddress: '192.168.1.10',
          publicIp: '82.65.14.90',
          macAddress: '00:0C:29:9F:8B:12',
          osVersion: 'Windows Server 2022 Datacenter (Build 20348)',
          agentVersion: 'v3.0.0-EDR-LIGHT',
          status: 'ONLINE',
          lastSeen: now,
          registeredAt: new Date(Date.now() - 3600000 * 120).toISOString(),
          healthScore: 98,
          activeThreatsCount: 0,
          networkIsolated: 0,
          cpuUsagePercent: 14,
          ramUsagePercent: 38,
        },
        {
          id: 'ep-win10-rnd-04',
          hostname: 'RND-DEV-STATION',
          ipAddress: '192.168.1.88',
          publicIp: '82.65.14.92',
          macAddress: '00:23:24:D1:6C:33',
          osVersion: 'Windows 10 Pro 22H2 (Build 19045.4170)',
          agentVersion: 'v3.0.0-EDR-LIGHT',
          status: 'ONLINE',
          lastSeen: now,
          registeredAt: new Date(Date.now() - 3600000 * 24).toISOString(),
          healthScore: 92,
          activeThreatsCount: 0,
          networkIsolated: 0,
          cpuUsagePercent: 21,
          ramUsagePercent: 58,
        },
      ];

      for (const ep of initialEndpoints) {
        this.db.run(`
          INSERT INTO edr_endpoints (
            id, hostname, ipAddress, publicIp, macAddress, osVersion, agentVersion, status,
            lastSeen, registeredAt, healthScore, activeThreatsCount, networkIsolated,
            cpuUsagePercent, ramUsagePercent
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
          ep.id, ep.hostname, ep.ipAddress, ep.publicIp, ep.macAddress, ep.osVersion,
          ep.agentVersion, ep.status, ep.lastSeen, ep.registeredAt, ep.healthScore,
          ep.activeThreatsCount, ep.networkIsolated, ep.cpuUsagePercent, ep.ramUsagePercent
        ]);
      }

      // Initial EDR Telemetry events
      const initialEvents = [
        {
          id: 'evt-edr-seed-1',
          endpointId: 'ep-win11-exec-03',
          hostname: 'EXEC-LAPTOP-03',
          timestamp: new Date(Date.now() - 120000).toISOString(),
          category: 'PROCESS',
          severity: 'CRITICAL',
          summary: 'Binaire non signé détecté dans C:\\Windows\\Resources\\Themes\\explorer.exe (PID: 7412 masquerading)',
          detailsJson: JSON.stringify({ path: 'C:\\Windows\\Resources\\Themes\\explorer.exe', pid: 7412, hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }),
          mitreTechnique: 'T1036.005 - Masquerading',
        },
        {
          id: 'evt-edr-seed-2',
          endpointId: 'ep-win11-exec-03',
          hostname: 'EXEC-LAPTOP-03',
          timestamp: new Date(Date.now() - 95000).toISOString(),
          category: 'NETWORK',
          severity: 'CRITICAL',
          summary: 'Balise de communication C2 sortante vers 194.26.29.112:4444 depuis PID 7412',
          detailsJson: JSON.stringify({ remoteIp: '194.26.29.112', remotePort: 4444, localPort: 49822, proto: 'TCP' }),
          mitreTechnique: 'T1071 - Application Layer Protocol',
        },
        {
          id: 'evt-edr-seed-3',
          endpointId: 'ep-win11-finance-01',
          hostname: 'CORP-FINANCE-W11',
          timestamp: new Date(Date.now() - 300000).toISOString(),
          category: 'REGISTRY',
          severity: 'HIGH',
          summary: 'Altération non autorisée d\'une clé Run : HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WinHealth',
          detailsJson: JSON.stringify({ key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', value: 'WinHealth', target: 'powershell.exe -w hidden' }),
          mitreTechnique: 'T1547.001 - Registry Run Keys',
        },
        {
          id: 'evt-edr-seed-4',
          endpointId: 'ep-winsrv-dc01',
          hostname: 'PROD-SRV-AD01',
          timestamp: new Date(Date.now() - 600000).toISOString(),
          category: 'SERVICE',
          severity: 'INFO',
          summary: 'Audit périodique intégrité LSASS & modules Kerberos : Intégrité validée à 100%',
          detailsJson: JSON.stringify({ status: 'HEALTHY', modulesChecked: 84 }),
          mitreTechnique: 'T1003 - OS Credential Dumping Check',
        },
      ];

      for (const evt of initialEvents) {
        this.db.run(`
          INSERT INTO edr_telemetry_events (id, endpointId, hostname, timestamp, category, severity, summary, detailsJson, mitreTechnique)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
          evt.id, evt.endpointId, evt.hostname, evt.timestamp, evt.category,
          evt.severity, evt.summary, evt.detailsJson, evt.mitreTechnique
        ]);
      }
      logger.info('[Database] Seeded initial EDR Fleet endpoints and telemetry events');
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
  getScanHistory(limit = 50): ScanHistoryRecord[] {
    if (!this.db) return [];
    try {
      const res = this.db.exec(
        'SELECT id, scanType, totalScanned, threatsFound, activeThreats, neutralizedThreats, score, durationMs, scannedAt, summaryJson FROM scan_history ORDER BY scannedAt DESC LIMIT ?',
        [limit]
      );
      if (res.length === 0) return [];
      return res[0].values.map(row => {
        let summary: any = {};
        try { summary = JSON.parse(String(row[9])); } catch {}
        return {
          id: String(row[0]),
          scanType: String(row[1]),
          totalScanned: Number(row[2]),
          threatsFound: Number(row[3]),
          activeThreats: row[4] !== null && row[4] !== undefined ? Number(row[4]) : (summary.activeThreats ?? Number(row[3])),
          neutralizedThreats: row[5] !== null && row[5] !== undefined ? Number(row[5]) : (summary.neutralizedThreats ?? 0),
          score: row[6] !== null && row[6] !== undefined ? Number(row[6]) : (summary.score ?? 100),
          durationMs: Number(row[7]),
          scannedAt: String(row[8]),
          summaryJson: String(row[9]),
        };
      });
    } catch {
      const res = this.db.exec(
        'SELECT id, scanType, totalScanned, threatsFound, durationMs, scannedAt, summaryJson FROM scan_history ORDER BY scannedAt DESC LIMIT ?',
        [limit]
      );
      if (res.length === 0) return [];
      return res[0].values.map(row => {
        let summary: any = {};
        try { summary = JSON.parse(String(row[6])); } catch {}
        return {
          id: String(row[0]),
          scanType: String(row[1]),
          totalScanned: Number(row[2]),
          threatsFound: Number(row[3]),
          activeThreats: summary.activeThreats ?? Number(row[3]),
          neutralizedThreats: summary.neutralizedThreats ?? 0,
          score: summary.score ?? 100,
          durationMs: Number(row[4]),
          scannedAt: String(row[5]),
          summaryJson: String(row[6]),
        };
      });
    }
  }

  recordScan(scan: ScanHistoryRecord): void {
    if (!this.db) return;
    try {
      this.db.run(
        'INSERT INTO scan_history (id, scanType, totalScanned, threatsFound, activeThreats, neutralizedThreats, score, durationMs, scannedAt, summaryJson) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [
          scan.id,
          scan.scanType,
          scan.totalScanned,
          scan.threatsFound,
          scan.activeThreats ?? scan.threatsFound,
          scan.neutralizedThreats ?? 0,
          scan.score ?? 100,
          scan.durationMs,
          scan.scannedAt,
          scan.summaryJson,
        ]
      );
    } catch {
      this.db.run(
        'INSERT INTO scan_history (id, scanType, totalScanned, threatsFound, durationMs, scannedAt, summaryJson) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [scan.id, scan.scanType, scan.totalScanned, scan.threatsFound, scan.durationMs, scan.scannedAt, scan.summaryJson]
      );
    }
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

  // --- EDR FLEET & TELEMETRY API ---
  getEndpoints(): EdrEndpoint[] {
    if (!this.db) return [];
    const res = this.db.exec(`
      SELECT e.*, (SELECT COUNT(*) FROM edr_commands c WHERE c.endpointId = e.id AND c.status = 'PENDING') as pendingCount
      FROM edr_endpoints e ORDER BY e.lastSeen DESC
    `);
    if (res.length === 0) return [];
    return res[0].values.map((row: any[]) => ({
      id: String(row[0]),
      hostname: String(row[1]),
      ipAddress: String(row[2]),
      publicIp: row[3] ? String(row[3]) : undefined,
      macAddress: String(row[4] || ''),
      osVersion: String(row[5]),
      agentVersion: String(row[6]),
      status: row[7] as EdrEndpoint['status'],
      lastSeen: String(row[8]),
      registeredAt: String(row[9]),
      healthScore: Number(row[10]),
      activeThreatsCount: Number(row[11]),
      networkIsolated: Boolean(row[12]),
      cpuUsagePercent: Number(row[13]),
      ramUsagePercent: Number(row[14]),
      pendingCommandsCount: Number(row[15] || 0),
    }));
  }

  getEndpoint(id: string): EdrEndpoint | null {
    if (!this.db) return null;
    const res = this.db.exec(`
      SELECT e.*, (SELECT COUNT(*) FROM edr_commands c WHERE c.endpointId = e.id AND c.status = 'PENDING') as pendingCount
      FROM edr_endpoints e WHERE e.id = ?
    `, [id]);
    if (res.length === 0 || res[0].values.length === 0) return null;
    const row = res[0].values[0];
    return {
      id: String(row[0]),
      hostname: String(row[1]),
      ipAddress: String(row[2]),
      publicIp: row[3] ? String(row[3]) : undefined,
      macAddress: String(row[4] || ''),
      osVersion: String(row[5]),
      agentVersion: String(row[6]),
      status: row[7] as EdrEndpoint['status'],
      lastSeen: String(row[8]),
      registeredAt: String(row[9]),
      healthScore: Number(row[10]),
      activeThreatsCount: Number(row[11]),
      networkIsolated: Boolean(row[12]),
      cpuUsagePercent: Number(row[13]),
      ramUsagePercent: Number(row[14]),
      pendingCommandsCount: Number(row[15] || 0),
    };
  }

  saveEndpoint(ep: Partial<EdrEndpoint> & { id: string; hostname: string }): EdrEndpoint {
    if (!this.db) throw new Error('Database not initialized');
    const existing = this.getEndpoint(ep.id);
    const now = new Date().toISOString();
    const endpoint: EdrEndpoint = {
      id: ep.id,
      hostname: ep.hostname,
      ipAddress: ep.ipAddress || existing?.ipAddress || '127.0.0.1',
      publicIp: ep.publicIp || existing?.publicIp,
      macAddress: ep.macAddress || existing?.macAddress || '00:15:5D:01:22:9A',
      osVersion: ep.osVersion || existing?.osVersion || 'Windows 11 Pro 64-bit',
      agentVersion: ep.agentVersion || existing?.agentVersion || 'v3.0.0-EDR-LIGHT',
      status: ep.status || existing?.status || 'ONLINE',
      lastSeen: ep.lastSeen || now,
      registeredAt: existing?.registeredAt || ep.registeredAt || now,
      healthScore: ep.healthScore !== undefined ? ep.healthScore : (existing?.healthScore ?? 100),
      activeThreatsCount: ep.activeThreatsCount !== undefined ? ep.activeThreatsCount : (existing?.activeThreatsCount ?? 0),
      networkIsolated: ep.networkIsolated !== undefined ? ep.networkIsolated : (existing?.networkIsolated ?? false),
      cpuUsagePercent: ep.cpuUsagePercent !== undefined ? ep.cpuUsagePercent : (existing?.cpuUsagePercent ?? 0),
      ramUsagePercent: ep.ramUsagePercent !== undefined ? ep.ramUsagePercent : (existing?.ramUsagePercent ?? 0),
    };

    this.db.run(`
      INSERT OR REPLACE INTO edr_endpoints (
        id, hostname, ipAddress, publicIp, macAddress, osVersion, agentVersion, status,
        lastSeen, registeredAt, healthScore, activeThreatsCount, networkIsolated,
        cpuUsagePercent, ramUsagePercent
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      endpoint.id,
      endpoint.hostname,
      endpoint.ipAddress,
      endpoint.publicIp || null,
      endpoint.macAddress,
      endpoint.osVersion,
      endpoint.agentVersion,
      endpoint.status,
      endpoint.lastSeen,
      endpoint.registeredAt,
      endpoint.healthScore,
      endpoint.activeThreatsCount,
      endpoint.networkIsolated ? 1 : 0,
      endpoint.cpuUsagePercent,
      endpoint.ramUsagePercent,
    ]);

    this.scheduleSave();
    return endpoint;
  }

  deleteEndpoint(id: string): void {
    if (!this.db) return;
    this.db.run('DELETE FROM edr_endpoints WHERE id = ?', [id]);
    this.db.run('DELETE FROM edr_telemetry_events WHERE endpointId = ?', [id]);
    this.db.run('DELETE FROM edr_commands WHERE endpointId = ?', [id]);
    this.scheduleSave();
  }

  addEdrEvent(event: Omit<EdrTelemetryEvent, 'id' | 'timestamp'> & { id?: string; timestamp?: string }): EdrTelemetryEvent {
    if (!this.db) throw new Error('Database not initialized');
    const fullEvent: EdrTelemetryEvent = {
      id: event.id || `evt-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
      endpointId: event.endpointId,
      hostname: event.hostname,
      timestamp: event.timestamp || new Date().toISOString(),
      category: event.category,
      severity: event.severity,
      summary: event.summary,
      details: event.details,
      mitreTechnique: event.mitreTechnique,
    };

    this.db.run(`
      INSERT INTO edr_telemetry_events (id, endpointId, hostname, timestamp, category, severity, summary, detailsJson, mitreTechnique)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      fullEvent.id,
      fullEvent.endpointId,
      fullEvent.hostname,
      fullEvent.timestamp,
      fullEvent.category,
      fullEvent.severity,
      fullEvent.summary,
      fullEvent.details ? JSON.stringify(fullEvent.details) : null,
      fullEvent.mitreTechnique || null,
    ]);

    this.scheduleSave();
    return fullEvent;
  }

  getEdrEvents(endpointId?: string, limit = 50): EdrTelemetryEvent[] {
    if (!this.db) return [];
    const query = endpointId
      ? 'SELECT id, endpointId, hostname, timestamp, category, severity, summary, detailsJson, mitreTechnique FROM edr_telemetry_events WHERE endpointId = ? ORDER BY timestamp DESC LIMIT ?'
      : 'SELECT id, endpointId, hostname, timestamp, category, severity, summary, detailsJson, mitreTechnique FROM edr_telemetry_events ORDER BY timestamp DESC LIMIT ?';
    const params = endpointId ? [endpointId, limit] : [limit];
    const res = this.db.exec(query, params);
    if (res.length === 0) return [];
    return res[0].values.map((row: any[]) => ({
      id: String(row[0]),
      endpointId: String(row[1]),
      hostname: String(row[2]),
      timestamp: String(row[3]),
      category: row[4] as EdrTelemetryEvent['category'],
      severity: row[5] as EdrTelemetryEvent['severity'],
      summary: String(row[6]),
      details: row[7] ? JSON.parse(String(row[7])) : undefined,
      mitreTechnique: row[8] ? String(row[8]) : undefined,
    }));
  }

  createEdrCommand(cmd: Omit<EdrCommand, 'id' | 'status' | 'createdAt'> & { id?: string }): EdrCommand {
    if (!this.db) throw new Error('Database not initialized');
    const fullCmd: EdrCommand = {
      id: cmd.id || `cmd-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
      endpointId: cmd.endpointId,
      hostname: cmd.hostname,
      type: cmd.type,
      payload: cmd.payload,
      status: 'PENDING',
      createdAt: new Date().toISOString(),
    };

    this.db.run(`
      INSERT INTO edr_commands (id, endpointId, hostname, commandType, payloadJson, status, createdAt)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `, [
      fullCmd.id,
      fullCmd.endpointId,
      fullCmd.hostname,
      fullCmd.type,
      fullCmd.payload ? JSON.stringify(fullCmd.payload) : null,
      fullCmd.status,
      fullCmd.createdAt,
    ]);

    this.scheduleSave();
    return fullCmd;
  }

  getPendingCommands(endpointId: string): EdrCommand[] {
    if (!this.db) return [];
    const res = this.db.exec(
      "SELECT id, endpointId, hostname, commandType, payloadJson, status, createdAt FROM edr_commands WHERE endpointId = ? AND status = 'PENDING' ORDER BY createdAt ASC",
      [endpointId]
    );
    if (res.length === 0) return [];
    return res[0].values.map((row: any[]) => ({
      id: String(row[0]),
      endpointId: String(row[1]),
      hostname: String(row[2]),
      type: row[3] as EdrCommand['type'],
      payload: row[4] ? JSON.parse(String(row[4])) : undefined,
      status: 'PENDING' as const,
      createdAt: String(row[6]),
    }));
  }

  updateEdrCommand(id: string, status: 'EXECUTED' | 'FAILED', result?: string): void {
    if (!this.db) return;
    this.db.run(
      'UPDATE edr_commands SET status = ?, executedAt = ?, resultJson = ? WHERE id = ?',
      [status, new Date().toISOString(), result || null, id]
    );
    this.scheduleSave();
  }

  getEdrCommands(endpointId?: string, limit = 50): EdrCommand[] {
    if (!this.db) return [];
    const query = endpointId
      ? 'SELECT id, endpointId, hostname, commandType, payloadJson, status, createdAt, executedAt, resultJson FROM edr_commands WHERE endpointId = ? ORDER BY createdAt DESC LIMIT ?'
      : 'SELECT id, endpointId, hostname, commandType, payloadJson, status, createdAt, executedAt, resultJson FROM edr_commands ORDER BY createdAt DESC LIMIT ?';
    const params = endpointId ? [endpointId, limit] : [limit];
    const res = this.db.exec(query, params);
    if (res.length === 0) return [];
    return res[0].values.map((row: any[]) => ({
      id: String(row[0]),
      endpointId: String(row[1]),
      hostname: String(row[2]),
      type: row[3] as EdrCommand['type'],
      payload: row[4] ? JSON.parse(String(row[4])) : undefined,
      status: row[5] as EdrCommand['status'],
      createdAt: String(row[6]),
      executedAt: row[7] ? String(row[7]) : undefined,
      result: row[8] ? String(row[8]) : undefined,
    }));
  }

  getStats(): { threatsCount: number; quarantineCount: number; logsCount: number; scansCount: number; endpointsCount: number } {
    return {
      threatsCount: this.scalar('SELECT COUNT(*) FROM threats'),
      quarantineCount: this.scalar('SELECT COUNT(*) FROM quarantine'),
      logsCount: this.scalar('SELECT COUNT(*) FROM audit_logs'),
      scansCount: this.scalar('SELECT COUNT(*) FROM scan_history'),
      endpointsCount: this.scalar('SELECT COUNT(*) FROM edr_endpoints'),
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
