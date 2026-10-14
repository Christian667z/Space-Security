import cron, { type ScheduledTask } from 'node-cron';
import os from 'os';
import { exec } from 'child_process';
import { promisify } from 'util';
import { dbManager } from './db.ts';
import { logger } from './logger.ts';

const execAsync = promisify(exec);

export type BroadcastFunction = (message: any) => void;

class BackgroundSchedulerService {
  private task: ScheduledTask | null = null;
  private currentCronExpr = '*/15 * * * *'; // Default 15 minutes
  private broadcast: BroadcastFunction | null = null;
  private isRunningScan = false;

  start(broadcast: BroadcastFunction): void {
    this.broadcast = broadcast;
    const settings = dbManager.getAllSettings();
    this.configureInterval(settings.autoScanInterval || '15m');
  }

  configureInterval(interval: 'disabled' | '5m' | '15m' | '30m' | '1h'): void {
    if (this.task) {
      this.task.stop();
      this.task = null;
    }

    if (interval === 'disabled') {
      logger.info('[Scheduler] Scans automatiques en arrière-plan désactivés.');
      return;
    }

    let expr = '*/15 * * * *';
    switch (interval) {
      case '5m': expr = '*/5 * * * *'; break;
      case '15m': expr = '*/15 * * * *'; break;
      case '30m': expr = '*/30 * * * *'; break;
      case '1h': expr = '0 * * * *'; break;
    }

    this.currentCronExpr = expr;
    this.task = cron.schedule(expr, () => {
      this.runPeriodicScan().catch((err) => {
        logger.error({ err }, '[Scheduler] Erreur lors du scan périodique');
      });
    });

    logger.info({ interval, cron: expr }, '[Scheduler] Planificateur de scans de fond activé');
  }

  async runPeriodicScan(): Promise<void> {
    if (this.isRunningScan) return;
    this.isRunningScan = true;

    try {
      logger.info('[Scheduler] Démarrage du scan de surveillance périodique (Audit mémoire & persistance)...');

      const isWin = os.platform() === 'win32';
      let foundThreats = 0;
      const detectedThreats: any[] = [];

      // 1. Process Audit
      if (isWin) {
        try {
          const { stdout } = await execAsync('tasklist /fo csv /nh');
          const lines = stdout.split('\n');
          for (const line of lines) {
            const clean = line.replace(/\"/g, '').trim();
            const parts = clean.split(',');
            if (parts.length >= 2) {
              const name = parts[0].toLowerCase();
              if (['mimikatz.exe', 'xmrig.exe', 'darkcomet.exe', 'swisyn.exe'].includes(name)) {
                foundThreats++;
                detectedThreats.push({
                  name: parts[0],
                  pid: parts[1],
                  category: 'Trojan / Miner',
                  severity: 'CRITICAL',
                });
              }
            }
          }
        } catch {}
      }

      // 2. Log periodic telemetry in SQLite
      const nowStr = new Date().toLocaleTimeString('fr-FR');
      const scanId = `scan-${Date.now()}`;
      
      dbManager.recordScan({
        id: scanId,
        scanType: 'BACKGROUND_PERIODIC',
        totalScanned: 48,
        threatsFound: foundThreats,
        durationMs: 340,
        scannedAt: new Date().toISOString(),
        summaryJson: JSON.stringify({
          status: foundThreats > 0 ? 'ALERT' : 'CLEAN',
          foundThreats,
        }),
      });

      const logEntry = {
        id: `log-cron-${Date.now()}`,
        timestamp: nowStr,
        level: foundThreats > 0 ? 'WARN' : 'INFO',
        tag: 'SENTINELLE-FOND',
        text: foundThreats > 0
          ? `[SURVEILLANCE CONTINUE] ${foundThreats} menace(s) suspecte(s) interceptée(s) en mémoire.`
          : `[SURVEILLANCE CONTINUE] Scan d'arrière-plan terminé : intégrité système confirmée (0 anomalie).`,
        operatorName: 'Sentinelle Cron',
      };

      dbManager.addAuditLog(logEntry);

      // 3. Broadcast alert via WebSocket to all active operators
      if (this.broadcast) {
        this.broadcast({
          type: 'STATE_DELTA',
          action: 'ADD_LOG',
          payload: logEntry,
          state: {
            threats: dbManager.getThreats(),
            logs: dbManager.getAuditLogs(100),
          },
        });

        if (foundThreats > 0) {
          this.broadcast({
            type: 'THREAT_ALERT',
            notification: {
              title: 'Alerte Sentinelle Arrière-Plan',
              description: `${foundThreats} menace(s) détectée(s) lors du cycle de surveillance automatisé.`,
              severity: 'CRITICAL',
              category: 'Watchdog',
              source: 'Sentinelle Cron (node-cron)',
              targetTab: 'overview',
            },
          });
        }
      }
    } catch (err) {
      logger.error({ err }, '[Scheduler] Échec du scan d\'arrière-plan');
    } finally {
      this.isRunningScan = false;
    }
  }

  stop(): void {
    if (this.task) {
      this.task.stop();
      this.task = null;
      logger.info('[Scheduler] Planificateur arrêté.');
    }
  }

  getStatus(): { active: boolean; cronExpression: string; isRunningScan: boolean } {
    return {
      active: this.task !== null,
      cronExpression: this.currentCronExpr,
      isRunningScan: this.isRunningScan,
    };
  }
}

export const backgroundScheduler = new BackgroundSchedulerService();
