/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { initializeApp, getApps } from 'firebase/app';
import {
  getFirestore,
  doc,
  setDoc,
  getDoc,
  getDocs,
  collection,
  deleteDoc,
  type Firestore,
} from 'firebase/firestore';
import { logger } from './logger.ts';
import { dbManager } from './db.ts';

// Static import of Firebase applet configuration as mandated by guidelines
import firebaseConfig from '../../firebase-applet-config.json';

class FirestoreSyncService {
  private db: Firestore | null = null;
  private isConnected = false;
  private lastSyncTime: string | null = null;

  async init(): Promise<boolean> {
    try {
      if (!firebaseConfig || !firebaseConfig.projectId || firebaseConfig.projectId === 'remixed-project-id') {
        logger.warn('[Firestore HA] Configuration non initialisée ou placeholder détecté.');
        return false;
      }

      const app = !getApps().length ? initializeApp(firebaseConfig) : getApps()[0];
      this.db = getFirestore(app, firebaseConfig.firestoreDatabaseId);

      // Verify connection to Firestore with a fast ping test
      const testDocRef = doc(this.db, 'system_health', 'ping');
      await setDoc(testDocRef, {
        status: 'ONLINE',
        service: 'SpaceSec-HA-Engine',
        timestamp: new Date().toISOString(),
      }, { merge: true });

      this.isConnected = true;
      this.lastSyncTime = new Date().toISOString();
      logger.info(
        { projectId: firebaseConfig.projectId, databaseId: firebaseConfig.firestoreDatabaseId },
        '🚀 [Firestore HA] Connecté avec succès à Cloud Firestore pour la persistance haute disponibilité !'
      );

      // Restore data from Firestore into local cache to survive container restarts
      await this.restoreFromCloud();
      return true;
    } catch (err: any) {
      logger.warn({ err: err?.message || err }, '[Firestore HA] Connexion Cloud Firestore indisponible, mode local résilient actif');
      this.isConnected = false;
      return false;
    }
  }

  getPersistenceStatus() {
    return {
      connected: this.isConnected,
      projectId: firebaseConfig?.projectId || '',
      databaseId: firebaseConfig?.firestoreDatabaseId || '(default)',
      lastSyncTime: this.lastSyncTime || 'Jamais',
      storageEngine: this.isConnected ? 'CLOUD_FIRESTORE_HA' : 'LOCAL_SQLITE_STANDALONE',
    };
  }

  /**
   * Restores historical data from Cloud Firestore on container boot if available.
   * Eliminates data wipe issues when container restarts without a persistent disk!
   */
  async restoreFromCloud(): Promise<void> {
    if (!this.db || !this.isConnected) return;

    try {
      logger.info('[Firestore HA] Synchronisation ascendante des archives cloud...');

      // 1. Restore Threats
      const threatsSnap = await getDocs(collection(this.db, 'threats'));
      let restoredThreats = 0;
      threatsSnap.forEach((docSnap) => {
        const data = docSnap.data();
        if (data && data.id) {
          dbManager.saveThreat(data as any);
          restoredThreats++;
        }
      });

      // 2. Restore EDR Endpoints
      const endpointsSnap = await getDocs(collection(this.db, 'edr_endpoints'));
      let restoredEndpoints = 0;
      endpointsSnap.forEach((docSnap) => {
        const data = docSnap.data();
        if (data && data.id && data.hostname) {
          dbManager.saveEndpoint(data as any);
          restoredEndpoints++;
        }
      });

      // 3. Restore User Settings
      const settingsSnap = await getDocs(collection(this.db, 'user_settings'));
      let restoredSettings = 0;
      settingsSnap.forEach((docSnap) => {
        const data = docSnap.data();
        if (data && data.key && data.valueJson) {
          try {
            dbManager.updateSettings({ [data.key]: JSON.parse(data.valueJson) });
            restoredSettings++;
          } catch {}
        }
      });

      logger.info(
        { restoredThreats, restoredEndpoints, restoredSettings },
        '[Firestore HA] Données historiques restaurées depuis le Cloud avec succès !'
      );

      // If Cloud was empty, seed current local records to Cloud for future restarts
      if (restoredThreats === 0) {
        const localThreats = dbManager.getThreats();
        for (const t of localThreats) {
          await this.syncThreat(t);
        }
      }

      if (restoredEndpoints === 0) {
        const localEndpoints = dbManager.getEndpoints();
        for (const ep of localEndpoints) {
          await this.syncEdrEndpoint(ep);
        }
      }

      this.lastSyncTime = new Date().toISOString();
    } catch (err: any) {
      logger.warn({ err: err?.message }, '[Firestore HA] Erreur pendant la synchronisation ascendante');
    }
  }

  // --- Real-time Persistence Sync Methods ---

  async syncThreat(threat: any): Promise<void> {
    if (!this.db || !this.isConnected || !threat || !threat.id) return;
    try {
      const docRef = doc(this.db, 'threats', threat.id);
      await setDoc(docRef, {
        id: threat.id,
        name: threat.name || 'Menace Inconnue',
        category: threat.category || 'General',
        severity: threat.severity || 'HIGH',
        targetPath: threat.targetPath || '',
        mitreTechnique: threat.mitreTechnique || '',
        lockedBySystem: Boolean(threat.lockedBySystem),
        trustedInstallerLocked: Boolean(threat.trustedInstallerLocked),
        description: threat.description || '',
        status: threat.status || 'ACTIVE',
        detectedAt: threat.detectedAt || new Date().toISOString(),
        resolvedAt: threat.resolvedAt || null,
        syncedAt: new Date().toISOString(),
      }, { merge: true });
      this.lastSyncTime = new Date().toISOString();
    } catch (err: any) {
      logger.debug({ err: err?.message, id: threat.id }, '[Firestore HA] Échec écriture menace');
    }
  }

  async deleteThreat(id: string): Promise<void> {
    if (!this.db || !this.isConnected) return;
    try {
      await deleteDoc(doc(this.db, 'threats', id));
    } catch {}
  }

  async syncAuditLog(log: any): Promise<void> {
    if (!this.db || !this.isConnected || !log || !log.id) return;
    try {
      const docRef = doc(this.db, 'audit_logs', log.id);
      await setDoc(docRef, {
        id: log.id,
        timestamp: log.timestamp || new Date().toLocaleTimeString('fr-FR'),
        level: log.level || 'INFO',
        tag: log.tag || 'SYSTEM',
        text: log.text || '',
        operatorName: log.operatorName || 'Analyste',
        createdAt: log.createdAt || new Date().toISOString(),
      });
      this.lastSyncTime = new Date().toISOString();
    } catch (err: any) {
      logger.debug({ err: err?.message }, '[Firestore HA] Échec écriture log');
    }
  }

  async syncEdrEndpoint(ep: any): Promise<void> {
    if (!this.db || !this.isConnected || !ep || !ep.id) return;
    try {
      const docRef = doc(this.db, 'edr_endpoints', ep.id);
      await setDoc(docRef, {
        id: ep.id,
        hostname: ep.hostname,
        ipAddress: ep.ipAddress,
        publicIp: ep.publicIp || null,
        macAddress: ep.macAddress || '',
        osVersion: ep.osVersion,
        agentVersion: ep.agentVersion,
        status: ep.status || 'ONLINE',
        lastSeen: ep.lastSeen || new Date().toISOString(),
        registeredAt: ep.registeredAt || new Date().toISOString(),
        healthScore: Number(ep.healthScore ?? 100),
        activeThreatsCount: Number(ep.activeThreatsCount ?? 0),
        networkIsolated: Boolean(ep.networkIsolated),
        cpuUsagePercent: Number(ep.cpuUsagePercent ?? 0),
        ramUsagePercent: Number(ep.ramUsagePercent ?? 0),
        syncedAt: new Date().toISOString(),
      }, { merge: true });
      this.lastSyncTime = new Date().toISOString();
    } catch (err: any) {
      logger.debug({ err: err?.message, id: ep.id }, '[Firestore HA] Échec écriture endpoint');
    }
  }

  async deleteEdrEndpoint(id: string): Promise<void> {
    if (!this.db || !this.isConnected) return;
    try {
      await deleteDoc(doc(this.db, 'edr_endpoints', id));
    } catch {}
  }

  async syncEdrEvent(evt: any): Promise<void> {
    if (!this.db || !this.isConnected || !evt || !evt.id) return;
    try {
      const docRef = doc(this.db, 'edr_telemetry_events', evt.id);
      await setDoc(docRef, {
        id: evt.id,
        endpointId: evt.endpointId,
        hostname: evt.hostname,
        timestamp: evt.timestamp || new Date().toISOString(),
        category: evt.category,
        severity: evt.severity,
        summary: evt.summary,
        detailsJson: evt.details ? JSON.stringify(evt.details) : null,
        mitreTechnique: evt.mitreTechnique || null,
      });
      this.lastSyncTime = new Date().toISOString();
    } catch (err: any) {
      logger.debug({ err: err?.message, id: evt.id }, '[Firestore HA] Échec écriture événement');
    }
  }

  async syncSetting(key: string, value: any): Promise<void> {
    if (!this.db || !this.isConnected) return;
    try {
      const docRef = doc(this.db, 'user_settings', key);
      await setDoc(docRef, {
        key,
        valueJson: JSON.stringify(value),
        updatedAt: new Date().toISOString(),
      }, { merge: true });
      this.lastSyncTime = new Date().toISOString();
    } catch (err: any) {
      logger.debug({ err: err?.message, key }, '[Firestore HA] Échec écriture paramètre');
    }
  }
}

export const firestoreSync = new FirestoreSyncService();
