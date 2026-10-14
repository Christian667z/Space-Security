import { WebSocket } from 'ws';
import { dbManager } from './db.ts';
import { logger } from './logger.ts';

export interface OperatorClient {
  id: string;
  name: string;
  role: string;
  ip: string;
  connectedAt: string;
  status: 'ONLINE' | 'IDLE';
}

export interface SharedState {
  threats: any[];
  logs: any[];
  blockedIps: string[];
  blockedWifiBssids: string[];
  activeUsersCount: number;
  lastModified: string;
}

export const sharedState: SharedState = {
  threats: [],
  logs: [],
  blockedIps: [],
  blockedWifiBssids: [],
  activeUsersCount: 1,
  lastModified: new Date().toISOString(),
};

export const clientSessions = new Map<WebSocket, OperatorClient>();
export let operatorSequence = 1;
export const connectedClients = new Set<WebSocket>();

export function getActiveOperators(): OperatorClient[] {
  return Array.from(clientSessions.values());
}

export function incrementOperatorSequence(): number {
  return operatorSequence++;
}

export function broadcastToAll(message: any, excludeWs?: WebSocket): void {
  const payload = JSON.stringify(message);
  connectedClients.forEach((client) => {
    if (client !== excludeWs && client.readyState === WebSocket.OPEN) {
      try {
        client.send(payload);
      } catch {}
    }
  });
}

export function recordThreatInternal(threat: any): boolean {
  if (!threat || !threat.id) return false;
  const existing = sharedState.threats.find(
    (t) => t.id === threat.id || (threat.targetPath && t.targetPath === threat.targetPath)
  );
  if (!existing) {
    const fullThreat = {
      ...threat,
      status: threat.status || 'ACTIVE',
      detectedAt: threat.detectedAt || new Date().toISOString(),
    };
    sharedState.threats.push(fullThreat);
    dbManager.saveThreat(fullThreat);
    sharedState.lastModified = new Date().toISOString();
    broadcastToAll({
      type: 'STATE_DELTA',
      action: 'RECORD_SCANNED_THREATS',
      payload: { threats: [fullThreat] },
      state: {
        ...sharedState,
        activeUsersCount: Math.max(1, connectedClients.size),
        activeOperators: getActiveOperators(),
      },
    });
    return true;
  }
  return false;
}

export function recordThreatsBatch(incomingThreats: any[]): number {
  if (!Array.isArray(incomingThreats) || incomingThreats.length === 0) return 0;
  const added: any[] = [];
  for (const t of incomingThreats) {
    if (!t || !t.id) continue;
    const existing = sharedState.threats.find(
      (existingT) => existingT.id === t.id || (t.targetPath && existingT.targetPath === t.targetPath)
    );
    if (!existing) {
      const fullThreat = {
        ...t,
        status: t.status || 'ACTIVE',
        detectedAt: t.detectedAt || new Date().toISOString(),
      };
      sharedState.threats.push(fullThreat);
      dbManager.saveThreat(fullThreat);
      added.push(fullThreat);
    }
  }
  if (added.length > 0) {
    sharedState.lastModified = new Date().toISOString();
    broadcastToAll({
      type: 'STATE_DELTA',
      action: 'RECORD_SCANNED_THREATS',
      payload: { threats: added },
      state: {
        ...sharedState,
        activeUsersCount: Math.max(1, connectedClients.size),
        activeOperators: getActiveOperators(),
      },
    });
  }
  return added.length;
}

export function applyStateMutation(action: string, payload: any, operator: any, originWs?: WebSocket): void {
  if (action === 'UPDATE_THREAT_STATUS') {
    const { threatId, status, targetPath } = payload;
    sharedState.threats = sharedState.threats.map((t) =>
      t.id === threatId || (targetPath && t.targetPath === targetPath) ? { ...t, status } : t
    );
    dbManager.updateThreatStatus(threatId, status, targetPath);
    logger.info({ action, threatId, status, operator: operator?.name }, '[StateMutation] Menace mise à jour');
  } else if (action === 'ADD_LOG') {
    sharedState.logs = [...sharedState.logs.slice(-200), payload];
    dbManager.addAuditLog(payload);
  } else if (action === 'BLOCK_IP') {
    if (!sharedState.blockedIps.includes(payload.ip)) {
      sharedState.blockedIps.push(payload.ip);
      dbManager.addBlockedEntity('IP', payload.ip, payload.reason);
      logger.info({ ip: payload.ip, operator: operator?.name }, '[StateMutation] IP hostile bloquée');
    }
  } else if (action === 'UNBLOCK_IP') {
    sharedState.blockedIps = sharedState.blockedIps.filter((ip) => ip !== payload.ip);
    dbManager.removeBlockedEntity('IP', payload.ip);
    logger.info({ ip: payload.ip, operator: operator?.name }, '[StateMutation] IP débloquée');
  } else if (action === 'BLOCK_WIFI_BSSID') {
    if (!sharedState.blockedWifiBssids.includes(payload.bssid)) {
      sharedState.blockedWifiBssids.push(payload.bssid);
      dbManager.addBlockedEntity('WIFI', payload.bssid, payload.reason);
    }
  } else if (action === 'BULK_UPDATE_THREAT_STATUS') {
    const { threatIds, status, command } = payload;
    const idSet = new Set(Array.isArray(threatIds) ? threatIds : []);
    sharedState.threats = sharedState.threats.map((t) =>
      idSet.has(t.id) ? { ...t, status } : t
    );
    dbManager.bulkUpdateThreatStatus(Array.from(idSet), status);
    if (command) {
      const logEntry = {
        id: `log-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
        timestamp: new Date().toLocaleTimeString('fr-FR'),
        level: 'OK',
        text: `[COMMANDE-PARTAGÉE] Exécution groupée (${idSet.size} cibles) par ${operator?.name || 'Opérateur'} : "${command}" -> Statut: ${status}`,
        tag: 'BULK-OP',
        operatorName: operator?.name,
      };
      sharedState.logs = [...sharedState.logs.slice(-200), logEntry];
      dbManager.addAuditLog(logEntry);
    }
  } else if (action === 'DISMISS_THREATS') {
    const { threatIds } = payload;
    const idSet = new Set(Array.isArray(threatIds) ? threatIds : []);
    sharedState.threats = sharedState.threats.map((t) =>
      idSet.has(t.id) ? { ...t, status: 'DISMISSED' } : t
    );
    dbManager.dismissThreats(Array.from(idSet));
    const logEntry = {
      id: `log-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
      timestamp: new Date().toLocaleTimeString('fr-FR'),
      level: 'WARN',
      text: `[REJET-MASSE] ${idSet.size} menace(s) ignorée(s)/rejetée(s) par ${operator?.name || 'Opérateur'}.`,
      tag: 'DISMISS',
      operatorName: operator?.name,
    };
    sharedState.logs = [...sharedState.logs.slice(-200), logEntry];
    dbManager.addAuditLog(logEntry);
  } else if (action === 'RESTORE_THREATS') {
    const { threatIds } = payload;
    const idSet = new Set(Array.isArray(threatIds) ? threatIds : []);
    sharedState.threats = sharedState.threats.map((t) =>
      idSet.has(t.id) ? { ...t, status: 'ACTIVE' } : t
    );
    dbManager.bulkUpdateThreatStatus(Array.from(idSet), 'ACTIVE');
    const logEntry = {
      id: `log-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
      timestamp: new Date().toLocaleTimeString('fr-FR'),
      level: 'INFO',
      text: `[RESTAURATION] ${idSet.size} menace(s) réactivée(s) par ${operator?.name || 'Opérateur'}.`,
      tag: 'RESTORE',
      operatorName: operator?.name,
    };
    sharedState.logs = [...sharedState.logs.slice(-200), logEntry];
    dbManager.addAuditLog(logEntry);
  } else if (action === 'RECORD_SCANNED_THREATS') {
    const incoming: any[] = Array.isArray(payload.threats) ? payload.threats : [];
    let addedCount = 0;
    for (const t of incoming) {
      if (!t || !t.id) continue;
      const exists = sharedState.threats.some((existing) => existing.id === t.id);
      if (!exists) {
        sharedState.threats.push(t);
        dbManager.saveThreat(t);
        addedCount++;
      }
    }
    if (addedCount > 0) {
      logger.info({ addedCount, operator: operator?.name }, '[StateMutation] Nouvelles menaces de scan enregistrées');
    }
  } else if (action === 'ADD_THREAT') {
    const t = payload;
    if (t && t.id && !sharedState.threats.some((existing) => existing.id === t.id)) {
      sharedState.threats.push(t);
      dbManager.saveThreat(t);
      logger.info({ threatId: t.id, operator: operator?.name }, '[StateMutation] Menace ajoutée');
    }
  } else if (action === 'RESET_THREATS') {
    sharedState.threats = sharedState.threats.map((t) => ({ ...t, status: 'ACTIVE' }));
    dbManager.resetThreats();
  } else if (action === 'CLEAR_LOGS') {
    sharedState.logs = [];
    dbManager.clearAuditLogs();
  }

  sharedState.lastModified = new Date().toISOString();
  broadcastToAll(
    {
      type: 'STATE_DELTA',
      action,
      payload,
      senderOperator: operator,
      state: {
        ...sharedState,
        activeUsersCount: Math.max(1, connectedClients.size),
        activeOperators: getActiveOperators(),
      },
    },
    originWs
  );
}

export function initSharedState(): void {
  let initialThreats = dbManager.getThreats();
  const defaultSeedThreats = [
    {
      id: 'threat-themes-explorer_exe',
      name: 'Malware Dossier Thèmes : explorer.exe (Faux Explorateur)',
      category: 'Trojan',
      severity: 'CRITICAL' as const,
      targetPath: 'C:\\Windows\\Resources\\Themes\\explorer.exe',
      mitreTechnique: 'T1036.005 - Masquerading: Match Legitimate Name or Location',
      lockedBySystem: true,
      trustedInstallerLocked: true,
      description: 'Faux binaire explorer.exe (32-bit) masqué dans C:\\Windows\\Resources\\Themes avec verrouillage TrustedInstaller et watchdog actif.',
      status: 'ACTIVE' as const,
      detectedAt: new Date().toISOString(),
    },
    {
      id: 'threat-socket-c2-4444',
      name: 'Balise C2 Sortante Active : Port 4444',
      category: 'C2',
      severity: 'CRITICAL' as const,
      targetPath: 'TCP 127.0.0.1:49822 -> 194.26.29.112:4444 (PID 7412)',
      mitreTechnique: 'T1071.001 - Application Layer Protocol: Web Protocols',
      lockedBySystem: false,
      trustedInstallerLocked: false,
      description: "Connexion active et balisage régulier vers l'adresse C2 194.26.29.112 sur le port non-standard 4444.",
      status: 'ACTIVE' as const,
      detectedAt: new Date().toISOString(),
    },
    {
      id: 'threat-kernel-minifilter',
      name: 'Pilote Kernel Suspect : rootkit_hook.sys (Hook IRP Ring0)',
      category: 'Kernel',
      severity: 'CRITICAL' as const,
      targetPath: 'C:\\Windows\\System32\\drivers\\rootkit_hook.sys',
      mitreTechnique: 'T1014 - Rootkit: Kernel Minifilter Hook',
      lockedBySystem: true,
      trustedInstallerLocked: true,
      description: 'Driver de filtre système non signé WHQL interceptant les requêtes IRP_MJ_CREATE pour masquer les fichiers malveillants.',
      status: 'ACTIVE' as const,
      detectedAt: new Date().toISOString(),
    },
    {
      id: 'seed-threat-bits-1',
      name: "Tâche BITS d'Exfiltration Détectée",
      category: 'Persistence',
      severity: 'HIGH' as const,
      targetPath: 'bitsadmin /job WindowsHealthUpdate (194.26.29.112)',
      mitreTechnique: 'T1197 - BITS Jobs',
      lockedBySystem: true,
      trustedInstallerLocked: false,
      description: 'Tâche persistante BITS configurée pour transférer des données vers un C2 externe hostile.',
      status: 'ACTIVE' as const,
      detectedAt: new Date().toISOString(),
    },
    {
      id: 'seed-threat-vad-2',
      name: 'Injection Mémoire Suspecte (Reflective DLL)',
      category: 'Memory',
      severity: 'CRITICAL' as const,
      targetPath: 'lsass.exe PID: 684 (Zone VAD EXECUTE_READWRITE)',
      mitreTechnique: 'T1055.001 - Dynamic-link Library Injection',
      lockedBySystem: true,
      trustedInstallerLocked: true,
      description: "Descripteur de mémoire virtuelle avec permissions d'exécution suspectes injecté dans lsass.exe.",
      status: 'ACTIVE' as const,
      detectedAt: new Date().toISOString(),
    },
    {
      id: 'seed-threat-def-3',
      name: 'Exclusion Windows Defender Illégitime',
      category: 'Defender',
      severity: 'MEDIUM' as const,
      targetPath: 'C:\\Users\\Public\\ (MpPreference -ExclusionPath)',
      mitreTechnique: 'T1562.001 - Disable or Modify Tools',
      lockedBySystem: false,
      trustedInstallerLocked: false,
      description: 'Dossier public whitelisté frauduleusement dans les exclusions de protection antivirus.',
      status: 'ACTIVE' as const,
      detectedAt: new Date().toISOString(),
    },
    {
      id: 'threat-vuln-kb5034441',
      name: 'Vulnérabilité WinRE Non Corrigée (KB5034441)',
      category: 'Privilege',
      severity: 'HIGH' as const,
      targetPath: 'KB5034441 (WinRE CVE-2024-20666)',
      mitreTechnique: 'CVE-2024-20666 - BitLocker Security Feature Bypass',
      lockedBySystem: false,
      trustedInstallerLocked: false,
      description: 'Correctif critique Windows WinRE non installé permettant le contournement du chiffrement BitLocker.',
      status: 'ACTIVE' as const,
      detectedAt: new Date().toISOString(),
    },
    {
      id: 'threat-service-remoteregistry',
      name: 'Service Vulnérable Actif : RemoteRegistry',
      category: 'Trojan',
      severity: 'HIGH' as const,
      targetPath: 'RemoteRegistry (Service Windows)',
      mitreTechnique: 'T1112 - Modify Registry',
      lockedBySystem: false,
      trustedInstallerLocked: false,
      description: 'Registre à distance actif exposant les ruches système à des modifications RPC distantes.',
      status: 'ACTIVE' as const,
      detectedAt: new Date().toISOString(),
    },
    {
      id: 'threat-hosts-alteration',
      name: 'Altération Hostile du Fichier HOSTS',
      category: 'Network',
      severity: 'HIGH' as const,
      targetPath: 'C:\\Windows\\System32\\drivers\\etc\\hosts',
      mitreTechnique: 'T1565.001 - Internal Defacement / DNS Poisoning',
      lockedBySystem: false,
      trustedInstallerLocked: false,
      description: 'Redirections forcées vers 127.0.0.1 pour les domaines de télémétrie et de mise à jour antivirus Microsoft.',
      status: 'ACTIVE' as const,
      detectedAt: new Date().toISOString(),
    },
  ];

  const existingCategories = new Set(initialThreats.map((t) => t.category));
  const hasMissingPillars = ['Trojan', 'C2', 'Kernel', 'Persistence', 'Memory', 'Defender', 'Privilege', 'Network'].some(
    (c) => !existingCategories.has(c)
  );

  if (initialThreats.length === 0 || hasMissingPillars) {
    for (const t of defaultSeedThreats) {
      if (!initialThreats.some((existing) => existing.id === t.id)) {
        dbManager.saveThreat(t);
      }
    }
    initialThreats = dbManager.getThreats();
  }

  let initialLogs = dbManager.getAuditLogs(100);
  if (initialLogs.length === 0) {
    const seedLogs = [
      {
        id: 'log-init-1',
        timestamp: new Date().toLocaleTimeString('fr-FR'),
        level: 'INFO',
        tag: 'INITIALISATION',
        text: 'Initialisation de Space Security CyberDefense Suite v3.0 KERNEL EDITION...',
        operatorName: 'System Kernel',
      },
      {
        id: 'log-init-2',
        timestamp: new Date().toLocaleTimeString('fr-FR'),
        level: 'OK',
        tag: 'ELEVATION',
        text: 'Vérification du bouclier UAC : Privilèges Administrateur confirmés (SID S-1-5-32-544).',
        operatorName: 'System Kernel',
      },
      {
        id: 'log-init-3',
        timestamp: new Date().toLocaleTimeString('fr-FR'),
        level: 'KERNEL',
        tag: 'P/INVOKE',
        text: 'Acquisition des privilèges NT : SeDebugPrivilege et SeTakeOwnershipPrivilege activés avec succès.',
        operatorName: 'System Kernel',
      },
      {
        id: 'log-init-4',
        timestamp: new Date().toLocaleTimeString('fr-FR'),
        level: 'OK',
        tag: 'PERSISTENCE',
        text: 'Moteur de persistance SQLite (spacesec.sqlite) activé avec intégrité transactionnelle.',
        operatorName: 'System Kernel',
      },
    ];
    for (const l of seedLogs) {
      dbManager.addAuditLog(l);
    }
    initialLogs = dbManager.getAuditLogs(100);
  }

  sharedState.threats = initialThreats;
  sharedState.logs = initialLogs;
  sharedState.blockedIps = dbManager.getBlockedList('IP');
  sharedState.blockedWifiBssids = dbManager.getBlockedList('WIFI');
  sharedState.activeUsersCount = 1;
  sharedState.lastModified = new Date().toISOString();
}
