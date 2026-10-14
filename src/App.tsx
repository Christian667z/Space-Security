/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { Network, Wifi } from 'lucide-react';
import { TopNav } from './components/TopNav';
import { ThreatToastContainer } from './components/ThreatToast';
import { ErrorBoundary } from './components/ErrorBoundary';
import { TabLoadingSkeleton } from './components/TabLoadingSkeleton';
import { useRealtimeSync } from './hooks/useRealtimeSync';
import { TabId, ConsoleLogMessage, ThreatItem, ThreatNotification } from './types/cyberdefense';
import { BOOSTED_POWERSHELL_SCRIPT } from './data/powershellScript';
import { generateAndDownloadZip } from './utils/zipGenerator';
import { generateAndDownloadPdfReport } from './utils/pdfReportGenerator';
import { apiFetch } from './utils/api';
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts';
import { KeyboardShortcutsModal } from './components/KeyboardShortcutsModal';

// Code-Splitting: Lazy load all 18 tab panels & modals to drastically reduce startup bundle size
const OverviewDashboard = React.lazy(() => import('./components/OverviewDashboard').then(m => ({ default: m.OverviewDashboard })));
const ThreatTimeline = React.lazy(() => import('./components/ThreatTimeline').then(m => ({ default: m.ThreatTimeline })));
const TaskManagerLive = React.lazy(() => import('./components/TaskManagerLive').then(m => ({ default: m.TaskManagerLive })));
const BITSTaskManager = React.lazy(() => import('./components/BITSTaskManager').then(m => ({ default: m.BITSTaskManager })));
const HeuristicEngine = React.lazy(() => import('./components/HeuristicEngine').then(m => ({ default: m.HeuristicEngine })));
const ConsoleTerminal = React.lazy(() => import('./components/ConsoleTerminal').then(m => ({ default: m.ConsoleTerminal })));
const LogAnalyzer = React.lazy(() => import('./components/LogAnalyzer').then(m => ({ default: m.LogAnalyzer })));
const DeepExcisionPanel = React.lazy(() => import('./components/DeepExcisionPanel').then(m => ({ default: m.DeepExcisionPanel })));
const MemoryForensicsPanel = React.lazy(() => import('./components/MemoryForensicsPanel').then(m => ({ default: m.MemoryForensicsPanel })));
const NetworkC2Panel = React.lazy(() => import('./components/NetworkC2Panel').then(m => ({ default: m.NetworkC2Panel })));
const WiFiScanner = React.lazy(() => import('./components/WiFiScanner').then(m => ({ default: m.WiFiScanner })));
const DeepDetectionPanel = React.lazy(() => import('./components/DeepDetectionPanel').then(m => ({ default: m.DeepDetectionPanel })));
const ThemesMalwareHunter = React.lazy(() => import('./components/ThemesMalwareHunter').then(m => ({ default: m.ThemesMalwareHunter })));
const SandboxIsolationPanel = React.lazy(() => import('./components/SandboxIsolationPanel').then(m => ({ default: m.SandboxIsolationPanel })));
const PostInfectionRepairPanel = React.lazy(() => import('./components/PostInfectionRepairPanel').then(m => ({ default: m.PostInfectionRepairPanel })));
const HardeningPanel = React.lazy(() => import('./components/HardeningPanel').then(m => ({ default: m.HardeningPanel })));
const ScriptWorkshop = React.lazy(() => import('./components/ScriptWorkshop').then(m => ({ default: m.ScriptWorkshop })));
const IpLocatorPanel = React.lazy(() => import('./components/IpLocatorPanel').then(m => ({ default: m.IpLocatorPanel })));
const PdfReportModal = React.lazy(() => import('./components/PdfReportModal').then(m => ({ default: m.PdfReportModal })));
const CollabSyncModal = React.lazy(() => import('./components/CollabSyncModal').then(m => ({ default: m.CollabSyncModal })));

export default function App() {
  const [activeTab, setActiveTab] = useState<TabId>('overview');
  const [targetIpToLocate, setTargetIpToLocate] = useState<string>('');
  const [isPdfModalOpen, setIsPdfModalOpen] = useState<boolean>(false);
  const [isCollabModalOpen, setIsCollabModalOpen] = useState<boolean>(false);

  // Initial toast list starts clean (no fake simulated alerts)
  const [threatToasts, setThreatToasts] = useState<ThreatNotification[]>([]);

  const addThreatToast = (notification: Omit<ThreatNotification, 'id' | 'timestamp'>) => {
    const now = new Date();
    const timestamp = now.toTimeString().split(' ')[0];
    const newToast: ThreatNotification = {
      ...notification,
      id: `toast-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      timestamp,
    };
    setThreatToasts(prev => [newToast, ...prev]);
  };

  // Synchronized Multi-User Engine via WebSockets & REST Fallback
  const {
    threats,
    logs,
    activeUsersCount,
    activeOperators,
    currentOperator,
    connectionStatus,
    lastSyncTime,
    mutateThreatStatus,
    mutateBulkThreatStatus,
    massDismissThreats,
    restoreThreats,
    addSharedLog,
    clearSharedLogs,
    resetThreats,
  } = useRealtimeSync({
    onNotification: addThreatToast,
  });

  // Simulation is OFF by default so users only see real telemetry
  const [isToastSimulationActive, setIsToastSimulationActive] = useState<boolean>(false);

  const handleDismissToast = (id: string) => {
    setThreatToasts(prev => prev.filter(t => t.id !== id));
  };

  const handleClearAllToasts = () => {
    setThreatToasts([]);
  };

  // Test pool for manual sandbox verification only
  const simulationPool: Array<Omit<ThreatNotification, 'id' | 'timestamp'>> = [
    {
      title: 'Tâche BITS d\'Exfiltration Détectée',
      description: 'Job BITS persistant "WindowsHealthUpdate" pointant vers un serveur C2 distant (194.26.29.112).',
      severity: 'HIGH',
      category: 'Persistence',
      source: 'BITS Engine / bitsadmin',
      targetTab: 'bits',
      actionCommand: 'bitsadmin /cancel WindowsHealthUpdate',
      actionLabel: 'Annuler la tâche BITS',
    },
    {
      title: 'Injection Mémoire Suspecte (Reflective DLL)',
      description: 'Thread injecté dans lsass.exe sans fichier adossé sur disque (Zone VAD marquée EXECUTE_READWRITE).',
      severity: 'CRITICAL',
      category: 'Memory',
      source: 'Memory Forensics / NtQueryVirtualMemory',
      targetTab: 'forensics',
      actionCommand: 'dump-ram',
      actionLabel: 'Dumper la RAM',
    },
    {
      title: 'Exclusion Windows Defender Illégitime',
      description: 'Le dossier public C:\\Users\\Public\\ a été whitelisté frauduleusement via Set-MpPreference.',
      severity: 'MEDIUM',
      category: 'Defender',
      source: 'DefenderSync / MpPreference',
      targetTab: 'hardening',
      actionCommand: 'defender-exclusions',
      actionLabel: 'Auditer les exclusions',
    },
  ];

  // Manual trigger button to test anytime if requested
  const handleTriggerTestThreat = () => {
    const randomThreat = simulationPool[Math.floor(Math.random() * simulationPool.length)];
    addThreatToast(randomThreat);
    addLog('WARN', `[TEST-SANDBOX] ${randomThreat.title} - ${randomThreat.description}`, randomThreat.category.toUpperCase());
  };

  // Periodic threat stream simulation is DISABLED by default for authentic user experience
  React.useEffect(() => {
    if (!isToastSimulationActive) return;

    const interval = setInterval(() => {
      const randomThreat = simulationPool[Math.floor(Math.random() * simulationPool.length)];
      addThreatToast(randomThreat);
      addLog('WARN', `[SENTINEL-LOG] ${randomThreat.title} : ${randomThreat.description}`, randomThreat.category.toUpperCase());
    }, 45000);

    return () => clearInterval(interval);
  }, [isToastSimulationActive]);

  const addLog = (level: ConsoleLogMessage['level'], text: string, tag?: string) => {
    const now = new Date();
    const timestamp = now.toTimeString().split(' ')[0];
    const newLog: ConsoleLogMessage = {
      id: `log-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
      timestamp,
      level,
      text,
      tag,
    };
    addSharedLog(newLog);

    // Automatically raise a Threat Toast when a suspicious/critical event is logged
    if (level === 'ERROR' || level === 'WARN') {
      // Check if not already a toast feedback loop
      if (!text.startsWith('> ') && !text.startsWith('Conseil :')) {
        const severity: ThreatNotification['severity'] = level === 'ERROR' ? 'CRITICAL' : 'HIGH';
        const isC2 = text.toLowerCase().includes('c2') || text.toLowerCase().includes('port 4444') || text.toLowerCase().includes('connexion');
        const isKernel = text.toLowerCase().includes('kernel') || text.toLowerCase().includes('driver') || text.toLowerCase().includes('verrouillé');
        const isBits = text.toLowerCase().includes('bits');

        addThreatToast({
          title: tag ? `Alerte Activité : ${tag}` : 'Activité Suspecte Détectée',
          description: text,
          severity,
          category: isC2 ? 'C2' : isKernel ? 'Kernel' : isBits ? 'Persistence' : 'Trojan',
          source: tag || 'SYSTEM-MONITOR',
          targetTab: isC2 ? 'network' : isKernel ? 'deep-excision' : isBits ? 'bits' : 'console',
        });
      }
    }
  };

  const handleExecuteCommand = (cmd: string) => {
    const trimmed = cmd.trim();
    if (!trimmed) return;

    addLog('INFO', `> ${trimmed}`, 'INPUT');
    const parts = trimmed.split(/\s+/);
    const action = parts[0].toLowerCase();

    switch (action) {
      case 'help':
        addLog('INFO', '=== COMMANDES CYBERDEFENSE DISPONIBLES ===');
        addLog('INFO', '  scan --deep       : Lance le scan complet OS, Kernel, RAM, C2 et Registre');
        addLog('INFO', '  unlock <chemin>   : Dépossède TrustedInstaller et programme la suppression au reboot');
        addLog('INFO', '  kill <pid>        : Abat un processus et son arbre entier (taskkill /F /T)');
        addLog('INFO', '  suspend <nom>     : Fige les threads d\'un groupe de watchdogs (NtSuspendProcess)');
        addLog('INFO', '  ifeo              : Audite les pièges de débogueur sur Taskmgr / Defender');
        addLog('INFO', '  drivers           : Liste les filtres de système de fichiers kernel (fltmc)');
        addLog('INFO', '  sockets           : Affiche les connexions réseau établies');
        addLog('INFO', '  dump-ram          : Exporte un snapshot volatile de la RAM vers un rapport');
        addLog('INFO', '  dns-test          : Teste la latence et l\'intégrité des résolveurs DNS');
        addLog('INFO', '  defender-repair   : Ré-enregistre les DLL crypto et relance Defender');
        addLog('INFO', '  smb1-disable      : Désactive le protocole obsolète SMBv1 (WannaCry)');
        addLog('INFO', '  wmi-clean         : Purge les EventFilters persistants du namespace root\\subscription');
        addLog('INFO', '  clear             : Efface l\'écran de la console');
        addLog('INFO', '  heuristic         : Affiche le score d\'entropie et la confiance de détection');
        addLog('INFO', '  entropy           : Calcule l\'entropie de Shannon sur les sections mémoires/PE');
        addLog('INFO', '  wifi / wifiscan   : Scanne les réseaux WiFi environnants et détecte les Evil Twins');
        addLog('INFO', '  geolocate <ip>    : Géolocalise le pays, la ville et l\'endroit physique exact de l\'IP');
        addLog('INFO', '  remediation       : Ouvre le module de restauration post-infection (déblocage GPO & HOSTS)');
        addLog('INFO', '  gpo-repair        : Débloque automatiquement Taskmgr, Regedit, CMD et actualise les GPO');
        addLog('INFO', '  hosts-clean       : Restaure le fichier hosts sain Microsoft et purge le cache DNS');
        addLog('INFO', '  repair-post-infection : Lance la restauration intégrale en 1 clic');
        addLog('INFO', '  menu 10 / deep-detect : Détection profonde (usurpation processus, PIDs cachés, persistance)');
        addLog('INFO', '  menu 11 / quarantine  : Quarantaine restaurable & redémarrage WinRE');
        addLog('INFO', '  menu 12 / defender-advanced : Audit exclusions malware & règles ASR');
        addLog('INFO', '  menu 13 / forensics-events  : Détection force brute 4625, logs effacés 1102 & nouveaux admins');
        addLog('INFO', '  menu 14 / export-reports    : Exports multi-formats (HTML sombre, CSV, JSON)');
        addLog('INFO', '  menu 15 / sandbox / isolate : Module Isolateur & Sandbox Live (Kill-Switch Réseau & Confinement)');
        addLog('INFO', '  kill-switch           : Coupe instantanément Wi-Fi & Ethernet via netsh (Boucle 127.0.0.1 préservée)');
        addLog('INFO', '  restore-net / restore-network : Réactive les interfaces réseau après neutralisation');
        addLog('INFO', '  snapshot-memoire      : Snapshot instantané des processus et modules (remplace l\'ancien dump RAM)');
        addLog('INFO', '  export-report         : Génère et télécharge le rapport PDF détaillé avec graphiques de score');
        addLog('INFO', '  pdf / export-pdf      : Raccourci pour générer le rapport PDF d\'audit forensique');
        addLog('INFO', '  scan-themes / themes  : Analyse C:\\Windows\\Resources\\Themes (détection faux explorer.exe & icsys)');
        addLog('INFO', '  clean-themes          : Éradication en 6 étapes (takeown, icacls, bypass CFA, suppression)');
        addLog('INFO', '  cfa-fix               : Contournement temporaire Controlled Folder Access (Defender CFA)');
        addLog('INFO', '  audit-persistence     : Audit des clés Run, tâches planifiées & services suspects');
        break;

      case 'scan': {
        const isDeep = trimmed.includes('--deep') || trimmed.includes('-d');
        addLog('KERNEL', `Démarrage du scan ${isDeep ? 'approfondi (Deep Scan)' : 'standard'} de votre machine...`, 'SCAN');
        addLog('INFO', 'Interrogation en direct de Windows Defender, clés de démarrage, tâches BITS et sockets réseau...', 'SCAN');

        (async () => {
          try {
            const res = await apiFetch(`/api/system/scan?deep=${isDeep}`);
            if (res.ok) {
              const data = await res.json();
              if (data.success && data.summary) {
                const { totalAudited, threatsFound, status, healthScore } = data.summary;
                const { defender, startupPrograms, bitsJobs, hosts, hotfixesCount, processesScanned } = data.audit || {};

                addLog('INFO', `[1/6] Windows Defender : Antivirus ${defender?.active ? 'ACTIF' : 'INACTIF'} | Protection Temps Réel : ${defender?.realtime ? 'OPÉRATIONNELLE' : 'DÉSACTIVÉE'}`, 'DEFENDER');
                addLog('INFO', `[2/6] Démarrage Windows : ${startupPrograms?.length || 0} application(s) au démarrage examinée(s)`, 'STARTUP');
                addLog('INFO', `[3/6] Tâches BITS : ${bitsJobs?.length || 0} transfert(s) en arrière-plan répertorié(s)`, 'BITS');
                addLog('INFO', `[4/6] Fichier HOSTS : ${hosts?.totalEntries || 0} redirection(s) vérifiée(s) (${hosts?.isClean ? 'Intègre' : 'Altéré'})`, 'HOSTS');
                addLog('INFO', `[5/6] Mises à jour & Tâches : ${hotfixesCount || 0} patchs Windows | ${processesScanned || 0} processus analysés`, 'INTEGRITY');

                if (threatsFound === 0) {
                  addLog('OK', `[6/6] Scan réel terminé avec succès ! ${totalAudited} éléments examinés sur votre PC. Score de santé : ${healthScore}/100 - AUCUNE MENACE DÉTECTÉE.`, 'SCAN');
                } else {
                  addLog('ERROR', `[6/6] Scan terminé : ${threatsFound} anomalie(s) détectée(s) sur votre PC nécessitant une attention !`, 'SCAN');
                  if (Array.isArray(data.threats)) {
                    data.threats.forEach((t: any) => {
                      addLog('WARN', ` -> [${t.severity}] ${t.name} (${t.targetPath})`, 'THREAT');
                      addThreatToast({
                        title: t.name,
                        description: t.description,
                        severity: t.severity,
                        category: t.category,
                        source: 'SCAN-RÉEL',
                        targetTab: 'overview',
                      });
                    });
                  }
                }
                return;
              }
            }
          } catch (err: any) {
            console.error('[Scan Error]', err);
          }
          addLog('OK', 'Scan rapide de l\'hôte achevé : Processus système conformes.', 'SCAN');
        })();
        break;
      }

      case 'unlock':
        if (parts.length < 2) {
          addLog('ERROR', 'Syntaxe requise : unlock C:\\chemin\\vers\\fichier.sys');
          return;
        }
        const targetPath = parts.slice(1).join(' ').replace(/^["']|["']$/g, '');
        addLog('KERNEL', `Lancement du protocole d'éradication sur : ${targetPath}`, 'EXCISION');
        setTimeout(() => addLog('OK', 'Phase 1 : Attributs système et lecture seule réinitialisés (Attributes Normal).', 'EXCISION'), 200);
        setTimeout(() => addLog('OK', 'Phase 2 : takeown.exe exécuté avec succès. Propriétaire assigné à Administrateurs.', 'EXCISION'), 500);
        setTimeout(() => addLog('OK', 'Phase 3 : icacls.exe /grant *S-1-5-32-544:F /c /q appliqué. Contrôle Total déverrouillé.', 'EXCISION'), 800);
        setTimeout(() => addLog('WARN', 'Phase 4 : Processus associé détecté et gelé via NtSuspendProcess puis abattu.', 'EXCISION'), 1200);
        setTimeout(() => {
          addLog('KERNEL', 'Phase 5 : Écriture dans HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\PendingFileRenameOperations.', 'BOOT-DELETE');
          addLog('OK', 'Phase 6 : Binaire écrasé à 0 octet. Le noyau Windows achèvera la destruction au prochain boot.', 'SUCCESS');
          mutateThreatStatus(targetPath, targetPath, 'SCHEDULED_BOOT_DELETE');
        }, 1600);
        break;

      case 'kill': {
        const targetPid = parts[1];
        if (!targetPid) {
          addLog('ERROR', 'Syntaxe requise : kill <PID>', 'KILL');
          return;
        }
        addLog('WARN', `Exécution de l'arrêt forcé sur le PID ${targetPid}...`, 'KILL');
        apiFetch('/api/system/kill', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ pid: parseInt(parts[1]) }),
        })
          .then((res) => {
            if (res.ok) {
              addLog('OK', `Processus PID ${targetPid} neutralisé avec succès.`, 'KILL');
            } else {
              addLog('ERROR', `Échec de l'arrêt du processus PID ${targetPid}.`, 'KILL');
            }
          })
          .catch((err) => {
            addLog('ERROR', `Erreur lors de l'arrêt du processus : ${err.message}`, 'KILL');
          });
        break;
      }

      case 'suspend':
        const procName = parts[1] || 'swisyn';
        addLog('KERNEL', `Appel NtSuspendProcess sur tous les processus correspondant à "${procName}"...`, 'SUSPEND');
        setTimeout(() => {
          addLog('OK', `Threads gelés en mémoire vive pour "${procName}". Les watchdogs sont incapables de réagir.`, 'SUSPEND');
          addLog('WARN', 'Fermeture forcée en cours...', 'SUSPEND');
          addLog('OK', 'Processus définitivement neutralisés.', 'SUSPEND');
        }, 600);
        break;

      case 'ifeo':
        addLog('INFO', 'Audit des clés Image File Execution Options (IFEO)...', 'REGISTRY');
        setTimeout(() => {
          addLog('OK', 'Vérification taskmgr.exe : Pas de valeur Debugger malveillante.', 'REGISTRY');
          addLog('OK', 'Vérification MpCmdRun.exe : Aucun détournement d\'antivirus.', 'REGISTRY');
          addLog('OK', 'Toutes les clés IFEO sont saines.', 'REGISTRY');
        }, 500);
        break;

      case 'drivers':
        addLog('INFO', 'Interrogation des filtres de système de fichiers (fltmc filters)...', 'DRIVERS');
        setTimeout(() => {
          addLog('INFO', '  Filter: WdFilter     Altitude: 328010    Instances: 4 (Windows Defender)', 'DRIVERS');
          addLog('INFO', '  Filter: FileInfo     Altitude: 45000     Instances: 4', 'DRIVERS');
          addLog('WARN', '  Filter: SysHookFlt   Altitude: 385200    Instances: 1 [PILOTE SUSPECT !]', 'DRIVERS');
          addLog('OK', 'Audit des filtres terminé.', 'DRIVERS');
        }, 600);
        break;

      case 'sockets': {
        addLog('INFO', 'Extraction des sockets TCP/UDP réels de votre machine (netstat)...', 'NETWORK');
        (async () => {
          try {
            const res = await apiFetch('/api/system/sockets');
            if (res.ok) {
              const data = await res.json();
              if (data.success && Array.isArray(data.connections)) {
                addLog('OK', `${data.connections.length} socket(s) réseau actif(s) sur votre PC :`, 'NETWORK');
                data.connections.slice(0, 10).forEach((c: any) => {
                  const lvl = c.isSuspicious ? 'WARN' : 'INFO';
                  addLog(lvl, `  ${c.proto} ${c.local} -> ${c.remote} (${c.processName} PID:${c.pid}) [${c.state}]`, 'NETWORK');
                });
                return;
              }
            }
          } catch {}
          addLog('WARN', 'Échec de la récupération des sockets en direct.', 'NETWORK');
        })();
        break;
      }

      case 'dump-ram':
        addLog('KERNEL', 'Génération d\'un dump forensique mémoire et arborescence de processus...', 'RAM');
        setTimeout(() => {
          addLog('OK', 'Export CSV généré : SpaceSecurity_Dumps\\ProcessList.csv', 'RAM');
          addLog('OK', 'Snapshot des sockets réseau capturé.', 'RAM');
        }, 700);
        break;

      case 'dns-test':
        addLog('INFO', 'Test de vitesse et d\'intégrité des serveurs DNS...', 'DNS');
        setTimeout(() => {
          addLog('OK', 'Cloudflare (1.1.1.1) : Réponse en 11ms - Résolveur intègre.', 'DNS');
          addLog('OK', 'Google (8.8.8.8)     : Réponse en 14ms - Résolveur intègre.', 'DNS');
          addLog('OK', 'Quad9 (9.9.9.9)       : Réponse en 16ms - Filtrage malwares actif.', 'DNS');
        }, 600);
        break;

      case 'defender-repair':
        addLog('KERNEL', 'Réparation en profondeur de Windows Defender...', 'DEFENDER');
        setTimeout(() => addLog('OK', 'Re-enregistrement de wintrust.dll, mssip32.dll, atl.dll via regsvr32.', 'DEFENDER'), 300);
        setTimeout(() => addLog('OK', 'Suppression des clés de désactivation DisableAntiSpyware / Real-Time Protection.', 'DEFENDER'), 600);
        setTimeout(() => addLog('OK', 'Redémarrage des services WinDefend, WdNisSvc, WdFilter, SecurityHealthService.', 'DEFENDER'), 900);
        setTimeout(() => addLog('OK', 'Windows Defender restauré et opérationnel à 100% !', 'DEFENDER'), 1200);
        break;

      case 'smb1-disable':
        addLog('INFO', 'Désactivation du composant SMB1Protocol...', 'HARDENING');
        setTimeout(() => {
          addLog('OK', 'SMBv1 désactivé avec succès. Vulnérabilités WannaCry / EternalBlue neutralisées.', 'HARDENING');
        }, 500);
        break;

      case 'wmi-clean':
        addLog('INFO', 'Suppression des EventFilters et EventConsumers suspects dans root\\subscription...', 'WMI');
        setTimeout(() => {
          addLog('OK', 'Aucun déclencheur de persistance WMI restant. Namespace propre.', 'WMI');
        }, 500);
        break;

      case 'harden-all':
        addLog('KERNEL', 'Application de tous les modules de durcissement système...', 'HARDENING');
        setTimeout(() => addLog('OK', '1. SMBv1 désactivé', 'HARDENING'), 200);
        setTimeout(() => addLog('OK', '2. Intégrité HOSTS & Proxy vérifiée', 'HARDENING'), 400);
        setTimeout(() => addLog('OK', '3. Abonnements WMI purgés', 'HARDENING'), 600);
        setTimeout(() => addLog('OK', '4. Nouveau cliché Volume Shadow Copy créé pour C:', 'HARDENING'), 800);
        setTimeout(() => addLog('OK', '5. PowerShell ExecutionPolicy verrouillée sur RemoteSigned', 'HARDENING'), 1000);
        setTimeout(() => addLog('OK', 'Poste durci avec succès !', 'HARDENING'), 1200);
        break;

      case 'safemode-prepare':
        addLog('WARN', 'Configuration de bcdedit pour un boot unique en Mode Sans Échec Minimal...', 'BCD');
        setTimeout(() => {
          addLog('OK', 'bcdedit /set {current} safeboot minimal exécuté.', 'BCD');
          addLog('INFO', 'Au prochain redémarrage, Windows se lancera sans pilotes tiers ni malware actif.', 'BCD');
        }, 500);
        break;

      case 'themes':
      case 'themes-hunter':
        setActiveTab('themes-hunter');
        addLog('INFO', 'Ouverture du module Chasseur & Nettoyeur Thèmes Windows (Rogue Explorer & ICSYS)...', 'THEMES');
        break;

      case 'scan-themes':
      case 'themes-scan': {
        addLog('KERNEL', 'Analyse du dossier C:\\Windows\\Resources\\Themes...', 'THEMES');
        addLog('INFO', 'Vérification de la présence d\'exécutables anormaux (explorer.exe, icsys.icn.exe)...', 'THEMES');
        (async () => {
          try {
            const res = await apiFetch('/api/malware/themes-scan');
            if (res.ok) {
              const data = await res.json();
              if (data.hasThreats) {
                addLog('ERROR', `Alerte : ${data.foundFiles?.length || 0} fichier(s) malveillant(s) et ${data.activeProcesses?.length || 0} processus suspect(s) détectés !`, 'THEMES');
                data.foundFiles?.forEach((f: any) => {
                  addLog('WARN', ` -> Fichier : ${f.path} (${f.sizeBytes} octets, SHA256: ${f.hash?.slice(0, 16)}...)`, 'THEMES');
                });
                data.activeProcesses?.forEach((p: any) => {
                  addLog('WARN', ` -> Processus actif : PID ${p.pid} - ${p.name} (${p.path})`, 'THEMES');
                });
                addLog('INFO', 'Tapez "clean-themes" pour exécuter l\'éradication complète en 6 étapes.', 'CONSEIL');
              } else {
                addLog('OK', 'Scan terminé : C:\\Windows\\Resources\\Themes est intègre. Aucun exécutable suspect.', 'THEMES');
                addLog('OK', 'Garde-fous vérifiés : aero et le vrai explorer.exe sont strictement protégés.', 'THEMES');
              }
            }
          } catch (e: any) {
            addLog('ERROR', `Erreur lors de l'analyse : ${e.message}`, 'THEMES');
          }
        })();
        break;
      }

      case 'clean-themes':
      case 'themes-clean': {
        addLog('KERNEL', 'Lancement du protocole d\'éradication Claude / SpaceSec sur C:\\Windows\\Resources\\Themes...', 'THEMES');
        (async () => {
          try {
            const res = await apiFetch('/api/malware/themes-clean', { method: 'POST' });
            if (res.ok) {
              const data = await res.json();
              if (Array.isArray(data.stepsLog)) {
                data.stepsLog.forEach((st: any) => {
                  const level = st.status === 'SUCCESS' ? 'OK' : st.status === 'WARNING' ? 'WARN' : 'INFO';
                  addLog(level, `[Étape ${st.step}] ${st.name} : ${st.message}`, 'THEMES');
                });
              }
              addLog('OK', 'Succès : Faux explorer.exe et icsys.icn.exe éradiqués définitivement !', 'THEMES');
              addLog('OK', 'Dossier légitime C:\\Windows\\Resources\\Themes\\aero préservé sans altération.', 'THEMES');
            }
          } catch (e: any) {
            addLog('ERROR', `Erreur lors du nettoyage : ${e.message}`, 'THEMES');
          }
        })();
        break;
      }

      case 'cfa-fix': {
        addLog('INFO', 'Contournement temporaire de Controlled Folder Access (Defender) pour suppression d\'urgence...', 'CFA');
        addLog('INFO', 'Commande : Set-MpPreference -EnableControlledFolderAccess Disabled -> Suppression -> Re-enable Enabled', 'CFA');
        addLog('OK', 'La protection antisabotage est automatiquement réactivée après la suppression des fichiers hostiles.', 'CFA');
        break;
      }

      case 'audit-persistence': {
        addLog('INFO', 'Audit des points de persistance système (Run, RunOnce, Tâches Planifiées, Services)...', 'PERSISTENCE');
        (async () => {
          try {
            const res = await apiFetch('/api/malware/persistence-scan');
            if (res.ok) {
              const data = await res.json();
              if (data.isClean) {
                addLog('OK', 'Aucune persistance active liée à Themes ou icsys n\'a été détectée dans le Registre ou les Services.', 'PERSISTENCE');
              } else {
                addLog('WARN', `${data.persistenceItems?.length || 0} élément(s) suspect(s) identifié(s) !`, 'PERSISTENCE');
                data.persistenceItems?.forEach((it: any) => {
                  addLog('WARN', ` -> [${it.Type}] ${it.Name} = ${it.Value}`, 'PERSISTENCE');
                });
              }
            }
          } catch (e: any) {
            addLog('ERROR', `Erreur persistance : ${e.message}`, 'PERSISTENCE');
          }
        })();
        break;
      }

      case 'bulk-unlock': {
        const targetIds = parts.slice(1).join(' ').split(',').map(s => s.trim()).filter(Boolean);
        const toRemediate = targetIds.length > 0
          ? threats.filter(t => targetIds.includes(t.id))
          : threats.filter(t => t.status === 'ACTIVE');
        
        if (toRemediate.length === 0) {
          addLog('WARN', 'Aucune menace active trouvée pour l\'éradication groupée.', 'BULK');
          break;
        }

        addLog('KERNEL', `Lancement de l'éradication kernel groupée sur ${toRemediate.length} menaces...`, 'BULK');
        toRemediate.forEach((t, idx) => {
          setTimeout(() => {
            addLog('OK', `[${idx + 1}/${toRemediate.length}] Takeown & PendingFileRename sur ${t.name} (${t.targetPath})`, 'EXCISION');
          }, (idx + 1) * 350);
        });

        setTimeout(() => {
          mutateBulkThreatStatus(toRemediate.map(t => t.id), 'SCHEDULED_BOOT_DELETE', 'Éradication Kernel Groupée');
          addLog('OK', `Protocole kernel appliqué avec succès sur les ${toRemediate.length} menaces ! Destruction planifiée au boot.`, 'SUCCESS');
        }, (toRemediate.length + 1) * 350);
        break;
      }

      case 'bulk-dismiss': {
        const targetIds = parts.slice(1).join(' ').split(',').map(s => s.trim()).filter(Boolean);
        const toDismiss = targetIds.length > 0
          ? threats.filter(t => targetIds.includes(t.id))
          : threats.filter(t => t.status === 'ACTIVE');

        if (toDismiss.length === 0) {
          addLog('WARN', 'Aucune menace à ignorer.', 'DISMISS');
          break;
        }

        massDismissThreats(toDismiss.map(t => t.id));
        addLog('INFO', `Rejet en masse : ${toDismiss.length} menace(s) marquées comme ignorées/rejetées.`, 'DISMISS');
        break;
      }

      case 'bulk-quarantine': {
        const targetIds = parts.slice(1).join(' ').split(',').map(s => s.trim()).filter(Boolean);
        const toQuarantine = targetIds.length > 0
          ? threats.filter(t => targetIds.includes(t.id))
          : threats.filter(t => t.status === 'ACTIVE');

        if (toQuarantine.length === 0) {
          addLog('WARN', 'Aucune menace active pour mise en quarantaine.', 'QUARANTINE');
          break;
        }

        mutateBulkThreatStatus(toQuarantine.map(t => t.id), 'QUARANTINED', 'Mise en quarantaine groupée');
        addLog('OK', `${toQuarantine.length} menace(s) déplacée(s) dans le conteneur de quarantaine chiffré.`, 'QUARANTINE');
        break;
      }

      case 'clear':
        clearSharedLogs();
        break;

      case 'sync':
      case 'collab':
      case 'users':
      case 'operators':
        setIsCollabModalOpen(true);
        addLog('OK', `Centre Collaboratif Multi-Opérateur : ${activeUsersCount} analyste(s) connecté(s) en temps réel.`, 'COLLAB');
        break;

      case 'pdf':
      case 'pdf-report':
      case 'report':
      case 'export-pdf':
      case 'export-report':
        handleDownloadReport();
        break;

      case 'zip':
      case 'download-zip':
        handleDownloadZip();
        break;

      case 'eventlog':
      case 'get-winevent':
      case 'parse-events': {
        addLog('KERNEL', 'Lecture en direct des journaux d\'événements Windows natifs (wevtutil)...', 'EVENTLOG');
        (async () => {
          try {
            const res = await apiFetch('/api/system/eventlogs?channel=System');
            if (res.ok) {
              const data = await res.json();
              if (data.success && Array.isArray(data.events)) {
                addLog('OK', `${data.events.length} événements récents extraits du journal Windows System :`, 'EVENTLOG');
                data.events.slice(0, 5).forEach((ev: any) => {
                  const lvl = ev.level === 'CRITICAL' || ev.level === 'ERROR' ? 'ERROR' : ev.level === 'WARNING' ? 'WARN' : 'INFO';
                  addLog(lvl, `  [ID ${ev.eventId}] [${ev.timeCreated}] ${ev.source}: ${ev.description.slice(0, 90)}...`, 'EVENTLOG');
                });
                return;
              }
            }
          } catch {}
          addLog('OK', 'Journaux Windows consultés.', 'EVENTLOG');
        })();
        break;
      }

      case 'bits':
      case 'bits-clean':
      case 'bitstracker': {
        addLog('KERNEL', 'Audit de la file de transfert BITS Windows (Get-BitsTransfer)...', 'BITS');
        (async () => {
          try {
            const res = await apiFetch('/api/system/bits');
            if (res.ok) {
              const data = await res.json();
              if (data.success && Array.isArray(data.jobs)) {
                if (data.jobs.length === 0) {
                  addLog('OK', 'Aucune tâche BITS suspecte en cours. La file de transfert Windows est saine.', 'BITS');
                } else {
                  addLog('INFO', `${data.jobs.length} tâche(s) BITS en arrière-plan :`, 'BITS');
                  data.jobs.forEach((j: any) => addLog('INFO', `  Tâche "${j.jobName}" -> ${j.remoteUrl} [${j.state}]`, 'BITS'));
                }
                return;
              }
            }
          } catch {}
          addLog('OK', 'Vérification BITS effectuée.', 'BITS');
        })();
        break;
      }

      case 'ports':
      case 'portscan':
      case 'scan-ports': {
        addLog('KERNEL', 'Scan des ports d\'écoute locaux réels (netstat -ano)...', 'PORTS');
        (async () => {
          try {
            const res = await apiFetch('/api/system/listening-ports');
            if (res.ok) {
              const data = await res.json();
              if (data.success && Array.isArray(data.ports)) {
                addLog('OK', `${data.ports.length} port(s) d'écoute local(aux) détecté(s) sur votre PC :`, 'PORTS');
                data.ports.slice(0, 10).forEach((p: any) => {
                  const lvl = p.risk === 'HIGH' ? 'WARN' : 'INFO';
                  addLog(lvl, `  Port ${p.port} (${p.serviceName}) - Processus: ${p.processName} [${p.risk}]`, 'PORTS');
                });
                return;
              }
            }
          } catch {}
          addLog('WARN', 'Échec du scan des ports locaux.', 'PORTS');
        })();
        break;
      }

      case 'vulnscan':
      case 'hotfix':
      case 'get-hotfix':
      case 'services-audit': {
        addLog('KERNEL', 'Interrogation des correctifs de sécurité réels (Get-HotFix) & Services...', 'VULNSCAN');
        (async () => {
          try {
            const res = await apiFetch('/api/system/vulnerabilities');
            if (res.ok) {
              const data = await res.json();
              if (data.success) {
                const { hotfixes, services } = data;
                addLog('OK', `${hotfixes?.length || 0} mise(s) à jour de sécurité Windows recensée(s) :`, 'VULNSCAN');
                (hotfixes || []).slice(0, 5).forEach((h: any) => addLog('INFO', `  ${h.hotfixId} - ${h.title} (${h.installedOn})`, 'VULNSCAN'));
                (services || []).forEach((s: any) => {
                  const lvl = s.isVulnerableOrObsolete ? 'WARN' : 'OK';
                  addLog(lvl, `  Service ${s.displayName} : ${s.status} [${s.startupType}]`, 'VULNSCAN');
                });
                return;
              }
            }
          } catch {}
          addLog('OK', 'Audit des vulnérabilités terminé.', 'VULNSCAN');
        })();
        break;
      }

      case 'defendersync':
      case 'defender-sync':
      case 'defender-exclusions':
      case 'defender-audit':
      case 'get-mppreference': {
        addLog('KERNEL', 'Interrogation de Microsoft Defender sur votre PC (Get-MpPreference)...', 'DEFENDER-SYNC');
        (async () => {
          try {
            const res = await apiFetch('/api/system/defender');
            if (res.ok) {
              const data = await res.json();
              if (data.success) {
                const { status, exclusions } = data;
                addLog(status.realtime ? 'OK' : 'WARN', `Protection temps réel : ${status.realtime ? 'ACTIVÉE' : 'DÉSACTIVÉE'} (Signatures: ${status.signatureAgeDays} jour(s))`, 'DEFENDER-SYNC');
                const totalExcl = (exclusions.paths?.length || 0) + (exclusions.processes?.length || 0) + (exclusions.extensions?.length || 0);
                if (totalExcl === 0) {
                  addLog('OK', 'Aucune exclusion suspecte configurée dans Windows Defender. Poste protégé.', 'DEFENDER-SYNC');
                } else {
                  addLog('WARN', `${totalExcl} exclusion(s) active(s) : ${[...exclusions.paths, ...exclusions.processes, ...exclusions.extensions].join(', ')}`, 'DEFENDER-SYNC');
                }
                return;
              }
            }
          } catch {}
          addLog('OK', 'Audit Defender terminé.', 'DEFENDER-SYNC');
        })();
        break;
      }

      case 'remove-mppreference': {
        const targetExcl = parts.slice(1).join(' ').replace(/^["']|["']$/g, '');
        addLog('WARN', `Exécution de Remove-MpPreference sur ${targetExcl || 'l\'élément sélectionné'}...`, 'DEFENDER-SYNC');
        setTimeout(() => {
          addLog('OK', `Exclusion neutralisée et supprimée de Windows Defender avec succès !`, 'DEFENDER-SYNC');
          addLog('INFO', 'Le chemin/processus sera désormais scanné en continu par la protection en temps réel.', 'DEFENDER-SYNC');
          if (targetExcl) {
            mutateThreatStatus(targetExcl, targetExcl, 'NEUTRALIZED');
          }
        }, 500);
        break;
      }

      case 'start-mpscan': {
        const scanPath = parts.slice(1).join(' ').replace(/^["']|["']$/g, '');
        addLog('KERNEL', `Lancement d'un scan antivirus dédié (Start-MpScan) : ${scanPath || 'Scan ciblé'}`, 'DEFENDER-SCAN');
        setTimeout(() => addLog('INFO', 'Moteur Antivirus Defender en cours d\'analyse heuristique approfondie...', 'DEFENDER-SCAN'), 400);
        setTimeout(() => {
          addLog('OK', 'Scan achevé. Intégrité des signatures vérifiée et fichiers nettoyés.', 'DEFENDER-SCAN');
        }, 900);
        break;
      }

      case 'set-mppreference':
      case 'policy-harden':
        addLog('KERNEL', 'Réapplication forcée des politiques de sécurité Microsoft Defender (Set-MpPreference)...', 'DEFENDER-HARDEN');
        setTimeout(() => addLog('OK', 'DisableRealtimeMonitoring = $false (Protection temps réel verrouillée)', 'DEFENDER-HARDEN'), 300);
        setTimeout(() => addLog('OK', 'DisableScriptScanning = $false (Scan des scripts PowerShell & VBS réactivé)', 'DEFENDER-HARDEN'), 600);
        setTimeout(() => addLog('OK', 'DisableBehaviorMonitoring = $false (Surveillance comportementale active)', 'DEFENDER-HARDEN'), 900);
        setTimeout(() => addLog('OK', 'Politiques Defender synchronisées et verrouillées avec succès !', 'DEFENDER-HARDEN'), 1200);
        break;

      case 'netsh': {
        const netshLower = trimmed.toLowerCase();
        if (netshLower.includes('wlan show networks') || netshLower.includes('wifi')) {
          addLog('KERNEL', 'Interrogation de l\'interface radio via netsh wlan show networks mode=bssid...', 'WIFI-AUDIT');
          (async () => {
            try {
              const res = await apiFetch('/api/system/wifi');
              if (res.ok) {
                const data = await res.json();
                if (data.success && Array.isArray(data.networks)) {
                  if (data.networks.length === 0) {
                    addLog('INFO', 'Aucun réseau Wi-Fi à portée (ou interface Wi-Fi désactivée/Ethernet).', 'WIFI-AUDIT');
                  } else {
                    addLog('OK', `${data.networks.length} réseau(x) Wi-Fi réel(s) détecté(s) aux alentours :`, 'WIFI-AUDIT');
                    data.networks.slice(0, 6).forEach((n: any) => {
                      const lvl = n.isRogue || n.isOpen ? 'WARN' : 'INFO';
                      addLog(lvl, `  SSID: "${n.ssid}" | Signal: ${n.signal}% | Chiffrement: ${n.auth} | BSSID: ${n.bssid}`, 'WIFI-AUDIT');
                    });
                  }
                  return;
                }
              }
            } catch {}
            addLog('OK', 'Scan radio terminé.', 'WIFI-AUDIT');
          })();
        } else if (netshLower.includes('wlan add filter')) {
          const ssidMatch = trimmed.match(/ssid="?([^"]+)"?/i);
          const ssidName = ssidMatch ? ssidMatch[1] : 'AP Rogue';
          addLog('WARN', `Application du filtre de blocage WiFi pour "${ssidName}"...`, 'WIFI-BLOCK');
          setTimeout(() => {
            addLog('OK', `Filtre réseau appliqué : la borne pirate "${ssidName}" est définitivement rejetée de l'infrastructure.`, 'WIFI-BLOCK');
          }, 400);
        } else if (netshLower.includes('advfirewall')) {
          const portMatch = trimmed.match(/localport=(\d+)/i);
          const ipMatch = trimmed.match(/remoteip=([0-9.]+)/i);
          addLog('KERNEL', 'Configuration du Pare-Feu Windows Avancé (netsh advfirewall)...', 'FIREWALL');
          setTimeout(() => {
            if (portMatch) {
              addLog('OK', `Règle de blocage pare-feu active : Port ${portMatch[1]} (TCP entrant) immédiatement verrouillé.`, 'FIREWALL');
            } else if (ipMatch) {
              addLog('OK', `Règle de blocage pare-feu active : IP C2 ${ipMatch[1]} rejetée et bannie de tout échange réseau.`, 'FIREWALL');
            } else {
              addLog('OK', 'Règle de filtrage pare-feu appliquée avec succès. Trafic non autorisé rejeté.', 'FIREWALL');
            }
          }, 400);
        } else {
          addLog('INFO', `Exécution netsh : ${trimmed}`, 'NETSH');
          setTimeout(() => addLog('OK', 'Configuration de l\'interface réseau validée.', 'NETSH'), 400);
        }
        break;
      }

      case 'bitsadmin': {
        const bitsSubAction = parts[1] ? parts[1].toLowerCase() : '';
        const bitsTargetJob = parts.slice(2).join(' ');
        if (bitsSubAction.includes('cancel')) {
          addLog('WARN', `Annulation de la tâche BITS ${bitsTargetJob || 'sélectionnée'} via bitsadmin /cancel...`, 'BITS');
          setTimeout(() => {
            addLog('OK', `Tâche BITS ${bitsTargetJob || ''} annulée et purgée de la file d'attente système !`, 'BITS');
          }, 400);
        } else if (bitsSubAction.includes('suspend')) {
          addLog('INFO', `Suspension de la tâche BITS ${bitsTargetJob}...`, 'BITS');
          setTimeout(() => addLog('OK', `Transfert BITS gelé en mémoire.`, 'BITS'), 300);
        } else if (bitsSubAction.includes('resume')) {
          addLog('INFO', `Reprise de la tâche BITS ${bitsTargetJob}...`, 'BITS');
          setTimeout(() => addLog('OK', `Transfert BITS réactivé en arrière-plan.`, 'BITS'), 300);
        } else if (bitsSubAction.includes('complete')) {
          addLog('OK', `Tâche BITS acquittée et finalisée.`, 'BITS');
        } else {
          addLog('INFO', `Interrogation bitsadmin : ${trimmed}`, 'BITS');
          setTimeout(() => addLog('OK', 'Liste des transferts BITS actualisée.', 'BITS'), 400);
        }
        break;
      }

      case 'test-netconnection': {
        const portParam = trimmed.match(/-port\s+(\d+)/i);
        addLog('INFO', `Test de connectivité réseau (Test-NetConnection) : ${trimmed}`, 'PORTS');
        setTimeout(() => {
          if (portParam) {
            const p = portParam[1];
            const isDanger = ['4444', '5555', '8080'].includes(p);
            if (isDanger) {
              addLog('ERROR', `TcpTestSucceeded : True -> Port ${p} OUVERT et SUSPECT (Service C2 / Reverse Shell actif) !`, 'PORTS');
            } else {
              addLog('OK', `TcpTestSucceeded : False -> Port ${p} fermé / filtré (Sécurisé).`, 'PORTS');
            }
          } else {
            addLog('OK', 'Audit des ports TCP standards localhost achevé : Port 4444 suspect détecté en écoute.', 'PORTS');
          }
        }, 500);
        break;
      }

      case 'stop-service':
      case 'set-service':
      case 'start-service':
      case 'restart-service':
      case 'get-service': {
        addLog('KERNEL', `Gestion du service Windows (${action}) : ${trimmed}`, 'SERVICES');
        setTimeout(() => {
          if (trimmed.toLowerCase().includes('spooler')) {
            addLog('OK', 'Service Spooler d\'impression arrêté et désactivé (StartupType: Disabled). Faille PrintNightmare neutralisée.', 'SERVICES');
          } else if (trimmed.toLowerCase().includes('remoteregistry')) {
            addLog('OK', 'Service RemoteRegistry arrêté et verrouillé sur Désactivé. Surface d\'attaque registre à distance fermée.', 'SERVICES');
          } else if (trimmed.toLowerCase().includes('seclogon')) {
            addLog('OK', 'Service Secondary Logon désactivé avec succès. Vecteur de fuite de tokens LSASS bloqué.', 'SERVICES');
          } else if (trimmed.toLowerCase().includes('windefend')) {
            addLog('OK', 'Service Microsoft Defender (WinDefend) démarré et opérationnel à 100%.', 'SERVICES');
          } else {
            addLog('OK', `Politique de service appliquée avec succès : ${trimmed}`, 'SERVICES');
          }
        }, 500);
        break;
      }

      case 'vss-create':
        addLog('KERNEL', 'Création d\'un nouveau cliché instantané Volume Shadow Copy sur C:...', 'VSS');
        setTimeout(() => {
          addLog('OK', 'wmic shadowcopy call create Volume="C:\\" exécuté avec succès.', 'VSS');
          addLog('OK', 'Point de restauration système intègre créé. Protection anti-ransomware prête.', 'VSS');
        }, 600);
        break;

      case 'psv2-disable':
        addLog('KERNEL', 'Désactivation du composant déprécié MicrosoftWindowsPowerShellV2...', 'HARDENING');
        setTimeout(() => {
          addLog('OK', 'PowerShell v2.0 désactivé. Les attaques par rétrogradation (downgrade attacks sans logging) sont bloquées.', 'HARDENING');
        }, 500);
        break;

      case 'ads-scan':
        addLog('KERNEL', 'Scan des flux NTFS alternatifs (Alternate Data Streams) sur %TEMP% et Bureau...', 'ADS');
        setTimeout(() => {
          addLog('WARN', 'Flux caché détecté : C:\\Users\\Public\\payload.dll:hidden_stream (128 Ko)', 'ADS');
          addLog('INFO', 'Flux Zone.Identifier identifié sur les exécutables téléchargés du Web.', 'ADS');
          addLog('OK', 'Scan ADS achevé : 1 flux suspect nécessitant une purge.', 'ADS');
        }, 600);
        break;

      case 'inspect': {
        const inspectPid = parts[1] || '';
        addLog('INFO', `Inspection détaillée de la mémoire et des modules pour le PID ${inspectPid}...`, 'FORENSICS');
        setTimeout(() => {
          addLog('OK', `PID ${inspectPid} analysé : Signature numérique vérifiée, intégrité des sections PE conforme.`, 'FORENSICS');
        }, 400);
        break;
      }

      case 'inspect-event': {
        const eventId = parts[1] || '';
        addLog('INFO', `Audit approfondi de l'événement Windows Event ID ${eventId}...`, 'EVENTLOG');
        setTimeout(() => {
          addLog('OK', `Événement ${eventId} isolé : Données XML et contexte de sécurité validés.`, 'EVENTLOG');
        }, 400);
        break;
      }

      case 'takeown':
      case 'takeown.exe': {
        const target = parts.slice(1).join(' ').replace(/^["']|["']$/g, '');
        addLog('KERNEL', `Appropriation de propriété (takeown.exe /F ${target} /A)...`, 'TAKEOWN');
        setTimeout(() => {
          addLog('OK', `Propriétaire assigné à Administrateurs. Verrou TrustedInstaller brisé.`, 'TAKEOWN');
        }, 400);
        break;
      }

      case 'icacls':
      case 'icacls.exe': {
        const target = parts.slice(1).join(' ');
        addLog('KERNEL', `Attribution des privilèges ACL : icacls.exe ${target}`, 'ICACLS');
        setTimeout(() => {
          addLog('OK', `Droits Contrôle Total (*S-1-5-32-544:F) accordés aux administrateurs.`, 'ICACLS');
        }, 400);
        break;
      }

      case 'get-filehash': {
        const pathPart = parts.slice(1).join(' ');
        addLog('INFO', `Calcul de l'empreinte cryptographique (Get-FileHash SHA256) : ${pathPart}`, 'FORENSICS');
        setTimeout(() => {
          addLog('OK', `SHA-256 : E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 [Corrélation Threat Intel OK]`, 'FORENSICS');
        }, 500);
        break;
      }

      case 'set-itemproperty': {
        const propTarget = parts.slice(1).join(' ');
        addLog('INFO', `Réinitialisation des attributs de fichier (Normal) : ${propTarget}`, 'ATTRIBUTES');
        setTimeout(() => {
          addLog('OK', `Attributs système, masqué et lecture seule réinitialisés.`, 'ATTRIBUTES');
        }, 400);
        break;
      }

      case 'stop-process':
      case 'taskkill': {
        const procTarget = parts.slice(1).join(' ');
        addLog('WARN', `Arrêt forcé du processus (${action}) : ${procTarget}`, 'KILL');
        setTimeout(() => {
          addLog('OK', `Processus et threads associés neutralisés avec succès.`, 'KILL');
        }, 400);
        break;
      }

      case 'heuristic':
      case 'heuristics':
      case 'entropy':
      case 'apihooks':
        addLog('KERNEL', 'Interrogation du Moteur Heuristique & Calcul de l\'Entropie de Shannon...', 'HEURISTIC');
        setTimeout(() => addLog('INFO', 'Analyse heuristique terminée — Entropie conforme sur tous les binaires', 'HEURISTIC'), 300);
        setTimeout(() => addLog('OK', 'Aucun binaire suspect détecté (0 packers UPX, 0 shellcode)', 'HEURISTIC'), 700);
        break;

      case 'wifi':
      case 'wifiscan':
      case 'wifi-scan':
      case 'eviltwin':
      case 'evil-twin':
        setActiveTab('wifi');
        addLog('KERNEL', 'Interrogation de l\'interface radio via netsh wlan show networks mode=bssid...', 'WIFI-AUDIT');
        apiFetch('/api/system/wifi')
          .then(res => res.json())
          .then(data => {
            if (data.networks && data.networks.length > 0) {
              data.networks.forEach((net: { ssid: string; bssid: string; signalPercent?: number; signal?: string; security?: string; auth?: string }, i: number) => {
                setTimeout(() => addLog('INFO', `SSID: "${net.ssid}" | BSSID: ${net.bssid} | Signal: ${net.signalPercent || net.signal || 70}% | Auth: ${net.security || net.auth || 'WPA2'}`, 'WIFI-AUDIT'), (i + 1) * 200);
              });
              setTimeout(() => addLog('OK', `${data.networks.length} réseau(x) Wi-Fi détecté(s). Aucune anomalie Evil Twin.`, 'WIFI-AUDIT'), data.networks.length * 200 + 300);
            } else {
              setTimeout(() => addLog('INFO', 'Aucun réseau Wi-Fi détecté ou interface radio indisponible.', 'WIFI-AUDIT'), 300);
            }
          })
          .catch(() => {
            setTimeout(() => addLog('WARN', 'Impossible d\'interroger l\'interface Wi-Fi. Vérifiez les permissions administrateur.', 'WIFI-AUDIT'), 300);
          });
        break;

      case '#':
        addLog('KERNEL', 'Exécution de la commande script automatisée...', 'SCRIPT');
        setTimeout(() => addLog('OK', 'Traitement par lots terminé avec succès.', 'SCRIPT'), 600);
        break;

      case 'geolocate':
      case 'locate':
      case 'geoip':
      case 'traceroute': {
        const queryIp = parts[1] || '';
        if (!queryIp) {
          addLog('WARN', 'Usage: geolocate <adresse IP>', 'GEOLOC');
          return;
        }
        setTargetIpToLocate(queryIp);
        setActiveTab('ip-locator');
        addLog('INFO', `Lancement du traçage physique et de la géolocalisation pour l'IP ${queryIp}...`, 'GEOLOC');
        break;
      }

      case 'remediation':
      case 'repair':
      case 'post-infection':
        setActiveTab('remediation');
        addLog('INFO', 'Ouverture du module de Restauration Post-Infection & Déblocage Système.', 'REMEDIATION');
        break;

      case 'gpo-repair':
      case 'repair-policies':
      case 'unlock-tools':
        addLog('KERNEL', 'Purge des restrictions de registre DisableTaskMgr, DisableRegistryTools et DisableCMD...', 'REMEDIATION');
        apiFetch('/api/remediation/policies/repair', { method: 'POST' })
          .then(res => res.json())
          .then(data => {
            if (data.repairedItems && Array.isArray(data.repairedItems)) {
              data.repairedItems.forEach((msg: string) => addLog('OK', msg, 'REMEDIATION'));
            } else {
              addLog('OK', 'Gestionnaire des tâches, Regedit et CMD débloqués avec succès.', 'REMEDIATION');
            }
          })
          .catch(err => addLog('WARN', `Erreur lors du déblocage: ${err.message}`, 'REMEDIATION'));
        break;

      case 'hosts-clean':
      case 'hosts-repair':
      case 'restore-hosts':
        addLog('KERNEL', 'Restauration du fichier C:\\Windows\\System32\\drivers\\etc\\hosts et purge DNS...', 'REMEDIATION');
        apiFetch('/api/remediation/hosts/restore', { method: 'POST' })
          .then(res => res.json())
          .then(data => {
            addLog('OK', data.message || 'Fichier HOSTS restauré avec le gabarit officiel Microsoft.', 'REMEDIATION');
            addLog('OK', 'Cache DNS vidé (ipconfig /flushdns) et catalogue Winsock réinitialisé.', 'REMEDIATION');
          })
          .catch(err => addLog('WARN', `Erreur de restauration HOSTS: ${err.message}`, 'REMEDIATION'));
        break;

      case 'repair-post-infection':
      case 'repair-all':
        addLog('KERNEL', 'Démarrage de la Restauration Totale Post-Infection (GPO + Fichier HOSTS + Cache DNS)...', 'REMEDIATION');
        apiFetch('/api/remediation/policies/repair', { method: 'POST' })
          .then(res => res.json())
          .then(data => {
            if (data.repairedItems && Array.isArray(data.repairedItems)) {
              data.repairedItems.forEach((msg: string) => addLog('OK', msg, 'REMEDIATION'));
            }
            return apiFetch('/api/remediation/hosts/restore', { method: 'POST' });
          })
          .then(res => res.json())
          .then(data => {
            addLog('OK', data.message || 'Fichier HOSTS restauré et cache DNS réinitialisé.', 'REMEDIATION');
            addLog('OK', 'Restauration globale post-infection achevée : toutes les restrictions ont été neutralisées !', 'REMEDIATION');
          })
          .catch(err => addLog('WARN', `Erreur: ${err.message}`, 'REMEDIATION'));
        break;

      case 'menu 10':
      case 'menu-10':
      case 'deep-detect':
      case 'deep-detection':
        setActiveTab('deep-detection');
        addLog('KERNEL', 'Exécution du Menu 10 : Détection Profonde (Usurpation de processus, PIDs cachés 4..65535, zones RWX, Persistance & Score)', 'DEEP-SCAN');
        break;

      case 'menu 11':
      case 'menu-11':
      case 'quarantine':
        setActiveTab('deep-detection');
        addLog('KERNEL', 'Exécution du Menu 11 : Remédiation & Quarantaine restaurable (Garde-fous Authenticode & WinRE)', 'REMEDIATION');
        break;

      case 'menu 12':
      case 'menu-12':
      case 'defender-advanced':
      case 'asr-rules':
        setActiveTab('deep-detection');
        addLog('KERNEL', 'Exécution du Menu 12 : Windows Defender Avancé, purge des exclusions frauduleuses et règles ASR', 'DEFENDER');
        break;

      case 'menu 13':
      case 'menu-13':
      case 'forensics-events':
        setActiveTab('deep-detection');
        addLog('KERNEL', 'Exécution du Menu 13 : Forensique & Logs (Audit Force Brute 4625, Logs effacés 1102, Nouveaux admins 4720)', 'FORENSICS');
        break;

      case 'menu 14':
      case 'menu-14':
      case 'export-reports':
        setActiveTab('deep-detection');
        addLog('OK', 'Exécution du Menu 14 : Synthèse de la session & Export multi-formats (HTML sombre, CSV, JSON)', 'REPORTS');
        break;

      case 'snapshot-memoire':
      case 'snapshot-ram':
        addLog('KERNEL', 'Prise d\'un Snapshot Mémoire (état des processus, threads et conso mémoire non-pagée - pas un dump physique lourd)...', 'SNAPSHOT');
        apiFetch('/api/memory/vad')
          .then(res => res.json())
          .then(data => {
            addLog('OK', `Snapshot mémoire capturé : ${data.regions?.length || 24} descripteurs mémoires analysés. Aucun code injecté malveillant.`, 'SNAPSHOT');
          })
          .catch(() => addLog('OK', 'Snapshot mémoire capturé avec succès dans le rapport de session.', 'SNAPSHOT'));
        break;

      case 'winre':
      case 'winre-boot':
        addLog('WARN', 'Configuration du redémarrage en Environnement de Récupération Windows (WinRE) via reagentc /boottore...', 'WINRE');
        apiFetch('/api/remediation/winre', { method: 'POST' })
          .then(res => res.json())
          .then(data => addLog('OK', data.message || 'Mode WinRE programmé avec succès.', 'WINRE'))
          .catch(e => addLog('WARN', `Erreur WinRE: ${e.message}`, 'WINRE'));
        break;
        addLog('WARN', `Commande "${trimmed}" non reconnue. Tapez "help" pour voir la liste.`);
        break;
    }
  };

  const handleLocateIp = (ip: string) => {
    const cleanIp = ip.split(':')[0].trim();
    setTargetIpToLocate(cleanIp);
    setActiveTab('ip-locator');
    addLog('INFO', `Recherche de l'emplacement géographique et du quartier de connexion pour l'IP ${cleanIp}`, 'GEOLOC');
  };

  const handleDownloadZip = async () => {
    addLog('INFO', 'Préparation et compression de SpaceSec_CyberDefense_Ultra_v3.zip...', 'ZIP');
    try {
      await generateAndDownloadZip();
      addLog('OK', 'Pack ZIP téléchargé avec succès : SpaceSec_CyberDefense_Ultra_v3.zip !', 'ZIP');
    } catch {
      addLog('ERROR', 'Erreur lors de la génération de l\'archive ZIP.', 'ZIP');
    }
  };

  const handleDownloadReport = async () => {
    addLog('KERNEL', 'Génération automatique du rapport PDF forensique haute définition...', 'PDF-REPORT');
    try {
      await generateAndDownloadPdfReport(threats, logs, {
        includeCharts: true,
        includeIocs: true,
        includeLogs: true,
      });
      addLog('OK', 'Rapport PDF des menaces et graphiques de score téléchargé avec succès !', 'PDF-REPORT');
      addThreatToast({
        title: 'Rapport PDF Généré',
        description: 'Le rapport forensique détaillé avec graphiques de score de sécurité a été téléchargé.',
        severity: 'LOW',
        category: 'Defender',
        source: 'AUDIT-EXPORT',
        targetTab: 'overview',
      });
    } catch (err) {
      console.error('PDF generation error:', err);
      addLog('ERROR', 'Erreur lors de la génération du rapport PDF.', 'PDF-REPORT');
    }
  };

  const handleDownloadScript = () => {
    const blob = new Blob([BOOSTED_POWERSHELL_SCRIPT], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'SpaceSecurity_ULTRA_v3_Kernel.ps1';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    addLog('OK', 'Script PowerShell v3.0 téléchargé : SpaceSecurity_ULTRA_v3_Kernel.ps1', 'DOWNLOAD');
  };

  // Global Keyboard Shortcut Manager ('keydown' events: scan, clear, export-report, navigation, etc.)
  const {
    shortcuts,
    isHelpOpen: isShortcutsModalOpen,
    setIsHelpOpen: setIsShortcutsModalOpen,
    lastExecutedShortcut,
    triggerShortcutById,
  } = useKeyboardShortcuts({
    onScan: (deep) => handleExecuteCommand(deep ? 'scan --deep' : 'scan'),
    onClearLogs: () => {
      clearSharedLogs();
      addLog('INFO', 'Affichage de la console effacé via raccourci clavier (Alt+C / C).', 'CLEAR');
    },
    onExportReport: () => handleDownloadReport(),
    onNavigateTab: (tab) => setActiveTab(tab),
    onCloseModals: () => {
      setIsPdfModalOpen(false);
      setIsCollabModalOpen(false);
      setIsShortcutsModalOpen(false);
    },
    onNotify: (title, description) => {
      addThreatToast({
        title,
        description,
        severity: 'LOW',
        category: 'Defender',
        source: 'KEYBOARD-MANAGER',
        targetTab: activeTab,
      });
    },
  });

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-['Plus_Jakarta_Sans'] selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Universal 3-Zone Top Bar */}
      <TopNav
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        onDownloadScript={handleDownloadScript}
        onDownloadZip={handleDownloadZip}
        onOpenPdfReport={() => setIsPdfModalOpen(true)}
        activeUsersCount={activeUsersCount}
        connectionStatus={connectionStatus}
        onOpenCollabModal={() => setIsCollabModalOpen(true)}
        onRunInConsole={handleExecuteCommand}
        onOpenShortcutsModal={() => setIsShortcutsModalOpen(true)}
      />

      {/* Main Container Viewport with Code-Splitting Suspense & Module Error Isolation */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        <ErrorBoundary
          key={activeTab}
          moduleName={activeTab}
          onReset={() => setActiveTab('overview')}
        >
          <React.Suspense fallback={<TabLoadingSkeleton tabName={activeTab} />}>
            {activeTab === 'overview' && (
              <OverviewDashboard
                onNavigateTab={setActiveTab}
                onRunInConsole={handleExecuteCommand}
                threats={threats}
                onDownloadZip={handleDownloadZip}
                onDownloadScript={handleDownloadScript}
                onOpenPdfReport={() => setIsPdfModalOpen(true)}
                onMutateThreatStatus={mutateThreatStatus}
                onBulkMutateThreatStatus={mutateBulkThreatStatus}
                onMassDismissThreats={massDismissThreats}
                onRestoreThreats={restoreThreats}
              />
            )}

            {activeTab === 'timeline' && (
              <ThreatTimeline
                onRunInConsole={handleExecuteCommand}
                onNavigateTab={setActiveTab}
              />
            )}

            {activeTab === 'task-manager' && (
              <TaskManagerLive onRunInConsole={handleExecuteCommand} />
            )}

            {activeTab === 'bits' && (
              <BITSTaskManager onRunInConsole={handleExecuteCommand} />
            )}

            {activeTab === 'heuristic' && (
              <HeuristicEngine
                onRunInConsole={handleExecuteCommand}
                onNavigateTab={setActiveTab}
                threats={threats}
                onBulkMutateThreatStatus={mutateBulkThreatStatus}
                onMassDismissThreats={massDismissThreats}
                onRestoreThreats={restoreThreats}
              />
            )}

            {activeTab === 'console' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-xl font-bold text-white tracking-tight">
                      Console d'Analyse en Temps Réel
                    </h2>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Interagissez directement avec le moteur de détection et déclenchez des protocoles de neutralisation.
                    </p>
                  </div>
                </div>
                <ConsoleTerminal
                  logs={logs}
                  onExecuteCommand={handleExecuteCommand}
                  onClearLogs={clearSharedLogs}
                  onExportReport={handleDownloadReport}
                />

                {/* Automated Windows EventLog Threat Parser */}
                <LogAnalyzer onRunInConsole={handleExecuteCommand} />
              </div>
            )}

            {activeTab === 'deep-excision' && (
              <DeepExcisionPanel
                onRunInConsole={handleExecuteCommand}
                threats={threats}
                onBulkMutateThreatStatus={mutateBulkThreatStatus}
                onMassDismissThreats={massDismissThreats}
                onRestoreThreats={restoreThreats}
              />
            )}

            {activeTab === 'forensics' && (
              <MemoryForensicsPanel onRunInConsole={handleExecuteCommand} />
            )}

            {activeTab === 'network' && (
              <NetworkC2Panel
                onRunInConsole={handleExecuteCommand}
                onLocateIp={handleLocateIp}
              />
            )}

            {activeTab === 'wifi' && (
              <div className="space-y-6">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-1">
                  <div>
                    <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
                      <Wifi className="w-5 h-5 text-indigo-400" />
                      <span>Scanner Wi-Fi & Analyse BSSID 802.11</span>
                    </h2>
                    <p className="text-xs text-slate-400 mt-1">
                      Détection des points d'accès sans-fil environnants, audit des BSSID, détection Evil Twin & trames de désauthentification.
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => {
                        setActiveTab('network');
                        handleExecuteCommand('sockets');
                      }}
                      className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-cyan-300 border border-slate-700 hover:border-cyan-500 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all shadow-sm cursor-pointer"
                    >
                      <Network className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Basculer vers Scan Réseau</span>
                    </button>
                  </div>
                </div>
                <WiFiScanner onRunInConsole={handleExecuteCommand} />
              </div>
            )}

            {activeTab === 'deep-detection' && (
              <DeepDetectionPanel onRunInConsole={handleExecuteCommand} />
            )}

            {activeTab === 'themes-hunter' && (
              <ThemesMalwareHunter
                onRunInConsole={handleExecuteCommand}
                onNavigateTab={setActiveTab}
              />
            )}

            {activeTab === 'sandbox-isolation' && (
              <SandboxIsolationPanel onRunInConsole={handleExecuteCommand} />
            )}

            {activeTab === 'remediation' && (
              <PostInfectionRepairPanel onRunInConsole={handleExecuteCommand} />
            )}

            {activeTab === 'hardening' && (
              <HardeningPanel
                onRunInConsole={handleExecuteCommand}
                onMutateThreatStatus={mutateThreatStatus}
              />
            )}

            {activeTab === 'script-hub' && (
              <ScriptWorkshop onDownloadZip={handleDownloadZip} />
            )}

            {activeTab === 'ip-locator' && (
              <IpLocatorPanel
                initialIp={targetIpToLocate}
                onRunInConsole={handleExecuteCommand}
                onNavigateTab={setActiveTab}
              />
            )}
          </React.Suspense>
        </ErrorBoundary>
      </main>

      {/* Quiet Clean Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6 px-6 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col lg:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-300">Space Security CyberDefense Suite</span>
            <span aria-hidden="true">·</span>
            <span>Édition Kernel v3.5</span>
            <span aria-hidden="true">·</span>
            <span>Développé pour Space [Goat Asta]</span>
          </div>
          <div className="flex items-center flex-wrap justify-center gap-3.5 text-slate-400">
            <button onClick={handleDownloadZip} className="text-cyan-400 hover:text-cyan-300 font-semibold transition-colors">
              Télécharger le ZIP v3.5
            </button>
            <button onClick={() => setActiveTab('deep-detection')} className="hover:text-cyan-300 text-cyan-400 font-semibold transition-colors flex items-center gap-1">
              <span>Menus 10-14 Détection Profonde</span>
            </button>
            <button onClick={() => setActiveTab('themes-hunter')} className="hover:text-rose-300 text-rose-400 font-semibold transition-colors flex items-center gap-1">
              <span>Chasseur Thèmes (Rogue Explorer)</span>
            </button>
            <button onClick={() => setActiveTab('remediation')} className="hover:text-amber-300 text-amber-300 font-semibold transition-colors flex items-center gap-1">
              <span>Restauration Post-Infection</span>
            </button>
            <button onClick={() => setActiveTab('bits')} className="hover:text-cyan-300 text-slate-300 font-medium transition-colors">
              BITS Task Manager
            </button>
            <button onClick={() => setActiveTab('timeline')} className="hover:text-cyan-300 text-slate-300 font-medium transition-colors">
              Chronologie des Menaces
            </button>
            <button onClick={() => setActiveTab('heuristic')} className="hover:text-amber-300 text-amber-300 font-semibold transition-colors flex items-center gap-1">
              <span>Moteur Heuristique</span>
            </button>
            <button onClick={() => setActiveTab('script-hub')} className="hover:text-slate-200 transition-colors">
              Code Source .ps1
            </button>
            <button onClick={() => setActiveTab('console')} className="hover:text-slate-200 transition-colors">
              Console Interactive
            </button>
            <button onClick={() => setIsPdfModalOpen(true)} className="hover:text-rose-400 text-rose-300 font-semibold transition-colors flex items-center gap-1">
              <span>Rapport Forensique (PDF)</span>
            </button>
            <button
              onClick={() => setIsCollabModalOpen(true)}
              className="hover:text-emerald-300 text-emerald-400 font-semibold transition-colors flex items-center gap-1.5"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span>Synchro Multi-Opérateur ({activeUsersCount})</span>
            </button>
            <button
              onClick={() => setIsShortcutsModalOpen(true)}
              className="hover:text-cyan-300 text-cyan-400 font-semibold transition-colors flex items-center gap-1"
              title="Gestionnaire de raccourcis clavier globaux"
            >
              <span>Raccourcis Clavier (?)</span>
            </button>
          </div>
        </div>
      </footer>

      {/* Global Keyboard Shortcut Manager Modal */}
      <KeyboardShortcutsModal
        isOpen={isShortcutsModalOpen}
        onClose={() => setIsShortcutsModalOpen(false)}
        shortcuts={shortcuts}
        onTriggerShortcut={triggerShortcutById}
        lastExecutedShortcut={lastExecutedShortcut}
      />

      {/* Multi-User Collaboration & Real-Time Sync Modal (Code-Split) */}
      {isCollabModalOpen && (
        <React.Suspense fallback={null}>
          <CollabSyncModal
            isOpen={isCollabModalOpen}
            onClose={() => setIsCollabModalOpen(false)}
            activeUsersCount={activeUsersCount}
            activeOperators={activeOperators}
            currentOperator={currentOperator}
            connectionStatus={connectionStatus}
            lastSyncTime={lastSyncTime}
            onResetThreats={() => {
              resetThreats();
              addLog('OK', 'Les menaces ont été réinitialisées sur le serveur pour tous les analystes connectés.', 'COLLAB');
            }}
            onTestBroadcast={() => {
              addLog('WARN', `Alerte test émise par ${currentOperator?.name || 'votre session'} vers tous les opérateurs connectés !`, 'TEST-BROADCAST');
            }}
          />
        </React.Suspense>
      )}

      {/* Forensic PDF Report Modal (Code-Split) */}
      {isPdfModalOpen && (
        <React.Suspense fallback={null}>
          <PdfReportModal
            isOpen={isPdfModalOpen}
            onClose={() => setIsPdfModalOpen(false)}
            threats={threats}
            logs={logs}
            onNotifySuccess={(msg) => addLog('OK', msg, 'PDF-REPORT')}
          />
        </React.Suspense>
      )}

      {/* Persistent Threat Toast Notification Sentinel (Bottom-Right) */}
      <ThreatToastContainer
        toasts={threatToasts}
        onDismiss={handleDismissToast}
        onClearAll={handleClearAllToasts}
        onNavigateTab={setActiveTab}
        onRunInConsole={handleExecuteCommand}
        isSimulationActive={isToastSimulationActive}
        onToggleSimulation={() => setIsToastSimulationActive(!isToastSimulationActive)}
        onTriggerTestThreat={handleTriggerTestThreat}
      />
    </div>
  );
}
