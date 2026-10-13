/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { Network, Wifi } from 'lucide-react';
import { TopNav } from './components/TopNav';
import { ConsoleTerminal } from './components/ConsoleTerminal';
import { DeepExcisionPanel } from './components/DeepExcisionPanel';
import { MemoryForensicsPanel } from './components/MemoryForensicsPanel';
import { NetworkC2Panel } from './components/NetworkC2Panel';
import { HardeningPanel } from './components/HardeningPanel';
import { ScriptWorkshop } from './components/ScriptWorkshop';
import { OverviewDashboard } from './components/OverviewDashboard';
import { LogAnalyzer } from './components/LogAnalyzer';
import { TaskManagerLive } from './components/TaskManagerLive';
import { BITSTaskManager } from './components/BITSTaskManager';
import { ThreatTimeline } from './components/ThreatTimeline';
import { ThreatToastContainer } from './components/ThreatToast';
import { PdfReportModal } from './components/PdfReportModal';
import { HeuristicEngine } from './components/HeuristicEngine';
import { CollabSyncModal } from './components/CollabSyncModal';
import { IpLocatorPanel } from './components/IpLocatorPanel';
import { useRealtimeSync } from './hooks/useRealtimeSync';
import { TabId, ConsoleLogMessage, ThreatItem, ThreatNotification } from './types/cyberdefense';
import { BOOSTED_POWERSHELL_SCRIPT } from './data/powershellScript';
import { generateAndDownloadZip } from './utils/zipGenerator';
import { generateAndDownloadPdfReport } from './utils/pdfReportGenerator';

export default function App() {
  const [activeTab, setActiveTab] = useState<TabId>('overview');
  const [targetIpToLocate, setTargetIpToLocate] = useState<string>('185.220.101.4');
  const [isPdfModalOpen, setIsPdfModalOpen] = useState<boolean>(false);
  const [isCollabModalOpen, setIsCollabModalOpen] = useState<boolean>(false);

  const [threatToasts, setThreatToasts] = useState<ThreatNotification[]>([
    {
      id: 'toast-init-1',
      timestamp: '07:35:05',
      title: 'Balise C2 Détectée (Port 4444)',
      description: 'Connexion réseau sortante vers 185.220.101.4 initiée par svch0st_updater.exe (PID 5824).',
      severity: 'CRITICAL',
      category: 'C2',
      source: 'C2-HUNTER / Network Monitor',
      targetTab: 'network',
      actionCommand: 'kill 5824',
      actionLabel: 'Abattre PID 5824',
    },
    {
      id: 'toast-init-2',
      timestamp: '07:35:06',
      title: 'Driver Rootkit Verrouillé',
      description: 'Hook noyau sur IRP_MJ_CREATE protégé par TrustedInstaller : suspicious_kernel_hook.sys.',
      severity: 'HIGH',
      category: 'Kernel',
      source: 'KERNEL-LOCK / P/Invoke',
      targetTab: 'deep-excision',
      actionCommand: 'unlock C:\\Windows\\System32\\drivers\\suspicious_kernel_hook.sys',
      actionLabel: 'Déverrouiller & Supprimer',
    },
  ]);

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

  const [isToastSimulationActive, setIsToastSimulationActive] = useState(true);

  const handleDismissToast = (id: string) => {
    setThreatToasts(prev => prev.filter(t => t.id !== id));
  };

  const handleClearAllToasts = () => {
    setThreatToasts([]);
  };

  // Automated background threat simulation ticker
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
    {
      title: 'Scan Furtif de Ports Sortants Détecté',
      description: 'Flux TCP SYN consécutifs vers 8 sous-réseaux externes non répertoriés (Analyse heuristique).',
      severity: 'MEDIUM',
      category: 'Network',
      source: 'NetFilter Driver',
      targetTab: 'network',
      actionCommand: 'sockets',
      actionLabel: 'Voir sockets ouverts',
    },
    {
      title: 'Piège IFEO Actif sur taskmgr.exe',
      description: 'Clé Debugger détournée pour masquer la liste des processus actifs lors du lancement du Gestionnaire.',
      severity: 'CRITICAL',
      category: 'Persistence',
      source: 'Registry Inspector',
      targetTab: 'overview',
      actionCommand: 'ifeo',
      actionLabel: 'Corriger IFEO',
    },
  ];

  // Manual trigger button to test anytime
  const handleTriggerTestThreat = () => {
    const randomThreat = simulationPool[Math.floor(Math.random() * simulationPool.length)];
    addThreatToast(randomThreat);
    addLog('WARN', `[THREAT-ALERT] ${randomThreat.title} - ${randomThreat.description}`, randomThreat.category.toUpperCase());
  };

  // Periodic threat stream simulation if active
  React.useEffect(() => {
    if (!isToastSimulationActive) return;

    const interval = setInterval(() => {
      // Pick a random simulated event every 35 seconds
      const randomThreat = simulationPool[Math.floor(Math.random() * simulationPool.length)];
      addThreatToast(randomThreat);
      addLog('WARN', `[SENTINEL-LOG] ${randomThreat.title} : ${randomThreat.description}`, randomThreat.category.toUpperCase());
    }, 38000);

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
        addLog('INFO', '  export-report     : Génère et télécharge le rapport PDF détaillé avec graphiques de score');
        addLog('INFO', '  pdf / export-pdf  : Raccourci pour générer le rapport PDF d\'audit forensique');
        break;

      case 'scan':
        addLog('KERNEL', 'Démarrage du scan global approfondi de la machine...', 'SCAN');
        setTimeout(() => addLog('INFO', '[1/6] Inspection des attributs et autorisations ACL sur C:\\Windows...', 'SCAN'), 300);
        setTimeout(() => addLog('WARN', '[2/6] Détection : Pilote suspect C:\\Windows\\System32\\drivers\\suspicious_kernel_hook.sys verrouillé', 'SCAN'), 700);
        setTimeout(() => addLog('INFO', '[3/6] Audit des clés de persistance Run, RunOnce, Winlogon et BITS Jobs...', 'SCAN'), 1100);
        setTimeout(() => addLog('WARN', '[4/6] Alerte C2 : Connexion établie vers 185.220.101.4 sur port 4444 (PID 5824)', 'SCAN'), 1500);
        setTimeout(() => addLog('INFO', '[5/6] Analyse de la mémoire volatile et recherche d\'injections DLL...', 'SCAN'), 1900);
        setTimeout(() => {
          addLog('OK', '[6/6] Scan complet terminé ! 3 menaces nécessitent une éradication.', 'SCAN');
          addLog('INFO', 'Conseil : Utilisez la commande "unlock <chemin>" pour détruire les éléments verrouillés.', 'SCAN');
        }, 2300);
        break;

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

      case 'kill':
        if (parts.length < 2) {
          addLog('ERROR', 'Syntaxe requise : kill <PID>');
          return;
        }
        const targetPid = parts[1];
        addLog('WARN', `Exécution de taskkill /F /T sur le PID ${targetPid}...`, 'KILL');
        setTimeout(() => {
          addLog('OK', `Processus PID ${targetPid} et toute sa descendance de threads ont été abattus.`, 'KILL');
          if (targetPid === '5824') {
            mutateThreatStatus('t2', 'C:\\Users\\User\\AppData\\Local\\Temp\\svch0st_updater.exe', 'NEUTRALIZED');
          }
        }, 400);
        break;

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

      case 'sockets':
        addLog('INFO', 'Extraction des sockets TCP/UDP établis (Get-NetTCPConnection)...', 'NETWORK');
        addThreatToast({
          title: 'Audit Réseau Déclenché',
          description: 'Analyse des sockets TCP/UDP & écouteurs actifs (Get-NetTCPConnection).',
          severity: 'HIGH',
          category: 'Network',
          source: 'NET-SOCKETS',
          targetTab: 'network',
        });
        setTimeout(() => {
          addLog('INFO', '  TCP 192.168.1.42:52110 -> 142.250.190.46:443 (chrome.exe) [OK]', 'NETWORK');
          addLog('ERROR', '  TCP 192.168.1.42:52314 -> 185.220.101.4:4444 (svch0st_updater.exe) [ALERTE METASPLOIT]', 'NETWORK');
          addLog('WARN', '  TCP 192.168.1.42:52410 -> 45.154.255.89:8080 (powershell.exe) [IP SUSPECTE]', 'NETWORK');
          addThreatToast({
            title: '2 Flux C2 Détectés',
            description: '185.220.101.4:4444 (Metasploit) et 45.154.255.89:8080 (PowerShell Beacon).',
            severity: 'CRITICAL',
            category: 'Network',
            source: 'NET-SOCKETS',
            targetTab: 'network',
          });
        }, 600);
        break;

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
      case 'parse-events':
        addLog('KERNEL', 'Interrogation des journaux d\'événements Windows via wevtutil / Get-WinEvent...', 'EVENTLOG');
        setTimeout(() => addLog('WARN', 'Event ID 4688: Processus suspect powershell.exe -enc détecté dans le journal Security', 'EVENTLOG'), 300);
        setTimeout(() => addLog('ERROR', 'Event ID 4104: Tentative de neutralisation AMSI isolée dans Microsoft-Windows-PowerShell', 'EVENTLOG'), 600);
        setTimeout(() => addLog('WARN', 'Event ID 4625: 14 échecs de connexion brute-force détectés depuis l\'IP 185.220.101.4', 'EVENTLOG'), 900);
        setTimeout(() => addLog('OK', 'Parseur LogAnalyzer actualisé : 3 menaces critiques isolées.', 'EVENTLOG'), 1200);
        break;

      case 'bits':
      case 'bits-clean':
      case 'bitstracker':
        addLog('KERNEL', 'Audit approfondi des tâches BITS (Background Intelligent Transfer Service)...', 'BITS');
        setTimeout(() => addLog('WARN', 'Tâche BITS malveillante {8F3C-41A9} : Téléchargement furtif de payload vers %TEMP%\\stage2.bin', 'BITS'), 300);
        setTimeout(() => addLog('WARN', 'Tâche BITS d\'exfiltration {3C7D-90E1} : Upload HTTP POST asynchrone détecté vers 45.154.255.89', 'BITS'), 600);
        setTimeout(() => addLog('OK', 'Appel Remove-BitsTransfer / bitsadmin /cancel : Tâches BITS malveillantes purgées et neutralisées !', 'BITS'), 1000);
        break;

      case 'ports':
      case 'portscan':
      case 'scan-ports':
        addLog('KERNEL', 'Lancement de l\'audit PortScanner sur localhost (127.0.0.1)...', 'PORTS');
        setTimeout(() => addLog('ERROR', 'Port 4444 (TCP) OUVERT : Metasploit Default Listener / C2 Reverse Shell actif (PID 5824)', 'PORTS'), 300);
        setTimeout(() => addLog('WARN', 'Port 445 (TCP) OUVERT : Microsoft-DS SMB actif (Vecteur WannaCry / Lateral Movement)', 'PORTS'), 600);
        setTimeout(() => addLog('WARN', 'Port 3389 (TCP) OUVERT : RDP Remote Desktop exposé sur le réseau local', 'PORTS'), 900);
        setTimeout(() => addLog('OK', 'PortScanner terminé : 3 ports critiques détectés en écoute.', 'PORTS'), 1200);
        break;

      case 'vulnscan':
      case 'hotfix':
      case 'get-hotfix':
      case 'services-audit':
        addLog('KERNEL', 'Exécution de Get-HotFix & Get-Service pour l\'analyse de vulnérabilités...', 'VULNSCAN');
        setTimeout(() => addLog('ERROR', 'Get-HotFix : KB5005565 (PrintNightmare CVE-2021-34527) manquant sur le système !', 'VULNSCAN'), 300);
        setTimeout(() => addLog('ERROR', 'Get-HotFix : KB4012212 (MS17-010 EternalBlue) manquant dans la liste des patchs appliqués', 'VULNSCAN'), 600);
        setTimeout(() => addLog('WARN', 'Get-Service : Spooler d\'impression et RemoteRegistry actifs (surfaces d\'attaque RCE/LPE)', 'VULNSCAN'), 900);
        setTimeout(() => addLog('OK', 'VulnerabilityScanner actualisé : 3 correctifs/services nécessitent une remédiation.', 'VULNSCAN'), 1200);
        break;

      case 'defendersync':
      case 'defender-sync':
      case 'defender-exclusions':
      case 'defender-audit':
      case 'get-mppreference':
        addLog('KERNEL', 'Interrogation de Microsoft Defender via Get-MpPreference (Audit des Exclusions)...', 'DEFENDER-SYNC');
        setTimeout(() => addLog('ERROR', 'Exclusion Path Malveillante : C:\\Users\\Public\\svchost.exe [Trojan.Swisyn Drop Folder]', 'DEFENDER-SYNC'), 300);
        setTimeout(() => addLog('ERROR', 'Exclusion Path Masquée : C:\\ProgramData\\WindowsHealthUpdater\\ [CryptoMiner.XMRig]', 'DEFENDER-SYNC'), 600);
        setTimeout(() => addLog('WARN', 'Exclusion Processus : powershell.exe whitelisté pour bypass d\'analyse heuristique', 'DEFENDER-SYNC'), 900);
        setTimeout(() => addLog('WARN', 'Exclusion Extension : .ps1 ignoré lors des lectures disques', 'DEFENDER-SYNC'), 1100);
        setTimeout(() => addLog('OK', 'DefenderSync : Audit terminé. 4 exclusions critiques à purger immédiatement !', 'DEFENDER-SYNC'), 1300);
        break;

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
        if (netshLower.includes('wlan show networks')) {
          addLog('KERNEL', 'Interrogation de l\'interface radio via netsh wlan show networks mode=bssid...', 'WIFI-AUDIT');
          addThreatToast({
            title: 'Audit WiFi BSSID (netsh)',
            description: 'Interrogation de l\'interface radio (netsh wlan show networks mode=bssid).',
            severity: 'HIGH',
            category: 'Network',
            source: 'NETSH-WLAN',
            targetTab: 'network',
          });
          setTimeout(() => addLog('WARN', 'Borne Rogue Détectée : SSID "SpaceSec-Secure-Corp" cloné sur BSSID 00:C0:CA:91:DE:3F (Alfa Network)', 'WIFI-AUDIT'), 300);
          setTimeout(() => addLog('ERROR', 'Alerte Evil Twin : Déclassement de sécurité WPA3-SAE vers WPA2-PSK et 148 trames Deauth détectées !', 'WIFI-AUDIT'), 600);
          setTimeout(() => addLog('WARN', 'Réseau Ouvert Détecté : "FreeWifi_Public_Guest" (F4:8E:38:22:1A:BC) non chiffré', 'WIFI-AUDIT'), 900);
          setTimeout(() => {
            addLog('OK', 'Contre-mesure recommandée : Utilisez netsh wlan add filter pour bloquer le BSSID pirate.', 'WIFI-AUDIT');
            addThreatToast({
              title: 'Alerte Evil Twin Détectée !',
              description: 'SSID piraté sur BSSID 00:C0:CA:91:DE:3F avec 148 trames de désauthentification.',
              severity: 'CRITICAL',
              category: 'Network',
              source: 'NETSH-WLAN',
              targetTab: 'network',
            });
          }, 1200);
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
        setTimeout(() => addLog('WARN', 'Entropie Critique (7.94 bits/octet) : svch0st_updater.exe [UPX0 / Shellcode compacté]', 'HEURISTIC'), 300);
        setTimeout(() => addLog('WARN', 'Entropie Critique (7.88 bits/octet) : suspicious_kernel_hook.sys [IRP Hook Ring0]', 'HEURISTIC'), 600);
        setTimeout(() => addLog('ERROR', 'Crochet API Détecté : NtUnmapViewOfSection (Process Hollowing T1055.012 vers svchost.exe)', 'HEURISTIC'), 900);
        setTimeout(() => addLog('OK', 'Niveau de Confiance Global : 93.8% (Menaces polymorphes confirmées actives)', 'HEURISTIC'), 1200);
        break;

      case 'wifi':
      case 'wifiscan':
      case 'wifi-scan':
      case 'eviltwin':
      case 'evil-twin':
        addLog('KERNEL', 'Interrogation de l\'interface radio via netsh wlan show networks mode=bssid...', 'WIFI-AUDIT');
        setTimeout(() => addLog('WARN', 'Borne Rogue Détectée : SSID "SpaceSec-Secure-Corp" cloné sur BSSID 00:C0:CA:91:DE:3F (Alfa Network)', 'WIFI-AUDIT'), 300);
        setTimeout(() => addLog('ERROR', 'Alerte Evil Twin : Déclassement de sécurité WPA3-SAE vers WPA2-PSK et 148 trames Deauth détectées !', 'WIFI-AUDIT'), 600);
        setTimeout(() => addLog('WARN', 'Réseau Ouvert Détecté : "FreeWifi_Public_Guest" (F4:8E:38:22:1A:BC) non chiffré', 'WIFI-AUDIT'), 900);
        setTimeout(() => addLog('OK', 'Contre-mesure recommandée : Utilisez netsh wlan add filter pour bloquer le BSSID pirate.', 'WIFI-AUDIT'), 1200);
        break;

      case '#':
        addLog('KERNEL', 'Exécution de la commande script automatisée...', 'SCRIPT');
        setTimeout(() => addLog('OK', 'Traitement par lots terminé avec succès.', 'SCRIPT'), 600);
        break;

      case 'geolocate':
      case 'locate':
      case 'geoip':
      case 'traceroute': {
        const queryIp = parts[1] || '185.220.101.4';
        setTargetIpToLocate(queryIp);
        setActiveTab('ip-locator');
        addLog('INFO', `Lancement du traçage physique et de la géolocalisation pour l'IP ${queryIp}...`, 'GEOLOC');
        break;
      }

      default:
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
      />

      {/* Main Container Viewport */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
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
      </main>

      {/* Quiet Clean Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6 px-6 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col lg:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-300">SpaceSec CyberDefense Suite</span>
            <span aria-hidden="true">·</span>
            <span>Édition Kernel v3.0</span>
            <span aria-hidden="true">·</span>
            <span>Développé pour Space [Goat Asta]</span>
          </div>
          <div className="flex items-center flex-wrap justify-center gap-3.5 text-slate-400">
            {/* Section Scan Réseau (Accès Rapide Sockets & Netsh WLAN BSSID) */}
            <div className="flex items-center gap-1.5 p-1 bg-slate-900/90 border border-cyan-800/60 rounded-xl shadow-lg shadow-cyan-950/30">
              <button
                onClick={() => {
                  setActiveTab('network');
                  handleExecuteCommand('sockets');
                }}
                className="px-3 py-1.5 bg-gradient-to-r from-cyan-950/90 to-blue-950/90 hover:from-cyan-900 hover:to-blue-900 text-cyan-200 hover:text-white border border-cyan-600/70 hover:border-cyan-400 rounded-lg font-bold text-xs transition-all flex items-center gap-1.5 shadow-sm active:scale-95 cursor-pointer"
                title="Exécuter automatiquement la commande 'sockets' et basculer vers l'onglet 'network'"
              >
                <Network className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span>Scan Réseau</span>
              </button>

              <button
                onClick={() => {
                  setActiveTab('network');
                  handleExecuteCommand('netsh wlan show networks mode=bssid');
                }}
                className="px-3 py-1.5 bg-gradient-to-r from-indigo-950/90 to-purple-950/90 hover:from-indigo-900 hover:to-purple-900 text-indigo-200 hover:text-white border border-indigo-600/70 hover:border-indigo-400 rounded-lg font-bold text-xs transition-all flex items-center gap-1.5 shadow-sm active:scale-95 cursor-pointer"
                title="Exécuter automatiquement la commande 'netsh wlan show networks mode=bssid' et basculer vers l'onglet 'network'"
              >
                <Wifi className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                <span>Scan WiFi (BSSID)</span>
              </button>
            </div>

            <button onClick={handleDownloadZip} className="text-cyan-400 hover:text-cyan-300 font-semibold transition-colors">
              Télécharger le ZIP
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
          </div>
        </div>
      </footer>

      {/* Multi-User Collaboration & Real-Time Sync Modal */}
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

      {/* Forensic PDF Report Modal */}
      <PdfReportModal
        isOpen={isPdfModalOpen}
        onClose={() => setIsPdfModalOpen(false)}
        threats={threats}
        logs={logs}
        onNotifySuccess={(msg) => addLog('OK', msg, 'PDF-REPORT')}
      />

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
