import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Wrench,
  RotateCcw,
  Terminal,
  FileText,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Play,
  Lock,
  Unlock,
  RefreshCw,
  Globe,
  Radio,
  Sliders,
  Check,
  Copy,
  Info,
  Server,
  Zap,
} from 'lucide-react';
import { apiFetch } from '../utils/api';

interface PostInfectionRepairPanelProps {
  onRunInConsole: (command: string) => void;
}

interface RemediationStatusItem {
  name: string;
  blocked?: boolean;
  isClean?: boolean;
  path?: string;
  details?: string;
  totalLines?: number;
  suspiciousLines?: string[];
  isFlushed?: boolean;
}

export const PostInfectionRepairPanel: React.FC<PostInfectionRepairPanelProps> = ({ onRunInConsole }) => {
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [lastRefreshed, setLastRefreshed] = useState<string>('');
  const [actionLogs, setActionLogs] = useState<Array<{ time: string; text: string; type: 'OK' | 'WARN' | 'INFO' }>>([
    {
      time: new Date().toLocaleTimeString('fr-FR'),
      text: 'Outils de Restauration Post-Infection initialisés. Prêt pour l\'audit et la remédiation.',
      type: 'INFO',
    },
  ]);

  const [systemStatus, setSystemStatus] = useState<Record<string, RemediationStatusItem>>({
    taskmgr: { name: 'Gestionnaire des Tâches (Taskmgr)', blocked: false, details: 'Accessible & Opérationnel' },
    regedit: { name: 'Éditeur de Registre (Regedit)', blocked: false, details: 'Accessible & Opérationnel' },
    cmd: { name: 'Invite de Commandes (CMD / PowerShell)', blocked: false, details: 'Accessible & Opérationnel' },
    norun: { name: 'Menu Exécuter (Win+R / NoRun)', blocked: false, details: 'Accessible' },
    hosts: { name: 'Fichier C:\\Windows\\System32\\drivers\\etc\\hosts', isClean: true, totalLines: 2, suspiciousLines: [] },
    dns: { name: 'Résolution & Cache DNS', isFlushed: true, details: 'Résolution nominale sans proxy pirate' },
  });

  const [customHostsPreview, setCustomHostsPreview] = useState<string[]>([]);
  const [feedbackMessage, setFeedbackMessage] = useState<string | null>(null);

  const addActionLog = (type: 'OK' | 'WARN' | 'INFO', text: string) => {
    setActionLogs(prev => [
      { time: new Date().toLocaleTimeString('fr-FR'), text, type },
      ...prev.slice(0, 40),
    ]);
  };

  const fetchStatus = useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await apiFetch('/api/remediation/status');
      if (res.ok) {
        const data = await res.json();
        if (data.success && data.items) {
          setSystemStatus(data.items);
        }
      }

      // Also query hosts content
      const hostsRes = await apiFetch('/api/system/hosts');
      if (hostsRes.ok) {
        const hostsData = await hostsRes.json();
        if (hostsData.success && Array.isArray(hostsData.lines)) {
          setCustomHostsPreview(hostsData.lines);
        }
      }

      setLastRefreshed(new Date().toLocaleTimeString('fr-FR'));
    } catch (err: any) {
      console.warn('[Remediation] Fetch error:', err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  // Handler: Repair Policies (Taskmgr, Regedit, CMD)
  const handleRepairPolicies = async () => {
    setIsLoading(true);
    addActionLog('INFO', 'Lancement de la purge des stratégies de blocage malveillantes (DisableTaskMgr, DisableRegistryTools, DisableCMD)...');
    onRunInConsole('gpo-repair');

    try {
      const res = await apiFetch('/api/remediation/policies/repair', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        if (data.repairedItems && Array.isArray(data.repairedItems)) {
          data.repairedItems.forEach((msg: string) => addActionLog('OK', msg));
        }
        setFeedbackMessage('Gestionnaire des tâches, Regedit et CMD débloqués avec succès !');
        setTimeout(() => setFeedbackMessage(null), 5000);
      }
      await fetchStatus();
    } catch (err: any) {
      addActionLog('WARN', `Erreur lors du déblocage : ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  // Handler: Restore Hosts & Flush DNS
  const handleRestoreHosts = async () => {
    setIsLoading(true);
    addActionLog('INFO', 'Restauration du fichier C:\\Windows\\System32\\drivers\\etc\\hosts avec le gabarit propre Microsoft...');
    onRunInConsole('hosts-clean');

    try {
      const res = await apiFetch('/api/remediation/hosts/restore', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        addActionLog('OK', data.message || 'Fichier HOSTS restauré avec succès.');
        if (data.backupCreated) {
          addActionLog('INFO', 'Une copie de sauvegarde de votre ancien fichier hosts a été conservée (.spacesec_backup).');
        }
        addActionLog('OK', 'Cache DNS vidé (ipconfig /flushdns) et catalogue Winsock réinitialisé.');
        setFeedbackMessage('Fichier HOSTS restauré et cache DNS purgé avec succès !');
        setTimeout(() => setFeedbackMessage(null), 5000);
      }
      await fetchStatus();
    } catch (err: any) {
      addActionLog('WARN', `Erreur lors de la restauration du fichier hosts : ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  // Handler: Global 1-Click Total Remediation
  const handleRepairAll = async () => {
    setIsLoading(true);
    addActionLog('INFO', 'Démarrage de la RESTAURATION TOTALE POST-INFECTION (Stratégies GPO + Fichier HOSTS + Cache DNS)...');
    onRunInConsole('repair-post-infection');

    await handleRepairPolicies();
    await handleRestoreHosts();

    setFeedbackMessage('Restauration globale post-infection achevée : toutes les restrictions virales ont été neutralisées.');
    setTimeout(() => setFeedbackMessage(null), 6000);
  };

  return (
    <div className="space-y-6">
      {/* Hero Header */}
      <div className="p-6 md:p-8 bg-gradient-to-r from-slate-900 via-slate-900 to-slate-950 border border-slate-800 rounded-2xl relative overflow-hidden shadow-2xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="max-w-3xl space-y-3">
            <div className="inline-flex items-center gap-2 px-3 py-1 bg-cyan-950/80 border border-cyan-800/60 rounded-full text-cyan-300 font-mono text-xs font-semibold">
              <Wrench className="w-3.5 h-3.5 text-cyan-400" />
              <span>Outils de Restauration & Déblocage Système Post-Infection</span>
            </div>

            <h1 className="text-2xl md:text-3xl font-extrabold text-white tracking-tight font-['Plus_Jakarta_Sans']">
              Restauration Post-Infection & Réparation des Stratégies
            </h1>

            <p className="text-sm text-slate-300 leading-relaxed">
              Après une attaque par ransomware ou cheval de Troie, les malwares désactivent systématiquement vos outils d'administration
              et détournent vos résolveurs réseau. Ce module débloque instantanément le <strong className="text-cyan-300">Gestionnaire des tâches</strong>,
              l'<strong className="text-cyan-300">Éditeur de registre</strong>, l'<strong className="text-cyan-300">Invite de commandes</strong>,
              et assainit le fichier <strong className="text-cyan-300">HOSTS</strong> pour supprimer toute redirection pirate.
            </p>

            <div className="flex flex-wrap items-center gap-3 pt-2">
              <button
                onClick={handleRepairAll}
                disabled={isLoading}
                className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-slate-950 font-bold rounded-lg text-xs transition-all shadow-md shadow-cyan-950/50 cursor-pointer active:scale-95 disabled:opacity-50"
              >
                <Zap className="w-4 h-4 fill-slate-950" />
                <span>Débloquer & Réparer Tout en 1 Clic</span>
              </button>

              <button
                onClick={fetchStatus}
                disabled={isLoading}
                className="flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold rounded-lg text-xs transition-colors border border-slate-700"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
                <span>Actualiser l'Audit</span>
              </button>
            </div>
          </div>

          {/* Quick System Integrity Badge */}
          <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 lg:w-72 shrink-0 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Statut de Déblocage</span>
              <span className="text-[10px] font-mono text-cyan-400">SYNCHRONISÉ</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
              <span className="text-sm font-bold text-white font-mono">
                {Object.values(systemStatus).some(s => s.blocked || s.isClean === false)
                  ? 'Restrictions Détectées'
                  : 'Outils Système Opérationnels'}
              </span>
            </div>
            <div className="text-[11px] text-slate-500 font-mono">
              Dernière vérification : {lastRefreshed || 'En cours...'}
            </div>
          </div>
        </div>
      </div>

      {feedbackMessage && (
        <div className="p-4 bg-cyan-950/80 border border-cyan-500/80 rounded-xl text-cyan-200 text-xs font-mono flex items-center justify-between shadow-lg">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
            <span>{feedbackMessage}</span>
          </div>
          <button onClick={() => setFeedbackMessage(null)} className="text-cyan-400 hover:text-white font-bold">
            Fermer
          </button>
        </div>
      )}

      {/* 2-Column Core Remediation Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Module 1: Registre & Déblocage Stratégies (Group Policy) */}
        <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl shadow-lg space-y-5">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400">
                <Unlock className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white font-['Plus_Jakarta_Sans']">
                  Réparation du Registre & Déblocage des Outils Système
                </h3>
                <p className="text-[11px] text-slate-400">
                  Élimine les restrictions DisableTaskMgr, DisableRegistryTools et DisableCMD
                </p>
              </div>
            </div>

            <button
              onClick={handleRepairPolicies}
              disabled={isLoading}
              className="px-3 py-1.5 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 hover:text-white border border-cyan-800/80 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer"
            >
              <Wrench className="w-3.5 h-3.5 text-cyan-400" />
              <span>Débloquer Outils</span>
            </button>
          </div>

          <div className="space-y-3">
            {/* Tool Item 1: TaskMgr */}
            <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800/80 flex items-center justify-between gap-3">
              <div className="space-y-0.5">
                <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Gestionnaire des Tâches (taskmgr.exe)</span>
                </div>
                <div className="text-[11px] font-mono text-slate-400">
                  Clé : Policies\System\DisableTaskMgr
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {systemStatus.taskmgr?.blocked ? (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800">
                    BLOQUÉ PAR MALWARE
                  </span>
                ) : (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                    DÉVERROUILLÉ / OK
                  </span>
                )}
              </div>
            </div>

            {/* Tool Item 2: Regedit */}
            <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800/80 flex items-center justify-between gap-3">
              <div className="space-y-0.5">
                <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
                  <Sliders className="w-3.5 h-3.5 text-amber-400" />
                  <span>Éditeur de Registre Windows (regedit.exe)</span>
                </div>
                <div className="text-[11px] font-mono text-slate-400">
                  Clé : Policies\System\DisableRegistryTools
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {systemStatus.regedit?.blocked ? (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800">
                    BLOQUÉ PAR MALWARE
                  </span>
                ) : (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                    DÉVERROUILLÉ / OK
                  </span>
                )}
              </div>
            </div>

            {/* Tool Item 3: CMD & PowerShell */}
            <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800/80 flex items-center justify-between gap-3">
              <div className="space-y-0.5">
                <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
                  <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Invite de Commandes & Shell (cmd.exe)</span>
                </div>
                <div className="text-[11px] font-mono text-slate-400">
                  Clé : Policies\Microsoft\Windows\System\DisableCMD
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {systemStatus.cmd?.blocked ? (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800">
                    BLOQUÉ PAR MALWARE
                  </span>
                ) : (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                    DÉVERROUILLÉ / OK
                  </span>
                )}
              </div>
            </div>

            {/* Tool Item 4: Run Dialog */}
            <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800/80 flex items-center justify-between gap-3">
              <div className="space-y-0.5">
                <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
                  <Zap className="w-3.5 h-3.5 text-blue-400" />
                  <span>Boîte de Dialogue Exécuter (Win+R)</span>
                </div>
                <div className="text-[11px] font-mono text-slate-400">
                  Clé : Policies\Explorer\NoRun
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {systemStatus.norun?.blocked ? (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800">
                    MASQUÉ
                  </span>
                ) : (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                    ACTIF / OK
                  </span>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Module 2: Nettoyage Redirections DNS & Fichier Hosts */}
        <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl shadow-lg space-y-5">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-indigo-950 border border-indigo-800 flex items-center justify-center text-indigo-400">
                <Globe className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white font-['Plus_Jakarta_Sans']">
                  Nettoyage Redirections DNS & Fichier HOSTS
                </h3>
                <p className="text-[11px] text-slate-400">
                  Purge les détournements de Windows Update et sites antivirus vers des IP hostiles
                </p>
              </div>
            </div>

            <button
              onClick={handleRestoreHosts}
              disabled={isLoading}
              className="px-3 py-1.5 bg-indigo-950 hover:bg-indigo-900 text-indigo-200 hover:text-white border border-indigo-800/80 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5 text-indigo-400" />
              <span>Restaurer HOSTS Propre</span>
            </button>
          </div>

          <div className="space-y-3">
            <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800/80 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                  <FileText className="w-3.5 h-3.5 text-indigo-400" />
                  <span>Emplacement Système :</span>
                </span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                  systemStatus.hosts?.isClean
                    ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                    : 'bg-rose-950 text-rose-300 border border-rose-800'
                }`}>
                  {systemStatus.hosts?.isClean ? 'INTÈGRE / AUCUNE REDIRECTION' : 'ALTÉRÉ / SUSPECT'}
                </span>
              </div>
              <div className="text-xs font-mono text-cyan-300 bg-slate-900/90 p-2 rounded border border-slate-800">
                C:\Windows\System32\drivers\etc\hosts
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                Les trojans modifient ce fichier pour bloquer les mises à jour Windows et empêcher l'accès aux sites de cybersécurité en les redirigeant vers 127.0.0.1 ou des proxys C2.
              </p>
            </div>

            {/* Live Preview of Hosts File */}
            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5">
              <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                <span>Lignes Actives ({customHostsPreview.length || 2} entrées) :</span>
                <span className="text-slate-500">Format Standard Microsoft</span>
              </div>
              <div className="p-2.5 bg-slate-900/90 rounded border border-slate-800/80 text-[11px] font-mono text-slate-300 max-h-24 overflow-y-auto space-y-1">
                {customHostsPreview.length > 0 ? (
                  customHostsPreview.map((line, idx) => (
                    <div key={idx} className={line.toLowerCase().includes('localhost') ? 'text-slate-400' : 'text-rose-400 font-bold'}>
                      {line}
                    </div>
                  ))
                ) : (
                  <>
                    <div className="text-slate-400">127.0.0.1       localhost</div>
                    <div className="text-slate-400">::1             localhost</div>
                  </>
                )}
              </div>
            </div>

            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span className="text-slate-300">Vidage du Cache DNS & Reset Winsock :</span>
              </div>
              <span className="font-mono text-emerald-400 text-[11px] font-bold">ipconfig /flushdns</span>
            </div>
          </div>
        </div>

      </div>

      {/* Audit Log Terminal of Applied Remediations */}
      <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <h4 className="text-xs font-bold text-white font-mono uppercase tracking-wider">
              Journal des Opérations de Déblocage & Restauration
            </h4>
          </div>
          <span className="text-[10px] font-mono text-slate-500">
            Flux d'Événements Live
          </span>
        </div>

        <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 max-h-48 overflow-y-auto font-mono text-xs space-y-1.5">
          {actionLogs.map((log, index) => (
            <div key={index} className="flex items-start gap-2">
              <span className="text-slate-500 shrink-0 text-[11px]">[{log.time}]</span>
              <span
                className={`font-bold shrink-0 text-[11px] ${
                  log.type === 'OK'
                    ? 'text-emerald-400'
                    : log.type === 'WARN'
                    ? 'text-amber-400'
                    : 'text-cyan-400'
                }`}
              >
                [{log.type}]
              </span>
              <span className="text-slate-200">{log.text}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
