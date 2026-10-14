import React from 'react';
import { Lock, ShieldCheck, ShieldAlert, RefreshCw, AlertTriangle, Key, Terminal, Database } from 'lucide-react';
import { HardeningMetric, ThreatItem } from '../types/cyberdefense';
import { ErrorBoundary } from './ErrorBoundary';

const VulnerabilityScanner = React.lazy(() => import('./VulnerabilityScanner').then(m => ({ default: m.VulnerabilityScanner })));
const DefenderSync = React.lazy(() => import('./DefenderSync').then(m => ({ default: m.DefenderSync })));

interface HardeningPanelProps {
  onRunInConsole: (command: string) => void;
  onMutateThreatStatus?: (threatId: string, targetPath: string, status: ThreatItem['status']) => void;
}

export const HardeningPanel: React.FC<HardeningPanelProps> = ({ onRunInConsole, onMutateThreatStatus }) => {
  const hardeningMetrics: HardeningMetric[] = [
    {
      title: 'Windows Defender & Protection en Temps Réel',
      status: 'PROTECTED',
      details: 'Services WinDefend & WdFilter opérationnels. DLL de confiance (wintrust.dll, mssip32.dll) intègres.',
      remediationCmd: 'defender-repair',
    },
    {
      title: 'Protocole Réseau Obsolète SMBv1 (WannaCry / EternalBlue)',
      status: 'PROTECTED',
      details: 'SMBv1 est désactivé sur ce système. Les vecteurs de propagation latérale sans mot de passe sont neutralisés.',
      remediationCmd: 'smb1-disable',
    },
    {
      title: 'Abonnements WMI Persistants (EventFilter & EventConsumer)',
      status: 'PROTECTED',
      details: 'Aucun déclencheur WMI caché détecté dans le namespace root\\subscription.',
      remediationCmd: 'wmi-clean',
    },
    {
      title: 'Clichés Instantanés Volume Shadow Copy (VSS Anti-Ransomware)',
      status: 'PROTECTED',
      details: 'Service VSS configuré. Clichés instantanés disponibles pour la récupération rapide en cas d\'incident.',
      remediationCmd: 'vss-create',
    },
    {
      title: 'Politique d\'Exécution PowerShell (ExecutionPolicy)',
      status: 'PROTECTED',
      details: 'Configurée sur RemoteSigned pour empêcher l\'exécution silencieuse de scripts non approuvés du Web.',
      remediationCmd: 'policy-harden',
    },
    {
      title: 'PowerShell v2.0 (Vecteur Downgrade Attack sans Logging)',
      status: 'PROTECTED',
      details: 'Le moteur ancien PowerShell 2.0 (sans Script Block Logging Event 4104) est désactivé.',
      remediationCmd: 'psv2-disable',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs uppercase tracking-wider mb-2">
              <Lock className="w-4 h-4" />
              <span>Posture de Défense & Réduction de la Surface d'Attaque</span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight font-['Plus_Jakarta_Sans']">
              Durcissement Système & Réparation des Protections
            </h2>
            <p className="mt-1 text-sm text-slate-300">
              Verrouille les vecteurs de propagation latérale, répare Defender en cas de sabotage par un trojan et assure l'intégrité des sauvegardes VSS.
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              onClick={() => onRunInConsole('harden-all')}
              className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold rounded-lg text-xs transition-colors shadow-sm"
            >
              <ShieldCheck className="w-4 h-4" />
              <span>Appliquer Tout le Durcissement</span>
            </button>
          </div>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {hardeningMetrics.map((metric, idx) => (
          <div
            key={idx}
            className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-4 flex flex-col justify-between"
          >
            <div className="space-y-3">
              <div className="flex items-start justify-between gap-2">
                <h3 className="font-semibold text-slate-100 text-sm">
                  {metric.title}
                </h3>
                <span
                  className={`text-[10px] font-bold px-2 py-0.5 rounded font-mono uppercase tracking-wider shrink-0 ${
                    metric.status === 'PROTECTED'
                      ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/60'
                      : metric.status === 'VULNERABLE'
                      ? 'bg-rose-950 text-rose-300 border border-rose-800/60'
                      : 'bg-amber-950 text-amber-300 border border-amber-800/60'
                  }`}
                >
                  {metric.status === 'PROTECTED' ? 'Sécurisé' : metric.status === 'VULNERABLE' ? 'Vulnérable' : 'Attention'}
                </span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                {metric.details}
              </p>
            </div>

            <div className="pt-3 border-t border-slate-800/80">
              <button
                onClick={() => onRunInConsole(metric.remediationCmd)}
                className={`w-full py-2 px-3 text-xs font-semibold rounded-lg transition-colors flex items-center justify-center gap-1.5 ${
                  metric.status === 'VULNERABLE'
                    ? 'bg-rose-600 hover:bg-rose-500 text-white'
                    : metric.status === 'WARNING'
                    ? 'bg-amber-600 hover:bg-amber-500 text-white'
                    : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                }`}
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>
                  {metric.status === 'PROTECTED' ? 'Re-vérifier État' : 'Corriger & Durcir'}
                </span>
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* DefenderSync Module: Audit and Clean Malware Exclusions in Microsoft Defender */}
      <ErrorBoundary moduleName="Audit des Exclusions Windows Defender (MpPreference)">
        <React.Suspense fallback={<div className="h-40 flex items-center justify-center bg-slate-900/60 border border-slate-800 rounded-xl text-xs text-slate-500 font-mono animate-pulse">Chargement de DefenderSync...</div>}>
          <DefenderSync onRunInConsole={onRunInConsole} onMutateThreatStatus={onMutateThreatStatus} />
        </React.Suspense>
      </ErrorBoundary>

      {/* VulnerabilityScanner Module: Obsolete Windows Services & Missing Hotfixes (Get-HotFix / Get-Service) */}
      <ErrorBoundary moduleName="Scanner de Vulnérabilités & Correctifs Windows">
        <React.Suspense fallback={<div className="h-40 flex items-center justify-center bg-slate-900/60 border border-slate-800 rounded-xl text-xs text-slate-500 font-mono animate-pulse">Chargement du Scanner de Vulnérabilités...</div>}>
          <VulnerabilityScanner onRunInConsole={onRunInConsole} />
        </React.Suspense>
      </ErrorBoundary>

      {/* Emergency SafeMode Card */}
      <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <Key className="w-4 h-4 text-cyan-400" />
              Procédure de Sauvetage : Boot Chirurgical en Mode Sans Échec
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Si un rootkit ou un ransomware bloque toute action en session normale, le script configure Windows pour un redémarrage unique en mode minimal sans chargement des pilotes tiers.
            </p>
          </div>

          <button
            onClick={() => onRunInConsole('safemode-prepare')}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 rounded-lg text-xs font-semibold transition-colors shrink-0"
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Configurer SafeBoot BCD</span>
          </button>
        </div>

        <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono text-slate-300 space-y-2">
          <div className="text-slate-400 font-sans">Commandes intégrées dans la suite :</div>
          <div className="text-cyan-300">bcdedit.exe /set {'{current}'} safeboot minimal</div>
          <div className="text-slate-500"># Pour restaurer le mode standard ultérieurement :</div>
          <div className="text-cyan-300">bcdedit.exe /deletevalue {'{current}'} safeboot</div>
        </div>
      </div>
    </div>
  );
};
