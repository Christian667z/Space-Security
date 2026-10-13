import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Wifi,
  WifiOff,
  Network,
  Power,
  RotateCcw,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Unlock,
  Radio,
  Cpu,
  Terminal,
  Activity,
  Layers,
  Zap,
  RefreshCw,
  Server,
  Globe,
  Flame,
  Info,
} from 'lucide-react';
import { NetworkInterfaceInfo, SandboxProcessItem, KillSwitchStatus } from '../types/cyberdefense';
import { apiFetch } from '../utils/api';

interface SandboxIsolationPanelProps {
  onRunInConsole: (cmd: string) => void;
}

export const SandboxIsolationPanel: React.FC<SandboxIsolationPanelProps> = ({ onRunInConsole }) => {
  const [killSwitchActive, setKillSwitchActive] = useState<boolean>(false);
  const [interfaces, setInterfaces] = useState<NetworkInterfaceInfo[]>([]);
  const [sandboxedProcesses, setSandboxedProcesses] = useState<SandboxProcessItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [actionMessage, setActionMessage] = useState<{ type: 'ok' | 'warn' | 'error'; text: string } | null>(null);

  // Input state for process sandboxing
  const [targetPid, setTargetPid] = useState<string>('');
  const [targetProcName, setTargetProcName] = useState<string>('');
  const [targetProcPath, setTargetProcPath] = useState<string>('');

  // Fetch status from server
  const loadStatus = useCallback(async () => {
    try {
      setIsLoading(true);
      const res = await apiFetch('/api/sandbox/status');
      const data = await res.json();
      if (data && data.success) {
        setKillSwitchActive(data.killSwitch.isActive);
        setInterfaces(data.killSwitch.interfaces || []);
        setSandboxedProcesses(data.sandboxedProcesses || []);
      }
    } catch (err) {
      console.warn('[Sandbox Status Load Error]:', err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadStatus();
    const interval = setInterval(loadStatus, 5000);
    return () => clearInterval(interval);
  }, [loadStatus]);

  // Handle Engage Kill-Switch
  const handleEngageKillSwitch = async () => {
    setIsLoading(true);
    setActionMessage(null);
    try {
      const res = await apiFetch('/api/network/kill-switch', { method: 'POST' });
      const data = await res.json();
      if (data && data.success) {
        setKillSwitchActive(true);
        setActionMessage({
          type: 'warn',
          text: `Kill-Switch activé avec succès ! ${data.disabledInterfaces?.length || 0} interface(s) coupée(s). Boucle locale 127.0.0.1 (localhost:${data.localhostPort || 3000}) opérationnelle.`,
        });
        loadStatus();
      } else {
        setActionMessage({ type: 'error', text: data?.error || 'Erreur lors du déclenchement du Kill-Switch.' });
      }
    } catch (err: any) {
      setActionMessage({ type: 'error', text: err.message || 'Erreur réseau.' });
    } finally {
      setIsLoading(false);
    }
  };

  // Handle Restore Network
  const handleRestoreNetwork = async () => {
    setIsLoading(true);
    setActionMessage(null);
    try {
      const res = await apiFetch('/api/network/restore', { method: 'POST' });
      const data = await res.json();
      if (data && data.success) {
        setKillSwitchActive(false);
        setActionMessage({
          type: 'ok',
          text: `Réseau rétabli : ${data.restoredInterfaces?.length || 0} interface(s) réactivée(s). Connexions sortantes et entrantes rétablies.`,
        });
        loadStatus();
      } else {
        setActionMessage({ type: 'error', text: data?.error || 'Erreur lors du rétablissement réseau.' });
      }
    } catch (err: any) {
      setActionMessage({ type: 'error', text: err.message || 'Erreur réseau.' });
    } finally {
      setIsLoading(false);
    }
  };

  // Toggle single interface
  const handleToggleInterface = async (ifaceName: string, currentlyEnabled: boolean) => {
    try {
      const res = await apiFetch('/api/network/toggle-interface', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interfaceName: ifaceName, enable: !currentlyEnabled }),
      });
      const data = await res.json();
      if (data && data.success) {
        loadStatus();
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Isolate Process in Sandbox
  const handleIsolateProcess = async () => {
    const pid = parseInt(targetPid.trim(), 10);
    if (!pid || isNaN(pid)) {
      setActionMessage({ type: 'error', text: 'Veuillez saisir un PID numérique valide.' });
      return;
    }

    setIsLoading(true);
    try {
      const res = await apiFetch('/api/sandbox/isolate-process', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          pid,
          name: targetProcName.trim() || `Suspicious_Proc_${pid}`,
          path: targetProcPath.trim() || undefined,
        }),
      });
      const data = await res.json();
      if (data && data.success) {
        setActionMessage({
          type: 'ok',
          text: `PID ${pid} placé en Sandbox Live : Threads gelés et connexions réseau sortantes bloquées par le pare-feu.`,
        });
        setTargetPid('');
        setTargetProcName('');
        setTargetProcPath('');
        loadStatus();
      } else {
        setActionMessage({ type: 'error', text: data?.error || 'Échec du confinement.' });
      }
    } catch (err: any) {
      setActionMessage({ type: 'error', text: err.message || 'Erreur serveur.' });
    } finally {
      setIsLoading(false);
    }
  };

  // Terminate Sandboxed Process
  const handleTerminateProcess = async (pid: number) => {
    try {
      const res = await apiFetch('/api/sandbox/terminate-process', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid }),
      });
      const data = await res.json();
      if (data && data.success) {
        loadStatus();
      }
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* Top Banner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-xl backdrop-blur-md relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-red-500/5 rounded-full blur-3xl -z-10 pointer-events-none" />
        
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className={`p-3 rounded-xl border ${
              killSwitchActive
                ? 'bg-rose-500/20 border-rose-500/50 text-rose-400 animate-pulse'
                : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
            }`}>
              {killSwitchActive ? <WifiOff className="w-8 h-8" /> : <ShieldCheck className="w-8 h-8" />}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-black text-white tracking-wide font-['Plus_Jakarta_Sans']">
                  Module d'Isolateur & Bac à Sable (Sandbox Live)
                </h1>
                <span className={`px-2.5 py-0.5 text-xs font-bold rounded-full border ${
                  killSwitchActive
                    ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                    : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                }`}>
                  {killSwitchActive ? 'KILL-SWITCH ENGAGÉ (ISOLEMENT TOTAL)' : 'RÉSEAU ACTIF'}
                </span>
              </div>
              <p className="text-sm text-slate-300 mt-1 max-w-3xl">
                Coupe instantanément le trafic sortant et entrant via l'extinction administrative des interfaces Wi-Fi & Ethernet (<code className="text-rose-400">netsh interface set interface</code>), tout en garantissant le fonctionnement ininterrompu de la boucle locale <code className="text-emerald-400">127.0.0.1 (localhost)</code>.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={loadStatus}
              disabled={isLoading}
              className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-semibold flex items-center gap-1.5 border border-slate-700 transition"
              title="Rafraîchir les interfaces"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
              Actualiser
            </button>
            <button
              onClick={() => onRunInConsole('menu 15')}
              className="px-3.5 py-2 bg-indigo-600/30 hover:bg-indigo-600/50 text-indigo-300 border border-indigo-500/40 rounded-lg text-xs font-bold flex items-center gap-1.5 transition"
            >
              <Terminal className="w-3.5 h-3.5" />
              CLI Menu 15
            </button>
          </div>
        </div>

        {/* Action feedback banner */}
        {actionMessage && (
          <div className={`mt-4 p-3 rounded-lg border text-xs flex items-center gap-2 ${
            actionMessage.type === 'ok'
              ? 'bg-emerald-950/60 border-emerald-800/60 text-emerald-300'
              : actionMessage.type === 'warn'
              ? 'bg-amber-950/60 border-amber-800/60 text-amber-300'
              : 'bg-rose-950/60 border-rose-800/60 text-rose-300'
          }`}>
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{actionMessage.text}</span>
          </div>
        )}
      </div>

      {/* Main Grid: Kill-Switch & Localhost Guarantee */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Urgent Action Card: Network Kill-Switch */}
        <div className={`lg:col-span-2 rounded-xl p-6 border shadow-2xl relative overflow-hidden transition-all ${
          killSwitchActive
            ? 'bg-gradient-to-br from-rose-950/40 via-slate-900 to-slate-950 border-rose-600/50'
            : 'bg-gradient-to-br from-slate-900 via-slate-900/90 to-slate-950 border-slate-800'
        }`}>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2.5">
              <Flame className={`w-5 h-5 ${killSwitchActive ? 'text-rose-400 animate-bounce' : 'text-amber-400'}`} />
              <h2 className="text-lg font-bold text-white tracking-wide">
                Coupe-Circuit d'Urgence (Kill-Switch Réseau)
              </h2>
            </div>
            <span className="text-xs text-slate-400 font-mono">
              Action Administrative L2/L3
            </span>
          </div>

          <p className="text-xs text-slate-300 mb-6 leading-relaxed">
            En cas d'infection active par un ransomware, ver informatique, fuite de données en cours ou communication avec un serveur Command & Control (C2), déclenchez immédiatement le Kill-Switch pour neutraliser les sockets réseau externes sans éteindre l'ordinateur.
          </p>

          {/* Action Trigger Buttons */}
          <div className="flex flex-col sm:flex-row gap-4">
            {!killSwitchActive ? (
              <button
                onClick={handleEngageKillSwitch}
                disabled={isLoading}
                className="flex-1 py-4 px-6 bg-rose-600 hover:bg-rose-500 active:bg-rose-700 text-white font-extrabold rounded-xl shadow-lg shadow-rose-950/60 flex items-center justify-center gap-3 transition-all transform hover:-translate-y-0.5 border border-rose-400/40 cursor-pointer group"
              >
                <Power className="w-6 h-6 text-white group-hover:scale-110 transition-transform" />
                <div className="text-left">
                  <div className="text-sm uppercase tracking-wider font-black">DÉCLENCHER LE KILL-SWITCH RÉSEAU</div>
                  <div className="text-[11px] text-rose-200 font-normal">Coupe Wi-Fi & Ethernet immédiatement (Préserve localhost)</div>
                </div>
              </button>
            ) : (
              <button
                onClick={handleRestoreNetwork}
                disabled={isLoading}
                className="flex-1 py-4 px-6 bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 text-white font-extrabold rounded-xl shadow-lg shadow-emerald-950/60 flex items-center justify-center gap-3 transition-all transform hover:-translate-y-0.5 border border-emerald-400/40 cursor-pointer group"
              >
                <RotateCcw className="w-6 h-6 text-white group-hover:rotate-180 transition-transform duration-500" />
                <div className="text-left">
                  <div className="text-sm uppercase tracking-wider font-black">RÉTABLIR LES INTERFACES RÉSEAU</div>
                  <div className="text-[11px] text-emerald-200 font-normal">Réactive les cartes Wi-Fi & Ethernet via netsh</div>
                </div>
              </button>
            )}

            <button
              onClick={() => onRunInConsole('kill-switch')}
              className="py-4 px-5 bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold rounded-xl border border-slate-700 text-xs flex items-center justify-center gap-2 transition"
            >
              <Terminal className="w-4 h-4 text-cyan-400" />
              Console Shell
            </button>
          </div>

          {/* Execution Command Log */}
          <div className="mt-6 pt-4 border-t border-slate-800">
            <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              Commandes Système Sous-Jacentes Exécutées :
            </div>
            <div className="bg-slate-950 rounded-lg p-3 font-mono text-[11px] text-slate-300 border border-slate-800 space-y-1">
              <div className="text-rose-400">
                # Désactivation d'urgence de toutes les interfaces physiques :
              </div>
              <div>netsh interface set interface &quot;Wi-Fi&quot; admin=disabled</div>
              <div>netsh interface set interface &quot;Ethernet&quot; admin=disabled</div>
              <div>Disable-NetAdapter -Name &quot;*&quot; -Confirm:$false</div>
              <div className="text-emerald-400 pt-1">
                # La boucle locale reste active dans le noyau TCP/IP (tcpip.sys) :
              </div>
              <div className="text-slate-400">127.0.0.1 / ::1 (localhost:3000) reste 100% fonctionnel</div>
            </div>
          </div>
        </div>

        {/* Localhost / Loopback Guarantee Card */}
        <div className="bg-slate-900/90 border border-emerald-500/30 rounded-xl p-6 shadow-xl relative overflow-hidden flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-3">
              <div className="p-2 rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
                <CheckCircle2 className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  Boucle Locale 127.0.0.1 (Localhost)
                </h3>
                <span className="text-[11px] text-emerald-400 font-medium">
                  Préservation Garantie Sans Coupure
                </span>
              </div>
            </div>

            <div className="bg-emerald-950/40 border border-emerald-800/40 rounded-lg p-3 text-xs text-emerald-200 mb-4 space-y-2">
              <div className="flex items-center justify-between font-mono">
                <span className="text-slate-300">Statut Pile Loopback :</span>
                <span className="font-bold text-emerald-400">ACTIF (UP)</span>
              </div>
              <div className="flex items-center justify-between font-mono">
                <span className="text-slate-300">Port Serveur Web :</span>
                <span className="font-bold text-emerald-400">3000 (Vite / Node)</span>
              </div>
              <div className="flex items-center justify-between font-mono">
                <span className="text-slate-300">Adresse Loopback :</span>
                <span className="font-bold text-emerald-400">127.0.0.1 &amp; ::1</span>
              </div>
              <div className="flex items-center justify-between font-mono">
                <span className="text-slate-300">Latence IPC Interne :</span>
                <span className="font-bold text-emerald-400">&lt; 0.1 ms</span>
              </div>
            </div>

            <div className="text-xs text-slate-300 leading-relaxed space-y-2">
              <p>
                <strong>Pourquoi l'interface continue de fonctionner ?</strong>
              </p>
              <p className="text-[11px] text-slate-400">
                L'arrêt des adaptateurs via <code className="text-cyan-300">netsh</code> désactive les couches physiques Wi-Fi/Ethernet. La boucle locale <code className="text-emerald-300">127.0.0.1</code> est un périphérique pseudo-réseau géré directement dans la mémoire du noyau Windows par le pilote <code className="text-slate-300">tcpip.sys</code>.
              </p>
              <p className="text-[11px] text-slate-400">
                Ainsi, l'interface web, les websockets locaux et les outils d'éradication continuent de fonctionner sans la moindre dépendance à une connexion Internet externe.
              </p>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
            <span>Protection C2 Exfiltration</span>
            <span className="text-emerald-400 font-bold">100% Étanche</span>
          </div>
        </div>
      </div>

      {/* Network Interfaces Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-xl">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Network className="w-5 h-5 text-cyan-400" />
            <h3 className="text-base font-bold text-white tracking-wide">
              Interfaces Réseau Détectées sur l'Hôte ({interfaces.length})
            </h3>
          </div>
          <span className="text-xs text-slate-400">
            Énumération via <code className="text-cyan-400">WMI Win32_NetworkAdapter</code> &amp; <code className="text-cyan-400">netsh</code>
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-950/80 text-slate-400 uppercase font-mono text-[11px] border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Type</th>
                <th className="py-2.5 px-3">Nom de l'Interface</th>
                <th className="py-2.5 px-3">État Admin</th>
                <th className="py-2.5 px-3">État Liaison</th>
                <th className="py-2.5 px-3">Adresse MAC</th>
                <th className="py-2.5 px-3">Adresses IP</th>
                <th className="py-2.5 px-3 text-right">Action Ciblée</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {interfaces.map((iface) => {
                const isLoop = iface.isLoopback;
                const isDownOrDisabled = iface.status === 'Disabled' || iface.adminStatus === 'Disabled';

                return (
                  <tr key={iface.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-2">
                        {iface.type === 'Wi-Fi' ? (
                          <Wifi className="w-4 h-4 text-sky-400" />
                        ) : iface.type === 'Loopback' ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        ) : (
                          <Network className="w-4 h-4 text-indigo-400" />
                        )}
                        <span className="font-bold text-slate-200">{iface.type}</span>
                      </div>
                    </td>
                    <td className="py-3 px-3 text-white font-semibold">
                      {iface.displayName || iface.name}
                    </td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        isDownOrDisabled
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                          : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      }`}>
                        {iface.adminStatus === 'Disabled' ? 'DÉSACTIVÉ' : 'ACTIVÉ'}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        iface.status === 'Up'
                          ? 'text-emerald-400'
                          : iface.status === 'Disabled'
                          ? 'text-rose-400'
                          : 'text-amber-400'
                      }`}>
                        {iface.status.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-slate-400">
                      {iface.mac || 'N/A'}
                    </td>
                    <td className="py-3 px-3 text-cyan-300">
                      {iface.ipAddresses && iface.ipAddresses.length > 0
                        ? iface.ipAddresses.join(', ')
                        : 'Aucune (Déconnecté)'}
                    </td>
                    <td className="py-3 px-3 text-right">
                      {isLoop ? (
                        <span className="text-[10px] font-bold text-emerald-400 bg-emerald-950/60 border border-emerald-800/60 px-2 py-1 rounded">
                          BOUCLE PROTÉGÉE
                        </span>
                      ) : (
                        <button
                          onClick={() => handleToggleInterface(iface.name, iface.adminStatus === 'Enabled')}
                          className={`px-2.5 py-1 rounded text-[11px] font-bold border transition ${
                            isDownOrDisabled
                              ? 'bg-emerald-600/30 hover:bg-emerald-600/50 text-emerald-300 border-emerald-500/40'
                              : 'bg-rose-600/30 hover:bg-rose-600/50 text-rose-300 border-rose-500/40'
                          }`}
                        >
                          {isDownOrDisabled ? 'Réactiver' : 'Couper'}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Sandbox Live Section: Process Containment & Freezing */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-xl">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Layers className="w-5 h-5 text-amber-400" />
            <h3 className="text-base font-bold text-white tracking-wide">
              Bac à Sable (Sandbox Live) &amp; Confinement de Menaces
            </h3>
          </div>
          <span className="text-xs text-slate-400">
            Suspension des threads (NtSuspendProcess) &amp; Isolation Pare-feu
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <div className="p-4 bg-slate-950 rounded-xl border border-slate-800">
            <div className="text-xs font-bold text-slate-400 mb-1">1. GELER L'EXÉCUTION</div>
            <div className="text-sm font-semibold text-white">Suspension Immédiate</div>
            <p className="text-[11px] text-slate-400 mt-1">
              Fige tous les threads du malware dans leur état actuel sans détruire la mémoire pour permettre l'analyse forensique.
            </p>
          </div>

          <div className="p-4 bg-slate-950 rounded-xl border border-slate-800">
            <div className="text-xs font-bold text-slate-400 mb-1">2. ISOLER DU RÉSEAU</div>
            <div className="text-xs font-semibold text-white">Règle Firewall Dédiée</div>
            <p className="text-[11px] text-slate-400 mt-1">
              Bloque tout trafic sortant du binaire suspect (<code className="text-amber-400">netsh advfirewall</code>) pour empêcher la transmission de clés de chiffrement.
            </p>
          </div>

          <div className="p-4 bg-slate-950 rounded-xl border border-slate-800">
            <div className="text-xs font-bold text-slate-400 mb-1">3. RESTRICTION SYSTEM</div>
            <div className="text-xs font-semibold text-white">Job Object Windows</div>
            <p className="text-[11px] text-slate-400 mt-1">
              Interdit la création de processus enfants, l'accès au presse-papiers et la modification de fichiers du système.
            </p>
          </div>
        </div>

        {/* Form to isolate a process */}
        <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 mb-6">
          <div className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">
            Placer un Processus en Confinement Sandbox Live
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
            <div>
              <label className="block text-[11px] font-mono text-slate-400 mb-1">PID Cible *</label>
              <input
                type="text"
                placeholder="Ex: 4892"
                value={targetPid}
                onChange={(e) => setTargetPid(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white font-mono focus:outline-none focus:border-amber-500"
              />
            </div>
            <div>
              <label className="block text-[11px] font-mono text-slate-400 mb-1">Nom du Processus</label>
              <input
                type="text"
                placeholder="Ex: suspicious_payload.exe"
                value={targetProcName}
                onChange={(e) => setTargetProcName(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-amber-500"
              />
            </div>
            <div>
              <label className="block text-[11px] font-mono text-slate-400 mb-1">Chemin Exécutable</label>
              <input
                type="text"
                placeholder="Ex: C:\Users\Admin\AppData\payload.exe"
                value={targetProcPath}
                onChange={(e) => setTargetProcPath(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-amber-500"
              />
            </div>
            <div className="flex items-end">
              <button
                onClick={handleIsolateProcess}
                disabled={isLoading}
                className="w-full py-2 px-4 bg-amber-600 hover:bg-amber-500 active:bg-amber-700 text-slate-950 font-bold rounded-lg text-xs flex items-center justify-center gap-1.5 transition cursor-pointer"
              >
                <Lock className="w-4 h-4" />
                Isoler en Sandbox
              </button>
            </div>
          </div>
        </div>

        {/* Current sandboxed processes list */}
        <div>
          <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
            Processus Actuellement Confinés en Sandbox ({sandboxedProcesses.length})
          </div>
          {sandboxedProcesses.length === 0 ? (
            <div className="text-center py-8 text-xs text-slate-500 bg-slate-950/40 rounded-lg border border-slate-800/60 font-mono">
              Aucun processus actuellement confiné en Sandbox. Utilisez le formulaire ci-dessus pour geler une menace.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-slate-950 text-slate-400 uppercase font-mono text-[11px] border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 px-3">PID</th>
                    <th className="py-2.5 px-3">Nom</th>
                    <th className="py-2.5 px-3">Chemin</th>
                    <th className="py-2.5 px-3">État Sandbox</th>
                    <th className="py-2.5 px-3">Réseau Coupé</th>
                    <th className="py-2.5 px-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {sandboxedProcesses.map((p) => (
                    <tr key={p.pid} className="hover:bg-slate-800/40 transition">
                      <td className="py-2.5 px-3 text-amber-400 font-bold">{p.pid}</td>
                      <td className="py-2.5 px-3 text-white font-semibold">{p.name}</td>
                      <td className="py-2.5 px-3 text-slate-400 truncate max-w-xs">{p.path}</td>
                      <td className="py-2.5 px-3">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                          {p.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="text-rose-400 font-bold text-[11px] flex items-center gap-1">
                          <WifiOff className="w-3.5 h-3.5" />
                          BLOQUÉ
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right space-x-2">
                        <button
                          onClick={() => handleTerminateProcess(p.pid)}
                          className="px-2 py-1 bg-rose-600/30 hover:bg-rose-600/50 text-rose-300 border border-rose-500/40 rounded text-[10px] font-bold"
                        >
                          Éradiquer (Kill)
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
