import React, { useState, useEffect } from 'react';
import {
  Users,
  Radio,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  Zap,
  X,
  Server,
  Activity,
  ArrowRight,
  ExternalLink,
  Database,
  Cloud,
  Globe,
  Lock,
} from 'lucide-react';
import { OperatorSession } from '../types/cyberdefense';
import { apiFetch } from '../utils/api';

interface CollabSyncModalProps {
  isOpen: boolean;
  onClose: () => void;
  activeUsersCount: number;
  activeOperators: OperatorSession[];
  currentOperator: OperatorSession | null;
  connectionStatus: 'connected' | 'connecting' | 'disconnected';
  lastSyncTime: string;
  onResetThreats: () => void;
  onTestBroadcast: () => void;
}

export const CollabSyncModal: React.FC<CollabSyncModalProps> = ({
  isOpen,
  onClose,
  activeUsersCount,
  activeOperators,
  currentOperator,
  connectionStatus,
  lastSyncTime,
  onResetThreats,
  onTestBroadcast,
}) => {
  const [haStatus, setHaStatus] = useState<{
    connected?: boolean;
    projectId?: string;
    databaseId?: string;
    lastSyncTime?: string;
    storageEngine?: string;
  } | null>(null);

  const [intelStatus, setIntelStatus] = useState<{
    virusTotal?: { configured: boolean; mode: string; provider: string };
    abuseIpDb?: { configured: boolean; mode: string; provider: string };
    threatCacheCount?: number;
  } | null>(null);

  useEffect(() => {
    if (!isOpen) return;
    
    // Fetch Firestore HA status
    apiFetch('/api/system/ha-status')
      .then(res => res.json())
      .then(data => {
        if (data && data.success) setHaStatus(data);
      })
      .catch(() => {});

    // Fetch Threat Intelligence status
    apiFetch('/api/intel/status')
      .then(res => res.json())
      .then(data => {
        if (data && data.success) setIntelStatus(data);
      })
      .catch(() => {});
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-2xl bg-slate-950 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden font-['Plus_Jakarta_Sans']">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 bg-slate-900 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-emerald-950/80 border border-emerald-800 text-emerald-400">
              <Users className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white tracking-tight">
                  Centre d'Opérations Collaboratif & Synchronisation Multi-Utilisateurs
                </h3>
              </div>
              <p className="text-xs text-slate-400">
                Protocole de synchronisation temps réel WebSocket SpaceSec Engine
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body Content */}
        <div className="p-6 space-y-6 max-h-[75vh] overflow-y-auto">
          {/* Real-time Status Card */}
          <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-2.5">
                <span className="relative flex h-3 w-3">
                  {connectionStatus === 'connected' ? (
                    <>
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
                    </>
                  ) : (
                    <span className="relative inline-flex rounded-full h-3 w-3 bg-amber-500"></span>
                  )}
                </span>
                <span className="text-sm font-bold text-white">
                  Canal WebSocket :{' '}
                  <span
                    className={
                      connectionStatus === 'connected'
                        ? 'text-emerald-400 font-mono'
                        : 'text-amber-400 font-mono'
                    }
                  >
                    {connectionStatus === 'connected' ? 'SYNCHRONISÉ EN DIRECT' : 'RECONNEXION...'}
                  </span>
                </span>
              </div>

              <div className="text-xs font-mono text-slate-400">
                Dernière synchro : <span className="text-slate-200">{lastSyncTime || 'Instantanée'}</span>
              </div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed font-sans">
              <strong>Oui, la synchronisation est automatique et bidirectionnelle.</strong> Dès qu'un
              autre utilisateur ou analyste ouvre l'application dans son navigateur, il reçoit
              automatiquement l'état complet du système en temps réel (menaces éradiquées, blocages
              IP, logs console). Toute action menée par un utilisateur est immédiatement propagée
              à tous les écrans connectés.
            </p>
          </div>

          {/* Active Operators Grid */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 uppercase tracking-wider">
                <Radio className="w-3.5 h-3.5" />
                <span>Analystes & Opérateurs Actuellement en Ligne ({activeUsersCount})</span>
              </div>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                Session Active
              </span>
            </div>

            <div className="space-y-2">
              {activeOperators.length > 0 ? (
                activeOperators.map(op => {
                  const isMe = currentOperator?.id === op.id;
                  return (
                    <div
                      key={op.id}
                      className={`p-3 rounded-xl border flex items-center justify-between text-xs transition-colors ${
                        isMe
                          ? 'bg-cyan-950/40 border-cyan-700/80 text-white'
                          : 'bg-slate-900 border-slate-800 text-slate-300'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <div
                          className={`w-8 h-8 rounded-full flex items-center justify-center font-mono font-bold text-xs ${
                            isMe ? 'bg-cyan-600 text-white' : 'bg-slate-800 text-slate-300'
                          }`}
                        >
                          {op.id.replace('OP-', '')}
                        </div>
                        <div>
                          <div className="font-semibold text-slate-100 flex items-center gap-2">
                            <span>{op.name}</span>
                            {isMe && (
                              <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-cyan-900 text-cyan-300">
                                (Votre session)
                              </span>
                            )}
                          </div>
                          <div className="text-[11px] text-slate-400 font-sans">{op.role}</div>
                        </div>
                      </div>

                      <div className="text-right font-mono text-[11px]">
                        <span className="text-emerald-400 font-bold flex items-center gap-1">
                          <CheckCircle2 className="w-3 h-3" />
                          En ligne
                        </span>
                        <span className="text-slate-500 text-[10px]">Depuis {op.connectedAt}</span>
                      </div>
                    </div>
                  );
                })
              ) : (
                <div className="p-3 bg-slate-900 rounded-xl border border-slate-800 flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-emerald-400" />
                    <span>Opérateur Principal Connecté</span>
                  </div>
                  <span className="font-mono text-emerald-400">ACTIF</span>
                </div>
              )}
            </div>
          </div>

          {/* Capabilities Summary */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-xl space-y-1">
              <div className="text-xs font-bold text-white flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                <span>Éradication Noyau</span>
              </div>
              <p className="text-[11px] text-slate-400">
                Quand vous éradiquez un malware ou pilote rootkit, le statut passe en "Destruction au boot" sur tous les écrans.
              </p>
            </div>

            <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-xl space-y-1">
              <div className="text-xs font-bold text-white flex items-center gap-1.5">
                <Zap className="w-3.5 h-3.5 text-amber-400" />
                <span>Télémétrie C2 & WiFi</span>
              </div>
              <p className="text-[11px] text-slate-400">
                Le blocage d'un serveur C2 (ex: 185.220.101.4) ou d'un Evil Twin est partagé en direct avec tous les analystes.
              </p>
            </div>

            <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-xl space-y-1">
              <div className="text-xs font-bold text-white flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-rose-400" />
                <span>Console & Audit</span>
              </div>
              <p className="text-[11px] text-slate-400">
                Les commandes tapées et les alertes de détection sont propagées dans les journaux console partagés.
              </p>
            </div>
          </div>

          {/* Haute Disponibilité & Cloud Firestore Resilience */}
          <div className="p-4 bg-slate-900/90 border border-slate-800 rounded-xl space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 uppercase tracking-wider">
                <Cloud className="w-3.5 h-3.5 text-cyan-400" />
                <span>Persistance Haute Disponibilité (Cloud Firestore)</span>
              </div>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                haStatus?.connected
                  ? 'bg-emerald-950/80 text-emerald-300 border-emerald-800'
                  : 'bg-amber-950/80 text-amber-300 border-amber-800'
              }`}>
                {haStatus?.connected ? 'HA CLOUD ACTIF' : 'SQLITE LOCAL (RÉSILIENCE)'}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div className="p-2.5 bg-slate-950/80 border border-slate-800 rounded-lg space-y-1">
                <div className="text-[11px] text-slate-400 flex items-center gap-1.5">
                  <Database className="w-3 h-3 text-cyan-400" />
                  <span>Moteur de Stockage</span>
                </div>
                <div className="font-mono text-slate-100 font-semibold truncate">
                  {haStatus?.storageEngine === 'CLOUD_FIRESTORE_HA' ? 'Firestore Enterprise HA' : 'SQLite WebAssembly'}
                </div>
                <div className="text-[10px] text-slate-500 font-mono truncate">
                  DB: {haStatus?.databaseId || 'spacesec.sqlite'}
                </div>
              </div>

              <div className="p-2.5 bg-slate-950/80 border border-slate-800 rounded-lg space-y-1">
                <div className="text-[11px] text-slate-400 flex items-center gap-1.5">
                  <Activity className="w-3 h-3 text-emerald-400" />
                  <span>Dernière Sauvegarde HA</span>
                </div>
                <div className="font-mono text-emerald-400 font-semibold truncate">
                  {haStatus?.lastSyncTime ? new Date(haStatus.lastSyncTime).toLocaleTimeString() : 'Automatique'}
                </div>
                <div className="text-[10px] text-slate-500">
                  Zéro perte en cas de redémarrage conteneur
                </div>
              </div>
            </div>
          </div>

          {/* Threat Intelligence Integrations Status */}
          <div className="p-4 bg-slate-900/90 border border-slate-800 rounded-xl space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-mono text-violet-400 uppercase tracking-wider">
                <Globe className="w-3.5 h-3.5 text-violet-400" />
                <span>Moteurs Threat Intelligence (VT v3 & AbuseIPDB)</span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-violet-950/80 text-violet-300 border border-violet-800">
                GLOBAL INTEL
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div className="p-2.5 bg-slate-950/80 border border-slate-800 rounded-lg space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-200">VirusTotal v3</span>
                  <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded ${
                    intelStatus?.virusTotal?.configured
                      ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                      : 'bg-slate-800 text-slate-300 border border-slate-700'
                  }`}>
                    {intelStatus?.virusTotal?.configured ? 'API V3 LIVE' : 'HEURISTIQUES DÉFENSE'}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400">
                  {intelStatus?.virusTotal?.configured
                    ? 'Réputation mondiale de hashs et domaines en temps réel.'
                    : 'Inspection heuristique locale autonome (signatures actives).'}
                </p>
              </div>

              <div className="p-2.5 bg-slate-950/80 border border-slate-800 rounded-lg space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-200">AbuseIPDB v2</span>
                  <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded ${
                    intelStatus?.abuseIpDb?.configured
                      ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                      : 'bg-slate-800 text-slate-300 border border-slate-700'
                  }`}>
                    {intelStatus?.abuseIpDb?.configured ? 'API V2 LIVE' : 'ANALYSE ASN / BGP'}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400">
                  {intelStatus?.abuseIpDb?.configured
                    ? 'Score de confiance des signalements IP C2 mondiaux.'
                    : 'Détection géolocalisée et filtrage des réseaux privés.'}
                </p>
              </div>
            </div>
          </div>

          {/* Action testing buttons */}
          <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-3">
            <div className="text-xs font-bold text-slate-200">
              Actions de Test et Démonstration de la Synchronisation
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <button
                onClick={onTestBroadcast}
                className="px-3.5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold transition-colors flex items-center gap-2"
              >
                <Zap className="w-3.5 h-3.5" />
                <span>Diffuser une Alerte Test Multi-Opérateur</span>
              </button>

              <button
                onClick={onResetThreats}
                className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition-colors flex items-center gap-2 border border-slate-700"
              >
                <RotateCcw className="w-3.5 h-3.5 text-slate-400" />
                <span>Réinitialiser les Menaces du Serveur</span>
              </button>
            </div>
            <p className="text-[11px] text-slate-500">
              💡 Conseil : Ouvrez l'URL dans un deuxième onglet ou une fenêtre de navigation privée pour observer la synchronisation instantanée entre les deux utilisateurs !
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 bg-slate-900/80 border-t border-slate-800 flex items-center justify-between text-xs">
          <span className="text-slate-400 font-mono">
            Serveur autoritaire : <span className="text-cyan-400">127.0.0.1:3000/ws</span>
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded-lg font-semibold transition-colors"
          >
            Fermer
          </button>
        </div>
      </div>
    </div>
  );
};
