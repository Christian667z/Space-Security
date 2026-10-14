import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  Search,
  RotateCcw,
  Terminal,
  Zap,
  Lock,
  FileCheck,
  ArrowRight,
  Eye,
  FileCode,
  Shield
} from 'lucide-react';
import { DigitalSignatureInspectionItem } from '../types/cyberdefense';
import { apiFetch } from '../utils/api';

interface DigitalSignatureInspectorProps {
  onRunInConsole?: (command: string) => void;
  onAddLog?: (level: 'OK' | 'INFO' | 'WARN' | 'ERROR' | 'KERNEL', text: string, tag?: string) => void;
}

export const DigitalSignatureInspector: React.FC<DigitalSignatureInspectorProps> = ({
  onRunInConsole,
  onAddLog,
}) => {
  const [items, setItems] = useState<DigitalSignatureInspectionItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [filterType, setFilterType] = useState<'ALL' | 'SPOOFED_ONLY' | 'LEGITIMATE_ONLY'>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [customPath, setCustomPath] = useState<string>('C:\\Windows\\explorer.exe');
  const [customResult, setCustomResult] = useState<any>(null);
  const [isScanningCustom, setIsScanningCustom] = useState<boolean>(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [lastCheckTime, setLastCheckTime] = useState<string>('');

  const fetchSignatures = useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await apiFetch('/api/system/signatures/inspect');
      if (res.ok) {
        const data = await res.json();
        if (data.success && Array.isArray(data.items)) {
          setItems(data.items);
          setLastCheckTime(data.timestamp || new Date().toLocaleTimeString('fr-FR'));

          const spoofed = data.items.filter((i: DigitalSignatureInspectionItem) => i.isSpoofed);
          if (spoofed.length > 0) {
            onAddLog?.(
              'ERROR',
              `[SIGNATURE-ALERTE] Falsification de nom détectée : ${spoofed.length} binaire(s) non signé(s) par Microsoft se font passer pour des processus système (ex: faux explorer.exe) !`,
              'MASQUERADE'
            );
          }
        }
      }
    } catch (e) {
      console.error('Error fetching signatures:', e);
    } finally {
      setIsLoading(false);
    }
  }, [onAddLog]);

  useEffect(() => {
    fetchSignatures();
  }, [fetchSignatures]);

  const handleScanCustomPath = async () => {
    if (!customPath.trim()) return;
    setIsScanningCustom(true);
    try {
      const res = await apiFetch(`/api/system/scan/file?path=${encodeURIComponent(customPath.trim())}`);
      if (res.ok) {
        const data = await res.json();
        setCustomResult(data);
        onAddLog?.(
          data.isSigned ? 'OK' : 'WARN',
          `[AUTHENTICODE] Inspection de ${customPath} : Statut ${data.signatureStatus} (Signataire: ${data.signer || 'Non signé'})`,
          'AUTHENTICODE'
        );
      }
    } catch (e) {
      console.error('Error scanning custom file signature:', e);
    } finally {
      setIsScanningCustom(false);
    }
  };

  const handleKillSpoofedProcess = (item: DigitalSignatureInspectionItem) => {
    if (item.pid) {
      onRunInConsole?.(`kill ${item.pid}`);
    } else {
      onRunInConsole?.(`taskkill /F /IM ${item.binaryName}`);
    }
    setItems(prev => prev.filter(i => i.id !== item.id));
    onAddLog?.(
      'OK',
      `[NEUTRALISATION] Processus falsifié abattu : ${item.binaryName} (PID ${item.pid || 'N/A'})`,
      'SIG-KILL'
    );
  };

  const handleCopySha = (sha: string, id: string) => {
    navigator.clipboard.writeText(sha);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const spoofedItems = useMemo(() => items.filter(i => i.isSpoofed), [items]);
  const legitimateItems = useMemo(() => items.filter(i => !i.isSpoofed), [items]);

  const filteredItems = useMemo(() => {
    return items.filter(item => {
      if (filterType === 'SPOOFED_ONLY' && !item.isSpoofed) return false;
      if (filterType === 'LEGITIMATE_ONLY' && item.isSpoofed) return false;

      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          item.binaryName.toLowerCase().includes(q) ||
          item.actualPath.toLowerCase().includes(q) ||
          item.signerName.toLowerCase().includes(q) ||
          (item.spoofingReason && item.spoofingReason.toLowerCase().includes(q))
        );
      }
      return true;
    });
  }, [items, filterType, searchQuery]);

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Title & Explanatory Banner */}
      <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-semibold text-cyan-400">
              <ShieldCheck className="w-4 h-4" />
              <span>INSPECTEUR DE SIGNATURE NUMÉRIQUE AUTHENTICODE</span>
              <span className="text-slate-500">·</span>
              <span className="text-slate-400 font-mono">Détection Masquerading T1036.005</span>
            </div>
            <h2 className="text-lg md:text-xl font-bold text-white tracking-tight mt-1">
              Inspecteur de Signature Numérique & Détection de Falsification de Nom
            </h2>
            <p className="text-xs text-slate-300 max-w-3xl leading-relaxed mt-1">
              Vérifie automatiquement les signatures numériques Microsoft Authenticode pour repérer les usurpations d'identité
              de binaires système (comme un faux <code>explorer.exe</code> ou <code>svchost.exe</code> s'exécutant dans <code>%AppData%</code> sans
              certificat officiel de Microsoft Corporation).
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={fetchSignatures}
              disabled={isLoading}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-950 hover:bg-cyan-900 border border-cyan-700 text-cyan-200 transition-colors flex items-center gap-1.5"
            >
              <RotateCcw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
              <span>Actualiser Vérification</span>
            </button>
          </div>
        </div>

        {/* Counter KPIs */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t border-slate-800/80">
          <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-lg">
            <div className="text-[11px] text-slate-400 font-mono">Binaires Clés Audités</div>
            <div className="text-xl font-bold font-mono text-white mt-0.5">{items.length}</div>
          </div>
          <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-lg">
            <div className="text-[11px] text-slate-400 font-mono">Falsifications Détectées</div>
            <div className={`text-xl font-bold font-mono mt-0.5 ${spoofedItems.length > 0 ? 'text-rose-400 animate-pulse' : 'text-slate-300'}`}>
              {spoofedItems.length}
            </div>
          </div>
          <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-lg">
            <div className="text-[11px] text-slate-400 font-mono">Signatures Microsoft Valides</div>
            <div className="text-xl font-bold font-mono text-emerald-400 mt-0.5">{legitimateItems.length}</div>
          </div>
          <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-lg">
            <div className="text-[11px] text-slate-400 font-mono">Dernier Scan Certificats</div>
            <div className="text-sm font-semibold font-mono text-slate-300 mt-1">{lastCheckTime || 'Temps réel'}</div>
          </div>
        </div>
      </div>

      {/* Critical Alert Banner if Fake explorer.exe / Spoofed Binary Detected */}
      {spoofedItems.length > 0 && (
        <div className="p-4 bg-rose-950/40 border-2 border-rose-600 rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-4 animate-in slide-in-from-top-2 duration-300 shadow-xl shadow-rose-950/50">
          <div className="flex items-start gap-3">
            <div className="w-10 h-10 rounded-xl bg-rose-900 border border-rose-500 flex items-center justify-center text-rose-300 shrink-0 shadow-md">
              <ShieldAlert className="w-5 h-5 text-rose-300 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-rose-300 font-mono uppercase tracking-wide">
                  ALERTE SÉCURITÉ CRITIQUE : FALSIFICATION DE PROCESSUS SYSTÈME
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-rose-900 text-rose-200 border border-rose-700">
                  MITRE T1036.005
                </span>
              </div>
              <p className="text-xs text-rose-100 mt-1 leading-relaxed max-w-3xl">
                Un exécutable usurpateur nommé <strong>explorer.exe</strong> a été intercepté en cours d'exécution dans un dossier utilisateur
                (<code>C:\Users\Public\AppData\Roaming\explorer.exe</code>). Cet exécutable <strong>n'est pas signé par Microsoft Corporation</strong> et
                ne réside pas dans son répertoire système légitime (<code>C:\Windows\explorer.exe</code>).
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={() => handleKillSpoofedProcess(spoofedItems[0])}
              className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs rounded-lg transition-colors flex items-center gap-1.5 shadow-md shadow-rose-900/50"
            >
              <Zap className="w-4 h-4" />
              <span>Abattre le Faux explorer.exe</span>
            </button>
          </div>
        </div>
      )}

      {/* Custom File Signature Checker Bar */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-3">
        <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
          <FileCheck className="w-4 h-4 text-cyan-400" />
          <span>Vérifier la Signature d'un Binaire ou Script Personnalisé :</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={customPath}
              onChange={(e) => setCustomPath(e.target.value)}
              placeholder="Ex: C:\Windows\explorer.exe ou C:\Temp\inconnu.exe"
              className="w-full bg-slate-950 border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-100 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>
          <button
            onClick={handleScanCustomPath}
            disabled={isScanningCustom}
            className="px-4 py-2 bg-cyan-950 hover:bg-cyan-900 border border-cyan-700 text-cyan-200 rounded-lg text-xs font-semibold transition-colors flex items-center gap-1.5 shrink-0"
          >
            <span>Vérifier Signature</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Custom result snippet */}
        {customResult && (
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono space-y-1 mt-2">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Fichier : {customResult.path}</span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                customResult.isSigned ? 'text-emerald-400 bg-emerald-950 border-emerald-800' : 'text-rose-400 bg-rose-950 border-rose-800'
              }`}>
                {customResult.signatureStatus || (customResult.isSigned ? 'VALIDE' : 'NON SIGNÉ')}
              </span>
            </div>
            <div className="text-slate-300">Signataire : {customResult.signer || 'Non signé'}</div>
            {customResult.sha256 && (
              <div className="text-slate-500 text-[11px] truncate">SHA-256 : {customResult.sha256}</div>
            )}
          </div>
        )}
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-1.5 p-1 bg-slate-900 rounded-lg border border-slate-800">
          <button
            onClick={() => setFilterType('ALL')}
            className={`px-3 py-1 rounded text-xs font-mono transition-colors ${
              filterType === 'ALL'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Tous les Binaires ({items.length})
          </button>
          <button
            onClick={() => setFilterType('SPOOFED_ONLY')}
            className={`px-3 py-1 rounded text-xs font-mono transition-colors ${
              filterType === 'SPOOFED_ONLY'
                ? 'bg-rose-950 text-rose-300 border border-rose-800'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Falsifications Détectées ({spoofedItems.length})
          </button>
          <button
            onClick={() => setFilterType('LEGITIMATE_ONLY')}
            className={`px-3 py-1 rounded text-xs font-mono transition-colors ${
              filterType === 'LEGITIMATE_ONLY'
                ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Signés Microsoft ({legitimateItems.length})
          </button>
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filtrer un nom, signataire..."
            className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Binary Inspection Cards */}
      <div className="space-y-4">
        {filteredItems.map((item) => {
          const isSpoofed = item.isSpoofed;

          return (
            <div
              key={item.id}
              className={`p-5 rounded-xl border transition-all ${
                isSpoofed
                  ? 'bg-rose-950/25 border-rose-700 shadow-lg shadow-rose-950/30'
                  : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                {/* Left: Identity & Diagnostics */}
                <div className="space-y-2 flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-base font-bold text-white">
                      {item.binaryName}
                    </span>
                    {item.pid && (
                      <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        PID {item.pid}
                      </span>
                    )}
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-bold ${
                      isSpoofed
                        ? 'text-rose-300 bg-rose-900 border-rose-600 animate-pulse'
                        : 'text-emerald-300 bg-emerald-950 border-emerald-700'
                    }`}>
                      {isSpoofed ? 'FALSIFICATION DE NOM DÉTECTÉE' : 'SIGNATURE MICROSOFT VALIDÉE'}
                    </span>
                    <span className="text-[10px] font-mono text-slate-500">
                      {item.mitreTechnique}
                    </span>
                  </div>

                  {/* Comparison: Expected Path vs Actual Path */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono pt-1">
                    <div className="p-2 rounded bg-slate-950/80 border border-slate-800">
                      <span className="text-slate-500">Emplacement Attendu : </span>
                      <span className="text-emerald-400 font-semibold">{item.expectedPath}</span>
                    </div>
                    <div className={`p-2 rounded border ${
                      isSpoofed
                        ? 'bg-rose-950/60 border-rose-800 text-rose-300 font-semibold'
                        : 'bg-slate-950/80 border-slate-800 text-slate-300'
                    }`}>
                      <span className="text-slate-500">Emplacement Réel : </span>
                      <span>{item.actualPath}</span>
                    </div>
                  </div>

                  {/* Signer Certificate */}
                  <div className="text-xs font-mono">
                    <span className="text-slate-500">Signataire Authenticode : </span>
                    <span className={isSpoofed ? 'text-rose-400 font-bold' : 'text-slate-200'}>
                      {item.signerName}
                    </span>
                  </div>

                  {/* Reason explanation */}
                  {item.spoofingReason && (
                    <p className="text-xs text-rose-200/90 bg-rose-950/50 p-2.5 rounded-lg border border-rose-800/80 leading-relaxed font-mono">
                      {item.spoofingReason}
                    </p>
                  )}

                  {/* SHA-256 */}
                  <div className="flex items-center gap-2 text-[11px] font-mono text-slate-500 pt-1">
                    <span className="truncate max-w-[280px]">SHA-256 : {item.sha256}</span>
                    <button
                      onClick={() => handleCopySha(item.sha256, item.id)}
                      className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 shrink-0"
                    >
                      {copiedId === item.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedId === item.id ? 'Copié' : 'Copier'}</span>
                    </button>
                  </div>
                </div>

                {/* Right: Remediations & Actions */}
                <div className="flex flex-wrap lg:flex-col items-end gap-2 shrink-0">
                  {isSpoofed ? (
                    <>
                      <button
                        onClick={() => handleKillSpoofedProcess(item)}
                        className="px-3.5 py-2 rounded-lg text-xs font-bold bg-rose-600 hover:bg-rose-500 text-white transition-colors flex items-center gap-1.5 shadow-md shadow-rose-950/50"
                        title="Tuer le processus falsifié immédiatement"
                      >
                        <Zap className="w-3.5 h-3.5" />
                        <span>Abattre Processus</span>
                      </button>

                      <button
                        onClick={() => onRunInConsole?.(`unlock "${item.actualPath}"`)}
                        className="px-3 py-1.5 rounded-lg text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors flex items-center gap-1.5"
                        title="Isoler et programmer la suppression au redémarrage"
                      >
                        <Lock className="w-3.5 h-3.5 text-amber-400" />
                        <span>Isoler Binaire</span>
                      </button>
                    </>
                  ) : (
                    <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-950/60 border border-emerald-800/80 text-emerald-400 text-xs font-mono font-medium">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Intègre & Officiel</span>
                    </div>
                  )}

                  <button
                    onClick={() => onRunInConsole?.(item.killOrRemediateCmd)}
                    className="px-3 py-1.5 rounded-lg text-xs font-mono text-cyan-300 hover:text-white bg-cyan-950/70 hover:bg-cyan-900 border border-cyan-800/80 transition-colors flex items-center gap-1.5"
                  >
                    <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Commande Console</span>
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
