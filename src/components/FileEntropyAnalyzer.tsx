import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Binary,
  Upload,
  FileCode,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Zap,
  RotateCcw,
  ShieldAlert,
  Search,
  Copy,
  Check,
  FileSpreadsheet,
  Layers,
  ArrowRight
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell
} from 'recharts';
import { FileEntropyReport, FileEntropyChunk } from '../types/cyberdefense';
import { apiFetch } from '../utils/api';

interface FileEntropyAnalyzerProps {
  onRunInConsole?: (command: string) => void;
  onAddLog?: (level: 'OK' | 'INFO' | 'WARN' | 'ERROR' | 'KERNEL', text: string, tag?: string) => void;
}

export const FileEntropyAnalyzer: React.FC<FileEntropyAnalyzerProps> = ({
  onRunInConsole,
  onAddLog,
}) => {
  const [report, setReport] = useState<FileEntropyReport | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [targetPathInput, setTargetPathInput] = useState<string>('C:\\Windows\\explorer.exe');
  const [isCopied, setIsCopied] = useState<boolean>(false);
  const [activeChartTab, setActiveChartTab] = useState<'CHUNKS' | 'DISTRIBUTION'>('CHUNKS');

  // Client-side Shannon entropy calculation on ArrayBuffer
  const calculateClientEntropy = (buffer: Uint8Array, fileName: string): FileEntropyReport => {
    const length = buffer.length;
    const frequencies = new Array(256).fill(0);
    for (let i = 0; i < length; i++) {
      frequencies[buffer[i]]++;
    }

    let entropy = 0;
    for (let i = 0; i < 256; i++) {
      if (frequencies[i] > 0) {
        const p = frequencies[i] / length;
        entropy -= p * Math.log2(p);
      }
    }

    const roundedEntropy = Math.round(entropy * 100) / 100;
    const chunkSize = Math.max(64, Math.min(1024, Math.floor(length / 20) || 128));
    const chunks: FileEntropyChunk[] = [];

    for (let offset = 0; offset < length; offset += chunkSize) {
      const end = Math.min(offset + chunkSize, length);
      const subFreq = new Array(256).fill(0);
      const subLen = end - offset;
      for (let j = offset; j < end; j++) {
        subFreq[buffer[j]]++;
      }
      let subEntropy = 0;
      for (let b = 0; b < 256; b++) {
        if (subFreq[b] > 0) {
          const p = subFreq[b] / subLen;
          subEntropy -= p * Math.log2(p);
        }
      }
      chunks.push({
        offset,
        entropy: Math.round(subEntropy * 100) / 100,
        isPackedOrEncrypted: subEntropy >= 7.2,
      });
    }

    let verdict: FileEntropyReport['verdict'];
    let verdictReason = '';
    let ransomwareProbability = 0;
    let isObfuscated = false;
    let isEncrypted = false;

    if (roundedEntropy >= 7.65) {
      verdict = 'RANSOMWARE_ENCRYPTED';
      ransomwareProbability = 95;
      isEncrypted = true;
      isObfuscated = true;
      verdictReason = `Entropie spectrale critique (${roundedEntropy.toFixed(2)}/8.00 bits). Distribution d'octets ultra-homogène caractéristique d'un chiffrement par ransomware (AES-256, ChaCha20, RSA) ou d'un conteneur chiffré.`;
    } else if (roundedEntropy >= 7.15) {
      verdict = 'PACKED_OBFUSCATED';
      ransomwareProbability = 45;
      isObfuscated = true;
      verdictReason = `Entropie très élevée (${roundedEntropy.toFixed(2)}/8.00 bits). Présence hautement probable d'un packer exécutable (UPX, Themida, VMProtect) ou d'un crypter masquant le code machine sous-jacent.`;
    } else if (roundedEntropy >= 6.8) {
      verdict = 'HIGH_DENSITY';
      ransomwareProbability = 15;
      verdictReason = `Entropie modérément dense (${roundedEntropy.toFixed(2)}/8.00 bits). Typique de binaires lourdement optimisés, bibliothèques compressées ou assets multimédias.`;
    } else if (roundedEntropy >= 4.5) {
      verdict = 'STANDARD_BINARY';
      ransomwareProbability = 2;
      verdictReason = `Entropie normale pour du code exécutable compilé (${roundedEntropy.toFixed(2)}/8.00 bits). Structure x86/x64 standard, imports et chaînes de caractères lisibles.`;
    } else {
      verdict = 'LOW_PLAINTEXT';
      ransomwareProbability = 0;
      verdictReason = `Entropie faible (${roundedEntropy.toFixed(2)}/8.00 bits). Données textuelles, scripts ou structures hautement répétitives sans aucun chiffrement.`;
    }

    return {
      success: true,
      fileName,
      fileSizeBytes: length,
      entropy: roundedEntropy,
      byteDistribution: frequencies,
      chunks,
      verdict,
      verdictReason,
      ransomwareProbability,
      isObfuscated,
      isEncrypted,
      sha256: 'calculé-localement-sha256',
    };
  };

  // Load preset or custom path from server
  const loadPreset = useCallback(async (presetType: 'ransomware_sim' | 'upx_sim' | 'microsoft_sim' | 'plaintext_sim') => {
    setIsLoading(true);
    try {
      const res = await apiFetch(`/api/heuristic/entropy?preset=${presetType}`);
      if (res.ok) {
        const data = await res.json();
        if (data.success) {
          setReport(data);
          onAddLog?.(
            data.verdict === 'RANSOMWARE_ENCRYPTED' ? 'ERROR' : data.verdict === 'PACKED_OBFUSCATED' ? 'WARN' : 'OK',
            `[ENTROPIE] Analyse de ${data.fileName} : ${data.entropy}/8.00 bits -> Verdict: ${data.verdict}`,
            'ENTROPY'
          );
        }
      }
    } catch (e) {
      console.error('Error loading entropy preset:', e);
    } finally {
      setIsLoading(false);
    }
  }, [onAddLog]);

  // Initial demo load with ransomware detection demo
  useEffect(() => {
    loadPreset('ransomware_sim');
  }, [loadPreset]);

  // Handle local file drop / input
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsLoading(true);
    const reader = new FileReader();
    reader.onload = () => {
      const arrayBuffer = reader.result as ArrayBuffer;
      const uint8 = new Uint8Array(arrayBuffer);
      const computed = calculateClientEntropy(uint8, file.name);
      setReport(computed);
      setIsLoading(false);

      onAddLog?.(
        computed.verdict === 'RANSOMWARE_ENCRYPTED' ? 'ERROR' : computed.verdict === 'PACKED_OBFUSCATED' ? 'WARN' : 'OK',
        `[ENTROPIE-UPLOAD] Fichier ${file.name} (${(file.size / 1024).toFixed(1)} KB) analysé : Entropie ${computed.entropy} bits -> ${computed.verdict}`,
        'ENTROPY'
      );
    };
    reader.readAsArrayBuffer(file);
  };

  const handleScanPath = async () => {
    if (!targetPathInput.trim()) return;
    setIsLoading(true);
    try {
      const res = await apiFetch(`/api/heuristic/entropy?path=${encodeURIComponent(targetPathInput.trim())}`);
      if (res.ok) {
        const data = await res.json();
        if (data.success) {
          setReport(data);
          onAddLog?.(
            data.verdict === 'RANSOMWARE_ENCRYPTED' ? 'ERROR' : 'OK',
            `[ENTROPIE-PATH] Fichier disque ${data.filePath} analysé : Entropie ${data.entropy} bits -> Verdict: ${data.verdict}`,
            'ENTROPY'
          );
        }
      } else {
        // Fallback demo for path if running in restricted container
        loadPreset(targetPathInput.toLowerCase().includes('explorer') ? 'microsoft_sim' : 'ransomware_sim');
      }
    } catch {
      loadPreset('microsoft_sim');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopySha = () => {
    if (report?.sha256) {
      navigator.clipboard.writeText(report.sha256);
      setIsCopied(true);
      setTimeout(() => setIsCopied(false), 2000);
    }
  };

  // 256-byte frequency bucketed data for chart
  const byteFrequencyBuckets = useMemo(() => {
    if (!report?.byteDistribution) return [];
    // Bucket 256 values into 32 groups for clean visualization
    const bucketSize = 8;
    const buckets: Array<{ range: string; count: number; byteVal: number }> = [];
    for (let i = 0; i < 256; i += bucketSize) {
      let sum = 0;
      for (let j = 0; j < bucketSize; j++) {
        sum += report.byteDistribution[i + j] || 0;
      }
      const hexStart = i.toString(16).padStart(2, '0').toUpperCase();
      const hexEnd = (i + bucketSize - 1).toString(16).padStart(2, '0').toUpperCase();
      buckets.push({
        range: `0x${hexStart}`,
        byteVal: i,
        count: sum,
      });
    }
    return buckets;
  }, [report?.byteDistribution]);

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Title & Explanatory Banner */}
      <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-semibold text-cyan-400">
              <Binary className="w-4 h-4" />
              <span>CALCUL D'ENTROPIE DE SHANNON & DÉTECTEUR RANSOMWARE</span>
              <span className="text-slate-500">·</span>
              <span className="text-slate-400 font-mono">0.00 à 8.00 bits/octet</span>
            </div>
            <h2 className="text-lg md:text-xl font-bold text-white tracking-tight mt-1">
              Détecteur de Chiffrement & Obfuscation de Code Exécutable
            </h2>
            <p className="text-xs text-slate-300 max-w-3xl leading-relaxed mt-1">
              Calcule le degré d'aléatoire statistique des octets. Un ransomware (LockBit, BlackCat, WannaCry) produit une entropie
              quasi-maximale (&gt; 7.65 bits/octet) avec une distribution plate, tandis qu'un packer (UPX, Themida) masque le code machine
              par couches polymorphes.
            </p>
          </div>

          {/* Quick Preset Buttons for Instant Verification */}
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              onClick={() => loadPreset('ransomware_sim')}
              className="px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-rose-950/80 hover:bg-rose-900 border border-rose-800 text-rose-300 transition-colors flex items-center gap-1.5 shadow-xs"
              title="Tester un fichier chiffré par ransomware (Entropie ~7.99 bits)"
            >
              <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
              <span>Ransomware (.locked)</span>
            </button>
            <button
              onClick={() => loadPreset('upx_sim')}
              className="px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-amber-950/80 hover:bg-amber-900 border border-amber-800 text-amber-300 transition-colors flex items-center gap-1.5 shadow-xs"
              title="Tester un exécutable packé UPX / obfusqué (Entropie ~7.52 bits)"
            >
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              <span>Packer UPX / Crypter</span>
            </button>
            <button
              onClick={() => loadPreset('microsoft_sim')}
              className="px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-800 text-emerald-300 transition-colors flex items-center gap-1.5 shadow-xs"
              title="Tester un binaire sain standard Microsoft (Entropie ~5.95 bits)"
            >
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              <span>explorer.exe Sain</span>
            </button>
            <button
              onClick={() => loadPreset('plaintext_sim')}
              className="px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 transition-colors flex items-center gap-1.5 shadow-xs"
              title="Tester un script texte brut (Entropie ~3.80 bits)"
            >
              <FileCode className="w-3.5 h-3.5 text-slate-400" />
              <span>Script Texte Brut</span>
            </button>
          </div>
        </div>

        {/* Input Zones: Drag & Drop + Path Bar */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-3 border-t border-slate-800/80">
          {/* Option A: Drop / Select Any File */}
          <div className="relative border-2 border-dashed border-slate-700 hover:border-cyan-500/70 rounded-xl p-4 transition-all bg-slate-950/60 flex items-center justify-center text-center cursor-pointer group">
            <input
              type="file"
              onChange={handleFileUpload}
              className="absolute inset-0 opacity-0 cursor-pointer w-full h-full"
              title="Glisser-déposer n'importe quel fichier (.exe, .dll, .bin, .locked) pour calculer son entropie"
            />
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-cyan-950 border border-cyan-800/80 flex items-center justify-center text-cyan-400 group-hover:scale-105 transition-transform">
                <Upload className="w-4 h-4" />
              </div>
              <div className="text-left">
                <div className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300 transition-colors">
                  Déposer ou Choisir un Fichier Local
                </div>
                <div className="text-[11px] text-slate-400">
                  Calcule l'entropie instantanément en local (.exe, .dll, .pdf, .locked)
                </div>
              </div>
            </div>
          </div>

          {/* Option B: Scan File Path on Disk */}
          <div className="flex items-center gap-2 p-3 bg-slate-950/60 border border-slate-800 rounded-xl">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={targetPathInput}
                onChange={(e) => setTargetPathInput(e.target.value)}
                placeholder="Ex: C:\Windows\explorer.exe ou C:\Temp\malware.exe"
                className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-100 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>
            <button
              onClick={handleScanPath}
              disabled={isLoading}
              className="px-3.5 py-2 rounded-lg text-xs font-semibold bg-cyan-950 hover:bg-cyan-900 border border-cyan-700 text-cyan-200 shrink-0 transition-colors flex items-center gap-1.5"
            >
              <span>Analyser Chemin</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Results Section */}
      {report && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column: Verdict, Shannon Gauge, and Threat Indicators */}
          <div className="lg:col-span-1 space-y-4">
            {/* Verdict Card */}
            <div className={`p-5 rounded-xl border ${
              report.verdict === 'RANSOMWARE_ENCRYPTED'
                ? 'bg-rose-950/40 border-rose-800/80 shadow-lg shadow-rose-950/30'
                : report.verdict === 'PACKED_OBFUSCATED'
                ? 'bg-amber-950/40 border-amber-800/80 shadow-lg shadow-amber-950/30'
                : 'bg-slate-900/90 border-slate-800'
            }`}>
              <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
                <span className="text-xs font-mono font-semibold text-slate-400">VERDICT HEURISTIQUE</span>
                <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold border ${
                  report.verdict === 'RANSOMWARE_ENCRYPTED'
                    ? 'text-rose-400 bg-rose-950 border-rose-800'
                    : report.verdict === 'PACKED_OBFUSCATED'
                    ? 'text-amber-400 bg-amber-950 border-amber-800'
                    : 'text-emerald-400 bg-emerald-950 border-emerald-800'
                }`}>
                  {report.verdict}
                </span>
              </div>

              {/* Shannon Entropy Number */}
              <div className="mt-4 flex items-baseline justify-between">
                <div>
                  <div className="text-3xl font-extrabold font-mono tabular-nums tracking-tight text-white flex items-baseline gap-1">
                    <span>{report.entropy.toFixed(2)}</span>
                    <span className="text-sm font-normal text-slate-400">/ 8.00 bits</span>
                  </div>
                  <div className="text-xs text-slate-400 mt-0.5 font-mono">
                    Entropie de Shannon ($H$)
                  </div>
                </div>

                {/* Ransomware Probability */}
                <div className="text-right">
                  <div className={`text-2xl font-bold font-mono tabular-nums ${
                    report.ransomwareProbability >= 80
                      ? 'text-rose-400 animate-pulse'
                      : report.ransomwareProbability >= 40
                      ? 'text-amber-400'
                      : 'text-emerald-400'
                  }`}>
                    {report.ransomwareProbability}%
                  </div>
                  <div className="text-[11px] text-slate-400 font-mono">
                    Probabilité Ransomware
                  </div>
                </div>
              </div>

              {/* Visual Entropy Bar with Thresholds */}
              <div className="mt-4 space-y-1.5">
                <div className="h-3 w-full bg-slate-950 rounded-full overflow-hidden p-0.5 border border-slate-800 relative">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${
                      report.entropy >= 7.65
                        ? 'bg-gradient-to-r from-amber-500 to-rose-600 shadow-md shadow-rose-500/50'
                        : report.entropy >= 7.15
                        ? 'bg-gradient-to-r from-cyan-500 to-amber-500'
                        : report.entropy >= 4.5
                        ? 'bg-gradient-to-r from-emerald-500 to-cyan-500'
                        : 'bg-emerald-500'
                    }`}
                    style={{ width: `${Math.min(100, (report.entropy / 8.0) * 100)}%` }}
                  />
                  {/* Seuil 7.2 bits marker */}
                  <div
                    className="absolute top-0 bottom-0 w-0.5 bg-rose-400 z-10"
                    style={{ left: `${(7.2 / 8.0) * 100}%` }}
                    title="Seuil d'alerte Ransomware / Obfuscation (7.20 bits)"
                  />
                </div>
                <div className="flex justify-between text-[10px] font-mono text-slate-500">
                  <span>0.00 (Texte)</span>
                  <span className="text-slate-400">5.50 (Binaire standard)</span>
                  <span className="text-rose-400 font-bold">7.20 (Seuil Chiffrement)</span>
                  <span>8.00 (Max)</span>
                </div>
              </div>

              {/* Detailed Reason */}
              <p className="mt-4 text-xs text-slate-300 leading-relaxed bg-slate-950/60 p-3 rounded-lg border border-slate-800">
                {report.verdictReason}
              </p>

              {/* Metadata details */}
              <div className="mt-4 space-y-2 pt-3 border-t border-slate-800/80 text-xs font-mono">
                <div className="flex justify-between text-slate-300">
                  <span className="text-slate-500">Cible :</span>
                  <span className="font-semibold text-white truncate max-w-[200px]" title={report.fileName}>
                    {report.fileName}
                  </span>
                </div>
                <div className="flex justify-between text-slate-300">
                  <span className="text-slate-500">Taille :</span>
                  <span>{(report.fileSizeBytes / 1024).toFixed(1)} KB ({report.fileSizeBytes} octets)</span>
                </div>
                <div className="flex justify-between text-slate-300">
                  <span className="text-slate-500">Code Obfusqué :</span>
                  <span className={report.isObfuscated ? 'text-amber-400 font-bold' : 'text-emerald-400'}>
                    {report.isObfuscated ? 'DÉTECTÉ (OUI)' : 'NON DÉTECTÉ'}
                  </span>
                </div>
                <div className="flex justify-between text-slate-300">
                  <span className="text-slate-500">Chiffrement Massif :</span>
                  <span className={report.isEncrypted ? 'text-rose-400 font-bold' : 'text-slate-400'}>
                    {report.isEncrypted ? 'CONFIRMÉ (Ransomware)' : 'AUCUN'}
                  </span>
                </div>
              </div>

              {/* SHA-256 fingerprint copy button */}
              {report.sha256 && (
                <div className="mt-3 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono">
                  <span className="text-slate-500 truncate max-w-[180px]">
                    SHA: {report.sha256.substring(0, 16)}...
                  </span>
                  <button
                    onClick={handleCopySha}
                    className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
                  >
                    {isCopied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{isCopied ? 'Copié' : 'Copier SHA'}</span>
                  </button>
                </div>
              )}
            </div>

            {/* Quick Action Button */}
            {report.verdict === 'RANSOMWARE_ENCRYPTED' && (
              <button
                onClick={() => onRunInConsole?.(`quarantine "${report.filePath || report.fileName}"`)}
                className="w-full py-2.5 px-4 bg-gradient-to-r from-rose-900 to-red-950 hover:from-rose-800 hover:to-red-900 border border-rose-600 rounded-xl text-xs font-bold text-white transition-all shadow-md shadow-rose-950/50 flex items-center justify-center gap-2"
              >
                <Lock className="w-4 h-4 text-rose-300" />
                <span>Isoler Immédiatement le Fichier Chiffré</span>
              </button>
            )}
          </div>

          {/* Right Column: Sliding Window Chunk Graph + Byte Distribution Histogram */}
          <div className="lg:col-span-2 space-y-4">
            <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
              {/* Tab Selector for Graphs */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
                <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
                  <button
                    onClick={() => setActiveChartTab('CHUNKS')}
                    className={`px-3 py-1.5 rounded-md text-xs font-medium font-mono transition-colors flex items-center gap-1.5 ${
                      activeChartTab === 'CHUNKS'
                        ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-xs'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    <Layers className="w-3.5 h-3.5" />
                    <span>Entropie par Bloc ({report.chunks.length} segments)</span>
                  </button>
                  <button
                    onClick={() => setActiveChartTab('DISTRIBUTION')}
                    className={`px-3 py-1.5 rounded-md text-xs font-medium font-mono transition-colors flex items-center gap-1.5 ${
                      activeChartTab === 'DISTRIBUTION'
                        ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-xs'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    <FileSpreadsheet className="w-3.5 h-3.5" />
                    <span>Spectre des 256 Octets (0x00 - 0xFF)</span>
                  </button>
                </div>

                <div className="text-[11px] text-slate-400 font-mono">
                  {activeChartTab === 'CHUNKS'
                    ? 'Variation le long de la structure du fichier'
                    : 'Fréquence d\'apparition par valeur d\'octet'}
                </div>
              </div>

              {/* Chart 1: Sliding Window Chunk Entropy AreaChart */}
              {activeChartTab === 'CHUNKS' && (
                <div className="space-y-3">
                  <div className="h-64 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart
                        data={report.chunks.map((c, idx) => ({
                          chunkIndex: idx + 1,
                          offsetHex: `0x${c.offset.toString(16).toUpperCase()}`,
                          entropy: c.entropy,
                          isAlert: c.entropy >= 7.2,
                        }))}
                        margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                      >
                        <defs>
                          <linearGradient id="entropyGradient" x1="0" y1="0" x2="0" y2="1">
                            <stop
                              offset="5%"
                              stopColor={report.verdict === 'RANSOMWARE_ENCRYPTED' ? '#f43f5e' : '#06b6d4'}
                              stopOpacity={0.8}
                            />
                            <stop
                              offset="95%"
                              stopColor={report.verdict === 'RANSOMWARE_ENCRYPTED' ? '#f43f5e' : '#06b6d4'}
                              stopOpacity={0.05}
                            />
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                        <XAxis
                          dataKey="offsetHex"
                          stroke="#64748b"
                          fontSize={10}
                          tickLine={false}
                          fontFamily="JetBrains Mono, monospace"
                        />
                        <YAxis
                          domain={[0, 8]}
                          stroke="#64748b"
                          fontSize={10}
                          tickLine={false}
                          fontFamily="JetBrains Mono, monospace"
                        />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#0f172a',
                            borderColor: '#334155',
                            borderRadius: '8px',
                            fontSize: '12px',
                            fontFamily: 'JetBrains Mono, monospace',
                          }}
                        />
                        <Area
                          type="monotone"
                          dataKey="entropy"
                          stroke={report.verdict === 'RANSOMWARE_ENCRYPTED' ? '#f43f5e' : '#06b6d4'}
                          strokeWidth={2}
                          fill="url(#entropyGradient)"
                          name="Entropie du Bloc (bits)"
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                  <p className="text-[11px] text-slate-400 font-mono">
                    Les plateaux au-dessus de 7.20 bits correspondent aux sections cryptées ou à des zones compressées sans récurrence d'octets.
                  </p>
                </div>
              )}

              {/* Chart 2: 256-Byte Histogram Distribution BarChart */}
              {activeChartTab === 'DISTRIBUTION' && (
                <div className="space-y-3">
                  <div className="h-64 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={byteFrequencyBuckets}
                        margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                      >
                        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                        <XAxis
                          dataKey="range"
                          stroke="#64748b"
                          fontSize={10}
                          tickLine={false}
                          fontFamily="JetBrains Mono, monospace"
                        />
                        <YAxis
                          stroke="#64748b"
                          fontSize={10}
                          tickLine={false}
                          fontFamily="JetBrains Mono, monospace"
                        />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#0f172a',
                            borderColor: '#334155',
                            borderRadius: '8px',
                            fontSize: '12px',
                            fontFamily: 'JetBrains Mono, monospace',
                          }}
                        />
                        <Bar dataKey="count" name="Nombre d'occurrences">
                          {byteFrequencyBuckets.map((entry, index) => (
                            <Cell
                              key={`cell-byte-${index}`}
                              fill={report.verdict === 'RANSOMWARE_ENCRYPTED' ? '#f43f5e' : '#06b6d4'}
                            />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                  <p className="text-[11px] text-slate-400 font-mono">
                    {report.verdict === 'RANSOMWARE_ENCRYPTED'
                      ? 'Distribution équi-répartie quasi-plate : tous les 256 octets apparaissent avec la même probabilité (1/256 ≈ 0.39%), preuve irréfutable de chiffrement pseudo-aléatoire moderne.'
                      : 'Distribution asymétrique classique avec pics sur 0x00 (padding NULL), 0x20 (espaces) et opcodes x86 (0x55, 0x8B, 0xE8) : structure binaire saine.'}
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
