import React, { useState } from 'react';
import {
  FileText,
  Download,
  X,
  ShieldCheck,
  ShieldAlert,
  CheckCircle2,
  PieChart,
  Network,
  Activity,
  Layers,
  Sparkles,
  Lock,
  Printer,
  ChevronRight,
  RefreshCw,
} from 'lucide-react';
import { ThreatItem, ConsoleLogMessage } from '../types/cyberdefense';
import {
  calculateSecurityScore,
  generateAndDownloadPdfReport,
} from '../utils/pdfReportGenerator';

interface PdfReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  threats: ThreatItem[];
  logs: ConsoleLogMessage[];
  onNotifySuccess?: (msg: string) => void;
}

export const PdfReportModal: React.FC<PdfReportModalProps> = ({
  isOpen,
  onClose,
  threats,
  logs,
  onNotifySuccess,
}) => {
  const [includeCharts, setIncludeCharts] = useState(true);
  const [includeIocs, setIncludeIocs] = useState(true);
  const [includeLogs, setIncludeLogs] = useState(true);
  const [auditorName, setAuditorName] = useState('Ingénieur Cybersécurité (Admin)');
  const [isGenerating, setIsGenerating] = useState(false);
  const [downloadCompleted, setDownloadCompleted] = useState(false);

  if (!isOpen) return null;

  const scoreData = calculateSecurityScore(threats);

  const handleDownload = async () => {
    setIsGenerating(true);
    try {
      await generateAndDownloadPdfReport(threats, logs, {
        includeCharts,
        includeIocs,
        includeLogs,
        auditorName,
      });
      setDownloadCompleted(true);
      if (onNotifySuccess) {
        onNotifySuccess('Rapport PDF complet téléchargé avec succès !');
      }
      setTimeout(() => {
        setIsGenerating(false);
      }, 1000);
    } catch (err) {
      console.error('Error generating PDF report:', err);
      setIsGenerating(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-3xl bg-slate-950 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        
        {/* Modal Top Header */}
        <div className="px-6 py-4 bg-gradient-to-r from-slate-900 via-slate-900 to-slate-950 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-950/80 border border-cyan-800 flex items-center justify-center text-cyan-400">
              <FileText className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white tracking-tight">
                  Générateur de Rapport PDF Forensique & Menaces
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800 font-semibold">
                  PDF HAUTE DÉFINITION
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Synthèse exécutive, graphiques vectoriels du score de sécurité, matrice MITRE et indicateurs IOCs
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

        {/* Modal Scrollable Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1">
          
          {/* Security Score Preview Card */}
          <div className="p-5 bg-slate-900/90 border border-slate-800 rounded-xl relative overflow-hidden">
            <div className="flex flex-col md:flex-row items-center justify-between gap-6">
              
              {/* Score Dial & Value */}
              <div className="flex items-center gap-5">
                <div className="relative w-24 h-24 flex items-center justify-center">
                  <svg className="w-24 h-24 transform -rotate-90" viewBox="0 0 100 100">
                    <circle
                      cx="50"
                      cy="50"
                      r="40"
                      stroke="#1e293b"
                      strokeWidth="10"
                      fill="transparent"
                    />
                    <circle
                      cx="50"
                      cy="50"
                      r="40"
                      stroke={scoreData.ratingColor}
                      strokeWidth="10"
                      strokeDasharray={251.2}
                      strokeDashoffset={251.2 - (251.2 * scoreData.score) / 100}
                      strokeLinecap="round"
                      fill="transparent"
                      className="transition-all duration-700 ease-out"
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                    <span className="text-2xl font-bold font-mono text-white leading-none">
                      {scoreData.score}
                    </span>
                    <span className="text-[10px] text-slate-400 font-mono">/ 100</span>
                  </div>
                </div>

                <div className="space-y-1">
                  <div className="text-xs font-mono uppercase tracking-wider text-slate-400">
                    Score de Posture Globale
                  </div>
                  <div
                    className="text-lg font-bold font-mono"
                    style={{ color: scoreData.ratingColor }}
                  >
                    {scoreData.ratingLabel}
                  </div>
                  <div className="text-xs text-slate-400 leading-relaxed">
                    Calculé en temps réel sur {scoreData.totalThreats} menaces identifiées,
                    dont {scoreData.criticalCount} critique(s) et {scoreData.neutralizedCount} neutralisée(s).
                  </div>
                </div>
              </div>

              {/* Mini Quick Stats Strip */}
              <div className="grid grid-cols-2 gap-2 w-full md:w-auto shrink-0 text-xs">
                <div className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800/80">
                  <span className="text-slate-400 text-[10px] block">CRITIQUES</span>
                  <span className="text-base font-bold text-rose-400 font-mono">
                    {scoreData.criticalCount}
                  </span>
                </div>
                <div className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800/80">
                  <span className="text-slate-400 text-[10px] block">RISQUE ÉLEVÉ</span>
                  <span className="text-base font-bold text-orange-400 font-mono">
                    {scoreData.highCount}
                  </span>
                </div>
                <div className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800/80">
                  <span className="text-slate-400 text-[10px] block">MOYENNES</span>
                  <span className="text-base font-bold text-amber-400 font-mono">
                    {scoreData.mediumCount}
                  </span>
                </div>
                <div className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800/80">
                  <span className="text-slate-400 text-[10px] block">TRAITÉES</span>
                  <span className="text-base font-bold text-emerald-400 font-mono">
                    {scoreData.neutralizedCount}
                  </span>
                </div>
              </div>

            </div>
          </div>

          {/* Configuration Options */}
          <div className="space-y-3">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono">
              Sections et Graphiques Inclus dans le Document PDF
            </h4>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {/* Option 1: Charts */}
              <label className="flex items-start gap-3 p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 cursor-pointer transition-colors">
                <input
                  type="checkbox"
                  checked={includeCharts}
                  onChange={e => setIncludeCharts(e.target.checked)}
                  className="mt-1 rounded bg-slate-800 border-slate-700 text-cyan-500 focus:ring-0 focus:ring-offset-0"
                />
                <div className="space-y-0.5">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-200">
                    <PieChart className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Graphiques de Score</span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-tight">
                    Jauge circulaire, camembert de répartition et barres de couverture
                  </p>
                </div>
              </label>

              {/* Option 2: IOCs */}
              <label className="flex items-start gap-3 p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 cursor-pointer transition-colors">
                <input
                  type="checkbox"
                  checked={includeIocs}
                  onChange={e => setIncludeIocs(e.target.checked)}
                  className="mt-1 rounded bg-slate-800 border-slate-700 text-cyan-500 focus:ring-0 focus:ring-offset-0"
                />
                <div className="space-y-0.5">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-200">
                    <Network className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Indicateurs IOCs & C2</span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-tight">
                    IPs de command & control, ports réseau, protocoles et origines géo
                  </p>
                </div>
              </label>

              {/* Option 3: Logs */}
              <label className="flex items-start gap-3 p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 cursor-pointer transition-colors">
                <input
                  type="checkbox"
                  checked={includeLogs}
                  onChange={e => setIncludeLogs(e.target.checked)}
                  className="mt-1 rounded bg-slate-800 border-slate-700 text-cyan-500 focus:ring-0 focus:ring-offset-0"
                />
                <div className="space-y-0.5">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-200">
                    <Activity className="w-3.5 h-3.5 text-purple-400" />
                    <span>Recommandations</span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-tight">
                    Checklist d'assainissement et signature cryptographique d'audit
                  </p>
                </div>
              </label>
            </div>
          </div>

          {/* Auditor Name Field */}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-300 font-mono">
              Identité de l'auditeur / Responsable Cybersécurité :
            </label>
            <input
              type="text"
              value={auditorName}
              onChange={e => setAuditorName(e.target.value)}
              placeholder="Ex: Ingénieur Sécurité - CIRT / SOC L2"
              className="w-full px-3.5 py-2 text-xs bg-slate-900 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          {/* Report Features Showcase */}
          <div className="p-4 rounded-xl bg-cyan-950/30 border border-cyan-800/40 text-xs space-y-2">
            <div className="flex items-center gap-2 text-cyan-300 font-semibold">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              <span>Contenu certifié du document PDF généré :</span>
            </div>
            <ul className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] text-slate-300">
              <li className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span>Format A4 professionnel multi-pages avec pagination</span>
              </li>
              <li className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span>Tableau d'analyse complet avec techniques MITRE ATT&CK</span>
              </li>
              <li className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span>Statut des verrous TrustedInstaller & Handles ouverts</span>
              </li>
              <li className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span>Empreinte de contrôle SHA-256 pour conformité d'audit</span>
              </li>
            </ul>
          </div>

        </div>

        {/* Modal Bottom Footer Actions */}
        <div className="px-6 py-4 bg-slate-900/90 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="text-xs text-slate-400 font-mono">
            Nom du fichier : <span className="text-slate-200">SpaceSec_Rapport_Menaces_*.pdf</span>
          </div>

          <div className="flex items-center gap-3 w-full sm:w-auto">
            <button
              onClick={onClose}
              className="w-full sm:w-auto px-4 py-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors"
            >
              Fermer
            </button>

            <button
              onClick={handleDownload}
              disabled={isGenerating}
              className="w-full sm:w-auto flex items-center justify-center gap-2 px-5 py-2.5 text-xs font-bold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg transition-all shadow-md shadow-cyan-500/20 active:translate-y-px disabled:opacity-50"
            >
              {isGenerating ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
                  <span>Génération en cours...</span>
                </>
              ) : downloadCompleted ? (
                <>
                  <CheckCircle2 className="w-4 h-4 text-slate-950" />
                  <span>Téléchargé ! Re-télécharger</span>
                </>
              ) : (
                <>
                  <Download className="w-4 h-4 text-slate-950" />
                  <span>Générer & Télécharger le Rapport PDF</span>
                </>
              )}
            </button>
          </div>
        </div>

      </div>
    </div>
  );
};
