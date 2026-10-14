import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw, Home, Copy, Check, ChevronDown, ChevronUp, Terminal, ShieldAlert } from 'lucide-react';

interface ErrorBoundaryProps {
  children: ReactNode;
  moduleName?: string;
  isGlobal?: boolean;
  onReset?: () => void;
  fallback?: ReactNode | ((error: Error, reset: () => void) => ReactNode);
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
  copied: boolean;
  showDetails: boolean;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      copied: false,
      showDetails: false,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    this.setState({ errorInfo });
    // Structured error logging for incident review
    console.error(`[SpaceSec-ErrorBoundary] Crash in module '${this.props.moduleName || 'Global'}':`, error, errorInfo);
  }

  handleReset = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
      copied: false,
      showDetails: false,
    });
    if (this.props.onReset) {
      this.props.onReset();
    }
  };

  handleCopyReport = () => {
    const { error, errorInfo } = this.state;
    const { moduleName } = this.props;
    const report = [
      `=== SPACE SECURITY CRASH INCIDENT REPORT ===`,
      `Date/Time: ${new Date().toISOString()}`,
      `Module: ${moduleName || 'Global App View'}`,
      `User Agent: ${typeof navigator !== 'undefined' ? navigator.userAgent : 'Unknown'}`,
      `Error Name: ${error?.name || 'Error'}`,
      `Error Message: ${error?.message || 'Unknown error occurred'}`,
      `\n--- Stack Trace ---`,
      error?.stack || 'No JS stack available',
      `\n--- Component Stack ---`,
      errorInfo?.componentStack || 'No React component stack available',
      `=============================================`,
    ].join('\n');

    navigator.clipboard.writeText(report).then(() => {
      this.setState({ copied: true });
      setTimeout(() => this.setState({ copied: false }), 2500);
    });
  };

  render() {
    const { hasError, error, errorInfo, copied, showDetails } = this.state;
    const { children, moduleName, isGlobal, fallback } = this.props;

    if (!hasError) {
      return children;
    }

    if (fallback) {
      if (typeof fallback === 'function') {
        return fallback(error || new Error('Unknown error'), this.handleReset);
      }
      return fallback;
    }

    // Global Root Crash Layout
    if (isGlobal) {
      return (
        <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-6 selection:bg-rose-500/30 selection:text-rose-200">
          <div className="max-w-2xl w-full bg-slate-900 border border-rose-500/40 rounded-xl shadow-2xl p-6 sm:p-8 space-y-6 relative overflow-hidden backdrop-blur-md">
            {/* Ambient Background Glow */}
            <div className="absolute -top-24 -right-24 w-64 h-64 bg-rose-600/10 rounded-full blur-3xl pointer-events-none" />
            <div className="absolute -bottom-24 -left-24 w-64 h-64 bg-cyan-600/10 rounded-full blur-3xl pointer-events-none" />

            {/* Header */}
            <div className="flex items-start gap-4">
              <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl text-rose-400 shrink-0">
                <ShieldAlert className="w-8 h-8 animate-pulse" />
              </div>
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30 uppercase tracking-widest">
                    Exception Critique
                  </span>
                  <span className="text-xs text-slate-400 font-mono">CODE: SEV-1-FATAL</span>
                </div>
                <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
                  Interruption du Noyau CyberDéfense
                </h1>
                <p className="text-sm text-slate-400 leading-relaxed">
                  Une anomalie non interceptée a interrompu le moteur d'interface. Pour préserver l'intégrité de vos sessions et de vos données, l'écran a été isolé dans ce bac à sable de sécurité.
                </p>
              </div>
            </div>

            {/* Error Message Box */}
            <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-4 font-mono text-xs text-rose-300 break-words flex items-start gap-3">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div>
                <span className="text-slate-400 font-semibold">{error?.name || 'Error'}: </span>
                <span>{error?.message || 'Erreur d’exécution inattendue'}</span>
              </div>
            </div>

            {/* Actions */}
            <div className="flex flex-wrap items-center gap-3 pt-2">
              <button
                type="button"
                onClick={this.handleReset}
                className="px-4 py-2 bg-gradient-to-r from-rose-600 to-rose-700 hover:from-rose-500 hover:to-rose-600 text-white font-medium rounded-lg text-sm flex items-center gap-2 shadow-lg shadow-rose-900/30 transition-all cursor-pointer active:scale-95"
              >
                <RefreshCw className="w-4 h-4" />
                <span>Réinitialiser la session</span>
              </button>

              <button
                type="button"
                onClick={() => window.location.reload()}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-sm font-medium flex items-center gap-2 transition-all cursor-pointer"
              >
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span>Recharger la page</span>
              </button>

              <button
                type="button"
                onClick={this.handleCopyReport}
                className="px-3.5 py-2 bg-slate-800/80 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded-lg text-sm font-medium flex items-center gap-2 transition-all cursor-pointer"
                title="Copier le diagnostic technique pour analyse"
              >
                {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                <span>{copied ? 'Rapport copié !' : 'Copier diagnostic'}</span>
              </button>

              <button
                type="button"
                onClick={() => this.setState({ showDetails: !showDetails })}
                className="ml-auto text-xs text-slate-400 hover:text-slate-300 flex items-center gap-1 transition-colors cursor-pointer"
              >
                <span>{showDetails ? 'Masquer' : 'Afficher'} détails</span>
                {showDetails ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              </button>
            </div>

            {/* Collapsible Tech Stack */}
            {showDetails && (
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-[11px] font-mono text-slate-400 max-h-56 overflow-y-auto space-y-2">
                <div className="text-slate-300 font-bold border-b border-slate-800 pb-1">Trace d'appel (Stack Trace) :</div>
                <pre className="text-rose-400 whitespace-pre-wrap">{error?.stack || 'Pas de trace de pile disponible'}</pre>
                {errorInfo && (
                  <>
                    <div className="text-slate-300 font-bold border-b border-slate-800 pb-1 pt-2">Hiérarchie React :</div>
                    <pre className="text-slate-400 whitespace-pre-wrap">{errorInfo.componentStack}</pre>
                  </>
                )}
              </div>
            )}
          </div>
        </div>
      );
    }

    // Component / Tab Panel Isolation Layout
    return (
      <div className="bg-slate-900/90 border border-rose-500/30 rounded-xl p-6 sm:p-7 shadow-xl space-y-5 my-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-400 shrink-0">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                  Incident Localisé
                </span>
                <span className="text-xs text-slate-400 font-mono">MODULE: {moduleName || 'Inconnu'}</span>
              </div>
              <h3 className="text-base font-bold text-white mt-1">
                Anomalie d'affichage dans le module "{moduleName || 'Composant'}"
              </h3>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={this.handleReset}
              className="px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 shadow-sm transition-all cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Relancer ce module</span>
            </button>
            <button
              type="button"
              onClick={this.handleCopyReport}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copié !' : 'Copier'}</span>
            </button>
          </div>
        </div>

        <div className="bg-slate-950/70 border border-slate-800/80 rounded-lg p-3.5 font-mono text-xs text-rose-300/90 break-words flex items-start gap-2.5">
          <Terminal className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div>
            <span className="text-slate-400 font-semibold">{error?.name || 'Erreur'}: </span>
            <span>{error?.message || 'Erreur de rendu interceptée avec succès.'}</span>
            <p className="text-[11px] text-slate-400 mt-1 font-sans">
              Le reste de l'application (surveillance réseau, console kernel, notifications de menaces) demeure pleinement fonctionnel.
            </p>
          </div>
        </div>

        <div className="flex items-center justify-between text-xs text-slate-400">
          <button
            type="button"
            onClick={() => this.setState({ showDetails: !showDetails })}
            className="hover:text-slate-200 flex items-center gap-1 transition-colors cursor-pointer"
          >
            <span>{showDetails ? 'Masquer' : 'Afficher'} les détails de la pile</span>
            {showDetails ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        </div>

        {showDetails && (
          <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-3 text-[11px] font-mono text-slate-400 max-h-48 overflow-y-auto">
            <pre className="text-rose-400/90 whitespace-pre-wrap">{error?.stack || 'Aucune trace de pile disponible'}</pre>
          </div>
        )}
      </div>
    );
  }
}
