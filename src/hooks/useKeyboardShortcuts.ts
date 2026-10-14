import { useEffect, useState, useCallback, useRef } from 'react';
import { TabId } from '../types/cyberdefense';

export interface ShortcutDefinition {
  id: string;
  label: string;
  description: string;
  keyCombo: string;
  category: 'CORE_ACTIONS' | 'NAVIGATION' | 'SYSTEM';
  badge: string;
  actionCommand?: string;
  handler: () => void;
}

interface UseKeyboardShortcutsProps {
  onScan: (deep?: boolean) => void;
  onClearLogs: () => void;
  onExportReport: () => void;
  onNavigateTab: (tab: TabId) => void;
  onCloseModals?: () => void;
  onNotify?: (title: string, description: string, keyCombo: string) => void;
  enabled?: boolean;
}

/**
 * Checks whether the keyboard event originated from an editable field
 * (input, textarea, select, contentEditable) to avoid hijacking user typing.
 */
function isEditableElement(element: EventTarget | null): boolean {
  if (!element || !(element instanceof HTMLElement)) return false;
  const tagName = element.tagName.toUpperCase();
  if (tagName === 'INPUT' || tagName === 'TEXTAREA' || tagName === 'SELECT') {
    return true;
  }
  return element.isContentEditable;
}

export function useKeyboardShortcuts({
  onScan,
  onClearLogs,
  onExportReport,
  onNavigateTab,
  onCloseModals,
  onNotify,
  enabled = true,
}: UseKeyboardShortcutsProps) {
  const [isHelpOpen, setIsHelpOpen] = useState(false);
  const [lastExecutedShortcut, setLastExecutedShortcut] = useState<{
    id: string;
    label: string;
    combo: string;
    timestamp: number;
  } | null>(null);

  // Keep references to latest callbacks to avoid re-attaching listeners continuously
  const callbacksRef = useRef({
    onScan,
    onClearLogs,
    onExportReport,
    onNavigateTab,
    onCloseModals,
    onNotify,
  });

  useEffect(() => {
    callbacksRef.current = {
      onScan,
      onClearLogs,
      onExportReport,
      onNavigateTab,
      onCloseModals,
      onNotify,
    };
  });

  const notifyTrigger = useCallback((id: string, label: string, combo: string) => {
    setLastExecutedShortcut({ id, label, combo, timestamp: Date.now() });
    if (callbacksRef.current.onNotify) {
      callbacksRef.current.onNotify(
        `Raccourci Clavier Activé : ${label}`,
        `Action exécutée instantanément depuis le clavier (${combo}).`,
        combo
      );
    }
  }, []);

  // Shortcut Registry
  const shortcuts: ShortcutDefinition[] = [
    {
      id: 'scan-standard',
      label: 'Scan de Sécurité Réel',
      description: 'Déclenche l\'audit instantané du système (Defender, BITS, processus, HOSTS).',
      keyCombo: 'Alt + S ou S',
      category: 'CORE_ACTIONS',
      badge: 'CORE',
      actionCommand: 'scan',
      handler: () => {
        notifyTrigger('scan-standard', 'Scan Système', 'Alt+S');
        callbacksRef.current.onScan(false);
      },
    },
    {
      id: 'scan-deep',
      label: 'Scan Approfondi (Deep Scan)',
      description: 'Scan intensif avec vérification approfondie des hashs et sockets cachés.',
      keyCombo: 'Alt + Shift + S',
      category: 'CORE_ACTIONS',
      badge: 'DEEP',
      actionCommand: 'scan --deep',
      handler: () => {
        notifyTrigger('scan-deep', 'Deep Scan Approfondi', 'Alt+Shift+S');
        callbacksRef.current.onScan(true);
      },
    },
    {
      id: 'clear-logs',
      label: 'Effacer la Console (Clear)',
      description: 'Purge l\'historique d\'affichage de la console et réinitialise le buffer.',
      keyCombo: 'Alt + C ou C',
      category: 'CORE_ACTIONS',
      badge: 'CLEAR',
      actionCommand: 'clear',
      handler: () => {
        notifyTrigger('clear-logs', 'Effacement Console', 'Alt+C');
        callbacksRef.current.onClearLogs();
      },
    },
    {
      id: 'export-report',
      label: 'Exporter le Rapport Forensique (PDF)',
      description: 'Génère et télécharge le rapport PDF complet avec score de posture et graphiques.',
      keyCombo: 'Alt + E ou E',
      category: 'CORE_ACTIONS',
      badge: 'EXPORT',
      actionCommand: 'export-report',
      handler: () => {
        notifyTrigger('export-report', 'Export Rapport PDF', 'Alt+E');
        callbacksRef.current.onExportReport();
      },
    },
    {
      id: 'tab-overview',
      label: 'Aller à la Vue Centrale',
      description: 'Affiche le tableau de bord principal de télémétrie et de santé.',
      keyCombo: 'Alt + 1',
      category: 'NAVIGATION',
      badge: 'NAV',
      handler: () => {
        notifyTrigger('tab-overview', 'Vue Centrale', 'Alt+1');
        callbacksRef.current.onNavigateTab('overview');
      },
    },
    {
      id: 'tab-taskmgr',
      label: 'Gestionnaire des Tâches Live',
      description: 'Affiche la surveillance temps réel CPU, RAM et processus.',
      keyCombo: 'Alt + 2',
      category: 'NAVIGATION',
      badge: 'NAV',
      handler: () => {
        notifyTrigger('tab-taskmgr', 'Gestionnaire des Tâches', 'Alt+2');
        callbacksRef.current.onNavigateTab('task-manager');
      },
    },
    {
      id: 'tab-console',
      label: 'Console d\'Analyse Terminal',
      description: 'Bascule directement vers le terminal de commande en direct.',
      keyCombo: 'Alt + 3',
      category: 'NAVIGATION',
      badge: 'NAV',
      handler: () => {
        notifyTrigger('tab-console', 'Console Terminal', 'Alt+3');
        callbacksRef.current.onNavigateTab('console');
      },
    },
    {
      id: 'tab-forensics',
      label: 'Forensique RAM & Mémoire',
      description: 'Audit de la mémoire volatile, process hollowing et VAD.',
      keyCombo: 'Alt + 4',
      category: 'NAVIGATION',
      badge: 'NAV',
      handler: () => {
        notifyTrigger('tab-forensics', 'Forensique RAM', 'Alt+4');
        callbacksRef.current.onNavigateTab('forensics');
      },
    },
    {
      id: 'tab-network',
      label: 'Scan Réseau & Sockets C2',
      description: 'Analyse des flux sortants, sockets ouverts et serveurs distants.',
      keyCombo: 'Alt + 5',
      category: 'NAVIGATION',
      badge: 'NAV',
      handler: () => {
        notifyTrigger('tab-network', 'Scan Réseau', 'Alt+5');
        callbacksRef.current.onNavigateTab('network');
      },
    },
    {
      id: 'tab-locator',
      label: 'Géolocalisation & Traçeur IP',
      description: 'Localisation de POP FAI, géolocalisation et cartographie BGP.',
      keyCombo: 'Alt + 6',
      category: 'NAVIGATION',
      badge: 'NAV',
      handler: () => {
        notifyTrigger('tab-locator', 'Traçeur IP', 'Alt+6');
        callbacksRef.current.onNavigateTab('ip-locator');
      },
    },
    {
      id: 'tab-isolation',
      label: 'Isolateur & Kill-Switch Réseau',
      description: 'Confinement rapide de la machine et coupure réseau d\'urgence.',
      keyCombo: 'Alt + K',
      category: 'SYSTEM',
      badge: 'SECURITÉ',
      handler: () => {
        notifyTrigger('tab-isolation', 'Isolateur Réseau', 'Alt+K');
        callbacksRef.current.onNavigateTab('sandbox-isolation');
      },
    },
    {
      id: 'shortcuts-modal',
      label: 'Aide des Raccourcis Clavier',
      description: 'Ouvre ou ferme le gestionnaire visuel de raccourcis interactifs.',
      keyCombo: '? ou F1',
      category: 'SYSTEM',
      badge: 'AIDE',
      handler: () => {
        setIsHelpOpen((prev) => !prev);
      },
    },
  ];

  // Core Global Keydown Event Listener
  useEffect(() => {
    if (!enabled) return;

    const handleKeyDown = (event: KeyboardEvent) => {
      const inInput = isEditableElement(event.target);
      const isAlt = event.altKey;
      const isCtrl = event.ctrlKey || event.metaKey;
      const isShift = event.shiftKey;
      const key = event.key;
      const keyLower = key.toLowerCase();

      // 1. ESCAPE: Always allowed (even in input) to dismiss modals or unfocus
      if (key === 'Escape') {
        if (isHelpOpen) {
          event.preventDefault();
          setIsHelpOpen(false);
          return;
        }
        if (callbacksRef.current.onCloseModals) {
          callbacksRef.current.onCloseModals();
        }
        return;
      }

      // 2. F1 / Help Modal Shortcut: Always allowed
      if (key === 'F1' || (isCtrl && key === '/')) {
        event.preventDefault();
        setIsHelpOpen((prev) => !prev);
        return;
      }

      // 3. Alt-based Shortcuts (Accessible everywhere, including when an input is focused)
      if (isAlt && !isCtrl) {
        // Alt + Shift + S => Deep Scan
        if (isShift && keyLower === 's') {
          event.preventDefault();
          notifyTrigger('scan-deep', 'Deep Scan Approfondi', 'Alt+Shift+S');
          callbacksRef.current.onScan(true);
          return;
        }

        // Alt + S => Standard Scan
        if (!isShift && keyLower === 's') {
          event.preventDefault();
          notifyTrigger('scan-standard', 'Scan Système', 'Alt+S');
          callbacksRef.current.onScan(false);
          return;
        }

        // Alt + C => Clear logs
        if (keyLower === 'c') {
          event.preventDefault();
          notifyTrigger('clear-logs', 'Effacement Console', 'Alt+C');
          callbacksRef.current.onClearLogs();
          return;
        }

        // Alt + E => Export report
        if (keyLower === 'e') {
          event.preventDefault();
          notifyTrigger('export-report', 'Export Rapport PDF', 'Alt+E');
          callbacksRef.current.onExportReport();
          return;
        }

        // Alt + K => Sandbox / Kill-Switch tab
        if (keyLower === 'k') {
          event.preventDefault();
          notifyTrigger('tab-isolation', 'Isolateur Réseau', 'Alt+K');
          callbacksRef.current.onNavigateTab('sandbox-isolation');
          return;
        }

        // Alt + 1..6 => Direct Tab Navigation
        switch (key) {
          case '1':
            event.preventDefault();
            notifyTrigger('tab-overview', 'Vue Centrale', 'Alt+1');
            callbacksRef.current.onNavigateTab('overview');
            return;
          case '2':
            event.preventDefault();
            notifyTrigger('tab-taskmgr', 'Gestionnaire des Tâches', 'Alt+2');
            callbacksRef.current.onNavigateTab('task-manager');
            return;
          case '3':
            event.preventDefault();
            notifyTrigger('tab-console', 'Console Terminal', 'Alt+3');
            callbacksRef.current.onNavigateTab('console');
            return;
          case '4':
            event.preventDefault();
            notifyTrigger('tab-forensics', 'Forensique RAM', 'Alt+4');
            callbacksRef.current.onNavigateTab('forensics');
            return;
          case '5':
            event.preventDefault();
            notifyTrigger('tab-network', 'Scan Réseau', 'Alt+5');
            callbacksRef.current.onNavigateTab('network');
            return;
          case '6':
            event.preventDefault();
            notifyTrigger('tab-locator', 'Traçeur IP', 'Alt+6');
            callbacksRef.current.onNavigateTab('ip-locator');
            return;
          default:
            break;
        }
      }

      // 4. Single-key shortcuts (Only when NOT inside an editable element, to avoid interfering with typing)
      if (!inInput && !isAlt && !isCtrl && !event.metaKey) {
        // Pressing 's' or 'S' outside input => Scan
        if (keyLower === 's') {
          event.preventDefault();
          if (isShift) {
            notifyTrigger('scan-deep', 'Deep Scan Approfondi', 'Shift+S');
            callbacksRef.current.onScan(true);
          } else {
            notifyTrigger('scan-standard', 'Scan Système', 'S');
            callbacksRef.current.onScan(false);
          }
          return;
        }

        // Pressing 'c' or 'C' outside input => Clear Console
        if (keyLower === 'c') {
          event.preventDefault();
          notifyTrigger('clear-logs', 'Effacement Console', 'C');
          callbacksRef.current.onClearLogs();
          return;
        }

        // Pressing 'e' or 'E' outside input => Export Report
        if (keyLower === 'e') {
          event.preventDefault();
          notifyTrigger('export-report', 'Export Rapport PDF', 'E');
          callbacksRef.current.onExportReport();
          return;
        }

        // Pressing '?' outside input => Toggle Help Modal
        if (key === '?' || (isShift && keyLower === '/')) {
          event.preventDefault();
          setIsHelpOpen((prev) => !prev);
          return;
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [enabled, isHelpOpen, notifyTrigger]);

  const triggerShortcutById = useCallback(
    (id: string) => {
      const match = shortcuts.find((s) => s.id === id);
      if (match) {
        match.handler();
      }
    },
    [shortcuts]
  );

  return {
    shortcuts,
    isHelpOpen,
    setIsHelpOpen,
    lastExecutedShortcut,
    triggerShortcutById,
  };
}
