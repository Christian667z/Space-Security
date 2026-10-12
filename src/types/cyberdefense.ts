export type TabId = 
  | 'overview'
  | 'task-manager'
  | 'bits'
  | 'timeline'
  | 'console'
  | 'deep-excision'
  | 'forensics'
  | 'network'
  | 'hardening'
  | 'script-hub';

export type TimelinePhase = 'SCAN' | 'DETECTION' | 'CONTAINMENT' | 'EXCISION' | 'HARDENING';

export interface ThreatTimelineEvent {
  id: string;
  timeOffsetSec: number;
  timeDisplay: string;
  phase: TimelinePhase;
  phaseLabel: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  status: 'DETECTED' | 'CONTAINED' | 'REMEDIATED' | 'VERIFIED' | 'IN_PROGRESS';
  mitreId?: string;
  mitreTactic?: string;
  targetArtifact?: string;
  description: string;
  evidence: string;
  remediationActionCmd?: string;
  remediationButtonLabel?: string;
  remediationResult?: string;
  scoreDelta?: number;
  cumulativeScore?: number;
  riskReductionPercent?: number;
  riskCategory?: string;
}

export interface ThreatItem {
  id: string;
  name: string;
  category: 'Rootkit' | 'Trojan' | 'Persistence' | 'C2' | 'Privilege' | 'Memory';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  targetPath: string;
  mitreTechnique: string;
  lockedBySystem: boolean;
  trustedInstallerLocked: boolean;
  description: string;
  status: 'ACTIVE' | 'QUARANTINED' | 'SCHEDULED_BOOT_DELETE' | 'NEUTRALIZED';
}

export interface ProcessItem {
  pid: number;
  name: string;
  parentPid: number;
  cpu: number;
  ramMb: number;
  path: string;
  isSuspicious: boolean;
  anomalyReason?: string;
  integrityLevel: 'SYSTEM' | 'High' | 'Medium' | 'Low';
}

export interface NetworkConnectionItem {
  local: string;
  remote: string;
  protocol: 'TCP' | 'UDP';
  pid: number;
  processName: string;
  state: 'ESTABLISHED' | 'LISTENING' | 'TIME_WAIT';
  isSuspicious: boolean;
  country?: string;
  intel?: string;
}

export interface ConsoleLogMessage {
  id: string;
  timestamp: string;
  level: 'OK' | 'INFO' | 'WARN' | 'ERROR' | 'KERNEL';
  text: string;
  tag?: string;
}

export interface HardeningMetric {
  title: string;
  status: 'PROTECTED' | 'VULNERABLE' | 'WARNING';
  details: string;
  remediationCmd: string;
}

export interface WindowsEventLogEntry {
  id: string;
  eventId: number;
  channel: 'Security' | 'System' | 'PowerShell' | 'Defender' | 'Application';
  timeCreated: string;
  level: 'CRITICAL' | 'ERROR' | 'WARNING' | 'INFORMATION';
  source: string;
  user?: string;
  computer: string;
  description: string;
  rawPayload?: string;
  mitreTactic?: string;
  isIsolatedThreat: boolean;
}

export interface ThreatNotification {
  id: string;
  timestamp: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: 'C2' | 'Kernel' | 'Trojan' | 'Persistence' | 'Memory' | 'Network' | 'Defender';
  source: string;
  targetTab?: TabId;
  actionCommand?: string;
  actionLabel?: string;
  isRead?: boolean;
}

