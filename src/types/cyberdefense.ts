export type TabId = 
  | 'overview'
  | 'edr-fleet'
  | 'task-manager'
  | 'bits'
  | 'timeline'
  | 'heuristic'
  | 'console'
  | 'deep-excision'
  | 'deep-detection'
  | 'themes-hunter'
  | 'sandbox-isolation'
  | 'forensics'
  | 'network'
  | 'wifi'
  | 'remediation'
  | 'hardening'
  | 'script-hub'
  | 'ip-locator';

export interface EntropyMetric {
  id: string;
  target: string;
  section: string;
  process: string;
  pid: number;
  entropy: number; // 0.00 to 8.00 (Shannon entropy)
  baseline: number;
  deviation: number;
  sizeBytes: number;
  status: 'NORMAL' | 'ELEVATED' | 'CRITICAL_PACKED';
  isObfuscated: boolean;
  classification: string;
}

export interface SuspiciousApiCall {
  id: string;
  timestamp: string;
  apiName: string;
  callerProcess: string;
  pid: number;
  targetProcess?: string;
  targetPid?: number;
  category: 'INJECTION' | 'CREDENTIAL' | 'EVASION' | 'PERSISTENCE' | 'DISCOVERY';
  riskScore: number; // 1-100
  callCount: number;
  ratePerSec: number;
  mitreTechnique: string;
  hookStatus: 'INTERCEPTED' | 'BLOCKED' | 'FLAGGED';
  details: string;
}

export interface ThreatConfidenceItem {
  id: string;
  threatName: string;
  targetPath: string;
  confidence: number; // 0 - 100%
  entropyScore: number; // 0 - 100
  apiScore: number; // 0 - 100
  behaviorScore: number; // 0 - 100
  mitreAlignment: number; // 0 - 100
  verdict: 'CONFIRMED_MALICIOUS' | 'HIGH_SUSPICION' | 'ELEVATED_RISK' | 'BENIGN';
  primaryTechnique: string;
  recommendedAction: string;
  remediationCmd: string;
}

export interface WiFiNetworkItem {
  id: string;
  ssid: string;
  bssid: string;
  channel: number;
  frequency: '2.4 GHz' | '5 GHz' | '6 GHz';
  signalDbm: number;
  signalPercent: number;
  security: 'WPA3-SAE' | 'WPA2-Enterprise' | 'WPA2-PSK (AES)' | 'WEP' | 'OPEN_UNSECURED';
  vendor: string;
  isEvilTwin: boolean;
  evilTwinReason?: string;
  isUnsecured: boolean;
  deauthFramesDetected?: number | null;
  status: 'LEGITIMATE' | 'SUSPECT_EVIL_TWIN' | 'UNSECURED_WARNING' | 'BLOCKED';
  firstSeen: string;
  recommendedAction: string;
  mitreTechnique: string;
  legitimateTwinBssid?: string;
}



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
  category: 'Rootkit' | 'Trojan' | 'Persistence' | 'C2' | 'Privilege' | 'Memory' | 'Kernel' | 'Network' | 'Defender';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  targetPath: string;
  mitreTechnique: string;
  lockedBySystem: boolean;
  trustedInstallerLocked: boolean;
  status: 'ACTIVE' | 'QUARANTINED' | 'SCHEDULED_BOOT_DELETE' | 'NEUTRALIZED' | 'DISMISSED';
  description?: string;
  detectedAt?: string;
}

export type BulkThreatActionType =
  | 'KERNEL_UNLOCK'
  | 'QUARANTINE'
  | 'MASS_DISMISS'
  | 'RESTORE'
  | 'SHARED_COMMAND';

export interface SharedCommandPreset {
  id: string;
  label: string;
  description: string;
  commandTemplate: string;
  category: 'KERNEL' | 'FORENSICS' | 'PROCESS' | 'REGISTRY';
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
  operatorName?: string;
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
  category: 'C2' | 'Kernel' | 'Trojan' | 'Persistence' | 'Memory' | 'Network' | 'Defender' | 'Collab';
  source: string;
  targetTab?: TabId;
  actionCommand?: string;
  actionLabel?: string;
  isRead?: boolean;
}

export interface OperatorSession {
  id: string;
  name: string;
  role: string;
  ip: string;
  connectedAt: string;
  isCurrentSession?: boolean;
  status: 'ONLINE' | 'IDLE';
}

export interface SharedSyncState {
  threats: ThreatItem[];
  logs: ConsoleLogMessage[];
  blockedIps: string[];
  blockedWifiBssids: string[];
  activeUsersCount: number;
  lastModified: string;
  activeOperators: OperatorSession[];
}

export interface TracerouteHop {
  hop: number;
  ip: string;
  host: string;
  latency: string;
  location: string;
  org: string;
}

export interface IpLocationReport {
  success: boolean;
  ip: string;
  isLocal: boolean;
  country: string;
  countryCode: string;
  continent: string;
  city: string;
  district: string;
  regionName: string;
  zip: string;
  latitude: number;
  longitude: number;
  timezone: string;
  isp: string;
  org: string;
  as: string;
  asname: string;
  reverseDns: string;
  isProxy: boolean;
  isHosting: boolean;
  isTor: boolean;
  threatScore: number;
  placeFacility: string;
  placeAddress: string;
  placeRoad?: string;
  placeQuarter?: string;
  placeIntel: string;
  distanceKm: number;
  estLatencyMs: number;
  hops: TracerouteHop[];
  firewallRulePs1: string;
  googleMapsUrl: string;
  googleMapsPlaceUrl: string;
  googleStreetViewUrl: string;
  openStreetMapUrl: string;
  groundingUrls?: Array<{ uri: string; title: string }>;
  isSimulatedHops?: boolean;
  tracerouteNotice?: string;
  measuredPingMs?: number | null;
  forensicIntegrityNotice?: string;
  addressPrecision?: 'EXACT_COORDINATES' | 'CITY_POP' | 'REGIONAL_POP' | 'LOCAL_RFC1918';
  error?: string;
}

export interface NetworkInterfaceInfo {
  id: string;
  name: string;
  displayName: string;
  type: 'Wi-Fi' | 'Ethernet' | 'Virtual' | 'Loopback' | 'Cellular' | 'Other';
  status: 'Up' | 'Down' | 'Disabled' | 'Unknown';
  adminStatus: 'Enabled' | 'Disabled';
  mac: string;
  ipAddresses: string[];
  speedMbps?: number;
  isLoopback: boolean;
  isPhysical: boolean;
  rxBytes?: number;
  txBytes?: number;
}

export interface SandboxProcessItem {
  pid: number;
  name: string;
  path: string;
  status: 'RUNNING' | 'FROZEN' | 'ISOLATED' | 'SANDBOXED' | 'TERMINATED';
  isolatedAt?: string;
  networkBlocked: boolean;
  cpuRestricted: boolean;
  threatScore: number;
  details?: string;
}

export interface KillSwitchStatus {
  isActive: boolean;
  engagedAt?: string;
  disabledInterfaces: string[];
  loopbackProtected: boolean;
  localhostPort: number;
  interfaces: NetworkInterfaceInfo[];
  totalActiveInterfaces: number;
  externalAccessBlocked: boolean;
  sandboxedProcesses: SandboxProcessItem[];
  appliedCommands: string[];
}

export interface EdrEndpoint {
  id: string;
  hostname: string;
  ipAddress: string;
  publicIp?: string;
  macAddress: string;
  osVersion: string;
  agentVersion: string;
  status: 'ONLINE' | 'OFFLINE' | 'WARNING' | 'CRITICAL';
  lastSeen: string;
  registeredAt: string;
  healthScore: number;
  activeThreatsCount: number;
  networkIsolated: boolean;
  isolationStatus?: 'NORMAL' | 'ISOLATION_PENDING' | 'ISOLATED' | 'RESTORATION_PENDING';
  agentSecret?: string;
  cpuUsagePercent: number;
  ramUsagePercent: number;
  pendingCommandsCount?: number;
}

export interface EdrTelemetryEvent {
  id: string;
  endpointId: string;
  hostname: string;
  timestamp: string;
  category: 'PROCESS' | 'REGISTRY' | 'NETWORK' | 'SERVICE' | 'BITS' | 'DEFENDER' | 'ANOMALY';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  summary: string;
  details?: any;
  mitreTechnique?: string;
}

export interface EdrCommand {
  id: string;
  endpointId: string;
  hostname: string;
  type: 'KILL_PROCESS' | 'ISOLATE_NETWORK' | 'UNISOLATE_NETWORK' | 'SCAN_DEEP' | 'REPAIR_THEMES' | 'RESTORE_DEFENDER';
  payload?: {
    pid?: number;
    command?: string;
    reason?: string;
  };
  status: 'PENDING' | 'EXECUTED' | 'FAILED' | 'EXPIRED';
  createdAt: string;
  expiresAt?: string;
  signature?: string;
  executedAt?: string;
  result?: string;
}


