// GeoJSON data for world landmasses and countries simplified for high-performance D3 rendering
export interface GeoFeature {
  type: string;
  properties: {
    name: string;
    iso2?: string;
  };
  geometry: {
    type: 'Polygon' | 'MultiPolygon';
    coordinates: number[][][] | number[][][][];
  };
}

export interface GeoFeatureCollection {
  type: 'FeatureCollection';
  features: GeoFeature[];
}

export interface ThreatGeoLocation {
  id: string;
  ip: string;
  port: number;
  country: string;
  countryCode: string;
  city: string;
  latitude: number;
  longitude: number;
  threatType: 'C2_BEACON' | 'DATA_EXFIL' | 'BOTNET_MIRAI' | 'BRUTE_FORCE' | 'DNS_TUNNEL' | 'PROXY_EXIT';
  processName: string;
  pid: number;
  threatIntensity: number; // 0 to 100
  threatScore: number;
  bandwidthKbps: number;
  protocol: 'TCP' | 'UDP';
  status: 'ACTIVE' | 'BLOCKED' | 'MONITORED';
  intel: string;
  asOrganization: string;
  lastPacketTime: string;
}

// Curated active C2 and malicious connection locations (starts empty on clean system)
export const DETECTED_MALICIOUS_ORIGINS: ThreatGeoLocation[] = [];

export interface TargetHostLocation {
  name: string;
  ip: string;
  city: string;
  country: string;
  countryCode: string;
  latitude: number;
  longitude: number;
  isp?: string;
  regionName?: string;
  isRealDetected?: boolean;
}

// Target Protected System Location (Initial fallback before live IP geo resolution)
export const PROTECTED_SYSTEM_LOCATION: TargetHostLocation = {
  name: 'Station Sécurisée Space Security (Endpoint)',
  ip: '127.0.0.1',
  city: 'Paris',
  country: 'France',
  countryCode: 'FR',
  latitude: 48.8566,
  longitude: 2.3522,
  isp: 'Station Locale / SOC',
  isRealDetected: false,
};
