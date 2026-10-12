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

// Curated active C2 and malicious connection locations matched to NetworkC2Panel & threat intel
export const DETECTED_MALICIOUS_ORIGINS: ThreatGeoLocation[] = [
  {
    id: 'c2-1',
    ip: '185.220.101.4',
    port: 4444,
    country: 'Fédération de Russie (Tor Exit)',
    countryCode: 'RU',
    city: 'Saint-Pétersbourg',
    latitude: 59.9343,
    longitude: 30.3351,
    threatType: 'C2_BEACON',
    processName: 'svch0st_updater.exe',
    pid: 5824,
    threatIntensity: 96,
    threatScore: 98,
    bandwidthKbps: 340,
    protocol: 'TCP',
    status: 'ACTIVE',
    intel: 'Cobalt Strike Beaconing / Swisyn Rootkit Controller (Port 4444)',
    asOrganization: 'AS208323 / AnonTor Relay Services',
    lastPacketTime: '1 sec ago',
  },
  {
    id: 'c2-2',
    ip: '45.154.255.89',
    port: 8080,
    country: 'Bulgarie',
    countryCode: 'BG',
    city: 'Sofia',
    latitude: 42.6977,
    longitude: 23.3219,
    threatType: 'DATA_EXFIL',
    processName: 'powershell.exe',
    pid: 7340,
    threatIntensity: 88,
    threatScore: 89,
    bandwidthKbps: 185,
    protocol: 'TCP',
    status: 'ACTIVE',
    intel: 'Exfiltration PowerShell vers serveur relais sous surveillance Threat Intel',
    asOrganization: 'AS44050 / Global Internet Telecomm Ltd',
    lastPacketTime: '3 sec ago',
  },
  {
    id: 'c2-3',
    ip: '103.251.167.22',
    port: 9001,
    country: 'Hong Kong (SAR)',
    countryCode: 'HK',
    city: 'Kowloon',
    latitude: 22.3193,
    longitude: 114.1694,
    threatType: 'PROXY_EXIT',
    processName: 'rundll32.exe',
    pid: 4192,
    threatIntensity: 74,
    threatScore: 78,
    bandwidthKbps: 92,
    protocol: 'TCP',
    status: 'MONITORED',
    intel: 'Canal de proxy inversé chiffré vers infrastructure APT41',
    asOrganization: 'AS138997 / HONG KONG BROADBAND CORP',
    lastPacketTime: '12 sec ago',
  },
  {
    id: 'c2-4',
    ip: '194.26.29.112',
    port: 53,
    country: 'Pays-Bas',
    countryCode: 'NL',
    city: 'Amsterdam',
    latitude: 52.3676,
    longitude: 4.9041,
    threatType: 'DNS_TUNNEL',
    processName: 'nslookup.exe',
    pid: 6108,
    threatIntensity: 68,
    threatScore: 71,
    bandwidthKbps: 45,
    protocol: 'UDP',
    status: 'ACTIVE',
    intel: 'Tunneling DNS furtif exfiltrant des hashes NTLM dans les sous-domaines',
    asOrganization: 'AS51852 / Private Layer Bulletproof Hosting',
    lastPacketTime: '5 sec ago',
  },
  {
    id: 'c2-5',
    ip: '193.32.162.77',
    port: 445,
    country: 'Roumanie',
    countryCode: 'RO',
    city: 'Bucarest',
    latitude: 44.4268,
    longitude: 26.1025,
    threatType: 'BRUTE_FORCE',
    processName: 'System (SMB)',
    pid: 4,
    threatIntensity: 82,
    threatScore: 84,
    bandwidthKbps: 110,
    protocol: 'TCP',
    status: 'ACTIVE',
    intel: 'Tentatives d\'injection SMBv1 / EternalBlue scanning sur port 445',
    asOrganization: 'AS49981 / WorldStream Cloud Security',
    lastPacketTime: '8 sec ago',
  },
  {
    id: 'c2-6',
    ip: '107.189.10.33',
    port: 3389,
    country: 'États-Unis (VPS Bulletproof)',
    countryCode: 'US',
    city: 'Chicago',
    latitude: 41.8781,
    longitude: -87.6298,
    threatType: 'BOTNET_MIRAI',
    processName: 'wmic.exe',
    pid: 8012,
    threatIntensity: 58,
    threatScore: 62,
    bandwidthKbps: 34,
    protocol: 'TCP',
    status: 'MONITORED',
    intel: 'Balise de contrôle RDP rebondie, tentative d\'escalade de privilèges',
    asOrganization: 'AS53667 / FranTech Solutions',
    lastPacketTime: '24 sec ago',
  },
  {
    id: 'c2-7',
    ip: '116.110.12.98',
    port: 8443,
    country: 'Vietnam',
    countryCode: 'VN',
    city: 'Hanoï',
    latitude: 21.0285,
    longitude: 105.8542,
    threatType: 'C2_BEACON',
    processName: 'certutil.exe',
    pid: 5310,
    threatIntensity: 79,
    threatScore: 82,
    bandwidthKbps: 76,
    protocol: 'TCP',
    status: 'ACTIVE',
    intel: 'Téléchargement de binaire masqué en certificat SSL via LOLBin CertUtil',
    asOrganization: 'AS7552 / VNPT Corp Net',
    lastPacketTime: '15 sec ago',
  },
  {
    id: 'c2-8',
    ip: '185.196.220.14',
    port: 1337,
    country: 'Seychelles / Off-shore',
    countryCode: 'SC',
    city: 'Victoria',
    latitude: -4.6191,
    longitude: 55.4513,
    threatType: 'DATA_EXFIL',
    processName: 'bitsadmin.exe',
    pid: 3996,
    threatIntensity: 64,
    threatScore: 65,
    bandwidthKbps: 52,
    protocol: 'TCP',
    status: 'MONITORED',
    intel: 'Tâche BITS d\'arrière-plan téléchargeant un stage 2 chiffré AES',
    asOrganization: 'AS200019 / Alexhost Offshore Services',
    lastPacketTime: '30 sec ago',
  }
];

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
  name: 'Station Sécurisée SpaceSec (Endpoint)',
  ip: '192.168.1.42',
  city: 'Paris',
  country: 'France',
  countryCode: 'FR',
  latitude: 48.8566,
  longitude: 2.3522,
  isp: 'Station Locale / SOC',
  isRealDetected: false,
};
