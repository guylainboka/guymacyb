export type ModuleView =
  | 'scanner-and-recon'
  | 'analyse-web'
  | 'tests-actifs-and-attaque'
  | 'laboratoire-attaques'
  | 'resultats-and-preuves'
  | 'rapport-and-remediation'
  | 'wifi-and-reseau'
  | 'cours-and-notions'
  | 'laboratoire-wifi'
  | 'terminal-integre';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type FindingStatus = 'VALIDATED' | 'DETECTED' | 'POTENTIAL';
export type TestFamilyStatus = 'PASS' | 'FAIL' | 'TESTING' | 'WARNING' | 'PENDING';

export type AttackCategory =
  | 'INJECTION'
  | 'AUTHENTICATION'
  | 'ACCESS_CONTROL'
  | 'CRYPTO'
  | 'CONFIG'
  | 'SERVER_SIDE';

export interface LabAttackVector {
  id: string;
  name: string;
  category: AttackCategory;
  owasp: string;
  cwe: string;
  severity: Severity;
  difficulty: 'FAIBLE' | 'MOYEN' | 'ÉLEVÉ';
  description: string;
  safeTestPayload: string;
  vulnerableResponseSample: string;
  remediatedResponseSample: string;
  vulnerableBehaviorExplanation: string;
  remediatedBehaviorExplanation: string;
  defensiveControls: string[];
  remediationCodeExample: {
    language: string;
    vulnerable: string;
    fixed: string;
  };
}

export interface LabSimulationResult {
  vectorId: string;
  vectorName: string;
  timestamp: string;
  targetMode: 'vulnerable' | 'remediated';
  status: 'VULNERABLE' | 'PROTECTED' | 'BLOCKED';
  probeSent: string;
  httpStatus: number;
  durationMs: number;
  responsePreview: string;
  wafIntercepted: boolean;
  securityObservations: string[];
  findingCandidate?: Finding;
}

export interface TargetConfig {
  url: string;
  port: number;
  scope: 'strict' | 'wildcard';
  authorized: boolean;
  operatorId: string;
  localDbName: string;
}

export interface EndpointItem {
  id: string;
  path: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'OPTIONS' | 'GET/PUT';
  status: number;
  statusText: string;
  authRequired?: boolean;
  type: 'root' | 'page' | 'folder' | 'api' | 'auth' | 'admin';
  hasFinding?: boolean;
  findingSeverity?: Severity;
  note?: string;
  children?: EndpointItem[];
  depth?: number;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  cvss: number;
  confidence: number;
  status: FindingStatus;
  affectedComponent: string;
  category: string;
  description: string;
  evidence: {
    request: string;
    response: string;
    authContext: string;
    roundtripMs: number;
    nonDestructiveProof: boolean;
  };
  impact: string;
  remediationTitle: string;
  remediationSteps: string[];
  cwe: string;
  signature: string;
  sqliteRow: number;
}

export interface ActiveTestFamily {
  id: string;
  name: string;
  icon: string;
  status: TestFamilyStatus;
  telemetrySummary: string;
  evidenceTrace?: {
    cwe: string;
    req: string;
    res: string;
  };
}

export interface TerminalLog {
  id: string;
  timestamp: string;
  tag: 'RECON' | 'DISCOVERY' | 'ENGINE' | 'TEST' | 'OBSERVATION' | 'VALIDATION' | 'FINDING' | 'TELEMETRY' | 'WARN' | 'CRITICAL' | 'ACTIVE' | 'SYSTEM';
  text: string;
  confidence?: string;
  severity?: Severity;
}

export interface HistoricalTarget {
  id: string;
  domain: string;
  url: string;
  risk: 'HIGH' | 'MED' | 'CLEAN';
  score: number;
  timestamp: string;
  findingCount: number;
}

// ============================================================
//  Types pour la partie WiFi & Réseau sans fil
// ============================================================

export type WifiEncryption =
  | 'OPEN'
  | 'WEP'
  | 'WPA'
  | 'WPA2'
  | 'WPA3'
  | 'WPA2/WPA3'
  | 'UNKNOWN';

export type WifiSecurityFlag =
  | 'PMF_ENABLED'        // Protected Management Frames (802.11w)
  | 'PMF_CAPABLE'
  | 'PMF_DISABLED'
  | 'WPS_ENABLED'
  | 'WPS_LOCKED'
  | 'HIDDEN_SSID'
  | 'TKIP'
  | 'AES-CCMP'
  | 'GCMP'
  | 'SAE'                // WPA3 Simultaneous Authentication of Equals
  | 'OWE'                // Opportunistic Wireless Encryption
  | 'EAP'
  | 'PSK';

export interface WifiNetwork {
  bssid: string;             // MAC du point d'accès
  ssid: string;              // Nom du réseau (vide si hidden)
  channel: number;
  frequency: number;         // MHz
  signalDbm: number;         // puissance en dBm (souvent négatif)
  quality: number;           // 0-100
  encryption: WifiEncryption;
  cipher: string;            // ex: "CCMP", "TKIP"
  authMode: string;          // ex: "PSK", "SAE", "802.1X"
  securityFlags: WifiSecurityFlag[];
  vendor: string;            // fabriquant estimé à partir du OUI
  isHidden: boolean;
  clients: number;           // nombre de clients détectés
  firstSeen: string;
  lastSeen: string;
}

export interface WifiScanResult {
  tool: string;              // 'iwlist' | 'aircrack-ng' | 'builtin-simulated'
  mode: string;
  interface: string;
  networks: WifiNetwork[];
  totalCount: number;
  secureCount: number;       // WPA2/WPA3
  weakCount: number;         // WEP/WPA/OPEN
  scannedAt: string;
  durationMs: number;
  error?: string;
}

export interface WpaAuditResult {
  tool: string;
  target: string;            // BSSID ou SSID
  interface: string;
  encryption: WifiEncryption;
  authMode: string;
  cipher: string;
  pmf: {
    supported: boolean;
    enabled: boolean;
    requirement: 'DISABLED' | 'OPTIONAL' | 'REQUIRED';
  };
  wps: {
    enabled: boolean;
    locked: boolean;
    version: string;
    pinMethod: string;
  };
  handshake: {
    captured: boolean;
    fourWayComplete: boolean;
    pmkidPresent: boolean;
    notes: string;
  };
  vulnerabilities: Array<{
    id: string;
    title: string;
    severity: Severity;
    cwe: string;
    description: string;
    remediation: string;
  }>;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  scannedAt: string;
  error?: string;
}

export interface DeauthEvent {
  timestamp: string;
  sourceBssid: string;
  targetClient: string;
  reason: string;
  frameType: string;
}

export interface DeauthDetectionResult {
  tool: string;
  interface: string;
  monitorMode: boolean;
  durationSec: number;
  events: DeauthEvent[];
  totalDeauths: number;
  suspectedAttack: boolean;
  attackType: string | null;   // 'DEAUTH_FLOOD' | 'EVIL_TWIN' | 'CAPTURE_HANDSHAKE' | null
  scannedAt: string;
  error?: string;
}

// ============================================================
//  Types pour le laboratoire d'attaques WiFi
// ============================================================

export type WifiAttackCategory =
  | 'WIFI_DEAUTH'
  | 'WIFI_EVIL_TWIN'
  | 'WIFI_KRACK'
  | 'WIFI_WPS'
  | 'WIFI_HANDSHAKE'
  | 'WIFI_DOWNGRADE';

export interface WifiLabVector {
  id: string;
  name: string;
  category: WifiAttackCategory;
  mitre: string;            // technique MITRE ATT&CK
  severity: Severity;
  difficulty: 'FAIBLE' | 'MOYEN' | 'ÉLEVÉ';
  targetEncryption: WifiEncryption;
  description: string;
  attackScenario: string;
  safeTestPayload: string;
  vulnerableResponseSample: string;
  remediatedResponseSample: string;
  vulnerableBehaviorExplanation: string;
  remediatedBehaviorExplanation: string;
  defensiveControls: string[];
  remediationCodeExample: {
    language: string;
    vulnerable: string;
    fixed: string;
  };
}

export interface WifiLabSimulationResult {
  vectorId: string;
  vectorName: string;
  timestamp: string;
  targetMode: 'vulnerable' | 'remediated';
  status: 'VULNERABLE' | 'PROTECTED' | 'BLOCKED';
  probeSent: string;
  durationMs: number;
  responsePreview: string;
  apIntercepted: boolean;
  securityObservations: string[];
  findingCandidate?: Finding;
}

// ============================================================
//  Types pour les cours / notions
// ============================================================

export interface CourseNotion {
  id: string;
  title: string;
  category: 'wifi' | 'network' | 'crypto' | 'attack' | 'defense';
  level: 'DÉBUTANT' | 'INTERMÉDIAIRE' | 'AVANCÉ';
  summary: string;
  content: string;          // markdown simplifié
  keyPoints: string[];
  references: string[];
}
