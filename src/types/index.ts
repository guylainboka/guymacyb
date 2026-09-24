export type ModuleView =
  | 'scanner-and-recon'
  | 'analyse-web'
  | 'tests-actifs-and-attaque'
  | 'laboratoire-attaques'
  | 'resultats-and-preuves'
  | 'rapport-and-remediation';

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
