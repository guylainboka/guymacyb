import { Finding, ActiveTestFamily, EndpointItem, HistoricalTarget, TerminalLog } from '../types';

export const INITIAL_HISTORICAL_TARGETS: HistoricalTarget[] = [
  {
    id: 'hist-1',
    domain: 'api.internal-cloud.io',
    url: 'https://api.internal-cloud.io',
    risk: 'HIGH',
    score: 8.4,
    timestamp: "Aujourd'hui • 14:20",
    findingCount: 18,
  },
  {
    id: 'hist-2',
    domain: 'stage-auth.corporation.com',
    url: 'https://stage-auth.corporation.com',
    risk: 'MED',
    score: 5.1,
    timestamp: 'Hier • 18:45',
    findingCount: 9,
  },
  {
    id: 'hist-3',
    domain: 'payment-gateway.node12.org',
    url: 'https://payment-gateway.node12.org',
    risk: 'CLEAN',
    score: 0.0,
    timestamp: '12 Mai • 09:12',
    findingCount: 0,
  },
];

export const INITIAL_ENDPOINTS_TREE: EndpointItem[] = [
  {
    id: 'ep-root',
    path: '/',
    method: 'GET',
    status: 200,
    statusText: '200 OK',
    type: 'root',
    depth: 1,
  },
  {
    id: 'ep-login',
    path: '/login',
    method: 'POST',
    status: 200,
    statusText: '200 OK',
    type: 'auth',
    note: '(Form auth)',
    depth: 1,
  },
  {
    id: 'ep-dashboard',
    path: '/dashboard',
    method: 'GET',
    status: 401,
    statusText: '401 Unauthorized',
    authRequired: true,
    type: 'page',
    depth: 1,
  },
  {
    id: 'ep-admin',
    path: '/admin',
    method: 'GET',
    status: 403,
    statusText: '403 Forbidden',
    authRequired: true,
    type: 'admin',
    hasFinding: true,
    findingSeverity: 'HIGH',
    note: 'HIGH FINDING',
    depth: 1,
  },
  {
    id: 'ep-api-parent',
    path: '/api',
    method: 'GET',
    status: 200,
    statusText: 'Namespace REST',
    type: 'folder',
    note: '(3 endpoints v1)',
    depth: 1,
    children: [
      {
        id: 'ep-api-user-id',
        path: '/api/user/{id}',
        method: 'GET/PUT',
        status: 401,
        statusText: '401',
        authRequired: true,
        type: 'api',
        hasFinding: true,
        findingSeverity: 'HIGH',
        note: '(Param ID)',
        depth: 2,
      },
      {
        id: 'ep-api-products',
        path: '/api/products',
        method: 'GET',
        status: 200,
        statusText: '200 OK',
        type: 'api',
        depth: 2,
      },
      {
        id: 'ep-api-orders',
        path: '/api/orders',
        method: 'POST',
        status: 401,
        statusText: '401',
        authRequired: true,
        type: 'api',
        hasFinding: true,
        findingSeverity: 'HIGH',
        note: '(JSON Body)',
        depth: 2,
      },
    ],
  },
  {
    id: 'ep-register',
    path: '/register',
    method: 'POST',
    status: 200,
    statusText: '200 OK',
    type: 'auth',
    depth: 1,
  },
  {
    id: 'ep-metrics',
    path: '/admin/metrics',
    method: 'GET',
    status: 200,
    statusText: '200 OK',
    type: 'admin',
    hasFinding: true,
    findingSeverity: 'HIGH',
    note: 'Prometheus endpoint exposé',
    depth: 1,
  },
  {
    id: 'ep-search',
    path: '/api/v1/search?sort=',
    method: 'GET',
    status: 200,
    statusText: '200 OK',
    type: 'api',
    hasFinding: true,
    findingSeverity: 'HIGH',
    note: 'SQLi injectable',
    depth: 1,
  },
  {
    id: 'ep-backup',
    path: '/backup.sql.gz',
    method: 'GET',
    status: 200,
    statusText: '200 OK',
    type: 'page',
    hasFinding: true,
    findingSeverity: 'HIGH',
    note: 'Archive backup publique',
    depth: 1,
  },
];

export const INITIAL_FINDINGS: Finding[] = [
  {
    id: 'SEC-2024-8841',
    title: 'Broken Access Control (Insecure Direct Object Reference - IDOR)',
    severity: 'HIGH',
    cvss: 8.5,
    confidence: 94,
    status: 'VALIDATED',
    affectedComponent: 'GET /api/user/{id}',
    category: 'Authorization',
    cwe: 'CWE-639',
    signature: 'a3f9e802...4c21b590',
    sqliteRow: 104,
    description: "Un utilisateur authentifié avec l'ID 104 a pu extraire directement les données sensibles de l'utilisateur avec l'ID 105 sans aucune vérification d'appartenance ni contrôle de permissions côté serveur. L'API expose les attributs de profil et les identifiants internes à tout agent authentifié modifiant l'entier d'URI.",
    evidence: {
      authContext: 'ID 104 (Session rôle: standard_user)',
      roundtripMs: 48,
      nonDestructiveProof: true,
      request: `GET /api/user/105 HTTP/1.1
Host: example.com
User-Agent: ShadowScan/1.0.0
Accept: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.user_104_token
Connection: close`,
      response: `HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 142

{
  "id": 105,
  "email": "victim@example.com",
  "role": "editor",
  "api_key": "sk_test_904128fba10c492b",
  "tenant_id": "corp_prod_eu"
}`,
    },
    impact: "Fuite de données personnelles (non-conformité RGPD art. 32), usurpation d'identité, élévation horizontale de privilèges et compromission directe des clés d'accès des comptes utilisateurs.",
    remediationTitle: 'RBAC / Policy check',
    remediationSteps: [
      'Vérifier formellement les droits du sujet avant tout renvoi d’enregistrement côté serveur.',
      'Ne jamais traiter l’ID extrait de l’URL comme une source d’identité authentifiée de confiance.',
      'Assurer l’égalité stricte entre req.session.userId et l’identifiant de la ressource demandée.',
      'Ajouter des tests d’intégration automatisés CI/CD testant les accès transverses entre comptes.',
    ],
  },
  {
    id: 'SEC-2024-8842',
    title: 'SQL Injection aveugle basée sur le temps (Blind Time-based SQLi)',
    severity: 'HIGH',
    cvss: 8.2,
    confidence: 98,
    status: 'VALIDATED',
    affectedComponent: 'GET /api/v1/search?sort=',
    category: 'Injection',
    cwe: 'CWE-89',
    signature: '77c2ab44...d10e9811',
    sqliteRow: 105,
    description: "Le paramètre 'sort' est concaténé sans échappement ni vérification dans la clause ORDER BY de la requête PostgreSQL sous-jacente. L'injection d'une charge utile contrôlée non-destructive (pg_sleep(2)) a provoqué un retard mesuré exactement de 2 042 ms.",
    evidence: {
      authContext: 'Anonyme (Public search)',
      roundtripMs: 2042,
      nonDestructiveProof: true,
      request: `GET /api/v1/search?q=laptop&sort=(SELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(2)+ELSE+pg_sleep(0)+END) HTTP/1.1
Host: example.com
User-Agent: ShadowScan/1.0.0
Accept: application/json`,
      response: `HTTP/1.1 200 OK
Content-Type: application/json
X-Response-Time: 2042.8ms

{
  "total": 14,
  "results": [...],
  "latency_injected": true
}`,
    },
    impact: 'Exfiltration complète de la base de données relationnelle, contournement des règles de contrôle d’accès et compromission possible du système d’exploitation hôte.',
    remediationTitle: 'Requêtes Préparées & Allowlisting',
    remediationSteps: [
      'Ne jamais concaténer de chaînes issues de l’entrée utilisateur dans une clause SQL ORDER BY.',
      'Valider le paramètre de tri contre une liste blanche stricte (allowlist) de colonnes autorisées.',
      'Utiliser un ORM (Drizzle, Prisma, SQLAlchemy) avec typage fort et requêtes paramétrées.',
    ],
  },
  {
    id: 'SEC-2024-8843',
    title: "Exposition de l'interface admin & métriques non authentifiée",
    severity: 'HIGH',
    cvss: 7.5,
    confidence: 89,
    status: 'VALIDATED',
    affectedComponent: 'GET /admin/metrics',
    category: 'Information Disclosure',
    cwe: 'CWE-200',
    signature: 'fa9910c2...8831ef76',
    sqliteRow: 106,
    description: "Le endpoint Prometheus /admin/metrics est accessible publiquement sans authentification HTTP Basic ni jeton Bearer. Il divulgue la mémoire allouée du processus, les requêtes SQL internes exécutées et les adresses IP des pods Kubernetes.",
    evidence: {
      authContext: 'Non authentifié (Aucun header)',
      roundtripMs: 34,
      nonDestructiveProof: true,
      request: `GET /admin/metrics HTTP/1.1
Host: example.com
User-Agent: ShadowScan/1.0.0
Accept: text/plain`,
      response: `HTTP/1.1 200 OK
Content-Type: text/plain; version=0.0.4

# HELP process_virtual_memory_bytes Virtual memory size in bytes.
# TYPE process_virtual_memory_bytes gauge
process_virtual_memory_bytes 4.1293847e+08
# HELP db_pool_active_connections Current active DB pool
db_pool_active_connections{db="app_prod",host="10.0.4.12"} 8`,
    },
    impact: 'Reconnaissance approfondie par un attaquant, cartographie de l’architecture réseau interne et préparation d’attaques ciblées.',
    remediationTitle: 'Restriction Réseau & Authentification',
    remediationSteps: [
      'Isoler le port et les routes de métriques (/metrics) sur une interface réseau locale interne (localhost / VPC).',
      'Exiger une authentification forte mutuelle TLS (mTLS) ou HTTP Basic sécurisée.',
    ],
  },
  {
    id: 'SEC-2024-8844',
    title: 'Absence de Content Security Policy (CSP)',
    severity: 'MEDIUM',
    cvss: 5.3,
    confidence: 99,
    status: 'POTENTIAL',
    affectedComponent: 'Header HTTP: Content-Security-Policy',
    category: 'Headers',
    cwe: 'CWE-1021',
    signature: 'b8192a01...11234c9f',
    sqliteRow: 107,
    description: "L'en-tête de protection XSS et injection de scripts tiers n'est configuré sur aucune route inspectée de l'application. En cas d'injection HTML, aucun mécanisme de bac à sable côté navigateur ne viendra restreindre l'exécution du script malveillant.",
    evidence: {
      authContext: 'Inspection passive des en-têtes HTTP',
      roundtripMs: 22,
      nonDestructiveProof: true,
      request: `HEAD / HTTP/1.1
Host: example.com
User-Agent: ShadowScan/1.0.0`,
      response: `HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Content-Type: text/html
X-Frame-Options: SAMEORIGIN
Strict-Transport-Security: max-age=31536000
(Content-Security-Policy absent)`,
    },
    impact: 'Exécution non restreinte de code JavaScript injecté, vol de cookies non protégés et détournement de session utilisateur.',
    remediationTitle: 'Déploiement Header CSP Stricte',
    remediationSteps: [
      "Définir l'en-tête : Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com;",
      "Désactiver impérativement les clauses 'unsafe-inline' et 'unsafe-eval'.",
    ],
  },
  {
    id: 'SEC-2024-8845',
    title: "Cookie de session manquant l'attribut SameSite Strict",
    severity: 'MEDIUM',
    cvss: 4.7,
    confidence: 96,
    status: 'DETECTED',
    affectedComponent: 'Set-Cookie: session_token',
    category: 'Session',
    cwe: 'CWE-1275',
    signature: '194dce88...ff739900',
    sqliteRow: 108,
    description: "Le cookie d'authentification principal 'session_token' est transmis avec SameSite=None sans protection anti-CSRF synchrone. Un site tiers peut forcer l'envoi de requêtes légitimes avec les identifiants de la victime.",
    evidence: {
      authContext: 'Analyse du flux Set-Cookie /login',
      roundtripMs: 51,
      nonDestructiveProof: true,
      request: `POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=demo&password=password123`,
      response: `HTTP/1.1 200 OK
Set-Cookie: session_token=abc123xyz; Path=/; Secure; HttpOnly; SameSite=None`,
    },
    impact: 'Vulnérabilité aux attaques Cross-Site Request Forgery (CSRF) permettant à un tiers d’effectuer des mutations d’état non sollicitées.',
    remediationTitle: 'Durcissement Cookie Flag',
    remediationSteps: [
      'Modifier la directive du cookie en : SameSite=Lax ou SameSite=Strict.',
      'Implémenter des jetons synchrones Anti-CSRF sur toutes les requêtes POST, PUT et DELETE.',
    ],
  },
  {
    id: 'SEC-2024-8846',
    title: 'Méthode HTTP TRACE activée (Cross-Site Tracing - XST)',
    severity: 'MEDIUM',
    cvss: 4.3,
    confidence: 91,
    status: 'VALIDATED',
    affectedComponent: 'OPTIONS/TRACE /',
    category: 'HTTP Methods',
    cwe: 'CWE-693',
    signature: '8872bca1...2094811a',
    sqliteRow: 109,
    description: "Le serveur répond avec un code HTTP 200 OK et reflète l'intégralité du corps de la requête lors de l'appel TRACE. Cela permet de contourner le flag HttpOnly via des failles XSS combinées.",
    evidence: {
      authContext: 'Test actif de méthode verbe HTTP',
      roundtripMs: 19,
      nonDestructiveProof: true,
      request: `TRACE / HTTP/1.1
Host: example.com
X-Test-Probe: shadowscan_active_verifier`,
      response: `HTTP/1.1 200 OK
Content-Type: message/http

TRACE / HTTP/1.1
Host: example.com
X-Test-Probe: shadowscan_active_verifier`,
    },
    impact: 'Contournement des protections HttpOnly des cookies de session via injection de script client.',
    remediationTitle: 'Désactivation Verbe TRACE',
    remediationSteps: [
      'Nginx: ajouter if ($request_method = TRACE) { return 405; }',
      'Apache: ajouter la directive TraceEnable Off.',
    ],
  },
  {
    id: 'SEC-2024-8847',
    title: 'Divulgation de bannière serveur (Server Banner Leaked)',
    severity: 'LOW',
    cvss: 3.1,
    confidence: 100,
    status: 'VALIDATED',
    affectedComponent: 'Header HTTP: Server',
    category: 'Information Disclosure',
    cwe: 'CWE-200',
    signature: '91bcfa31...00119842',
    sqliteRow: 110,
    description: "La réponse HTTP divulgue la version exacte du serveur web sous-jacent : 'nginx/1.24.0 (Ubuntu)'.",
    evidence: {
      authContext: 'Passive Banner Grab',
      roundtripMs: 14,
      nonDestructiveProof: true,
      request: `GET / HTTP/1.1
Host: example.com`,
      response: `HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)`,
    },
    impact: 'Facilite le ciblage des exploits connus spécifiques à la version 1.24.0.',
    remediationTitle: 'Masquage Server Tokens',
    remediationSteps: ['Ajouter la directive : server_tokens off; dans nginx.conf.'],
  },
];

export const INITIAL_TEST_FAMILIES: ActiveTestFamily[] = [
  {
    id: 'tf-auth',
    name: 'Authentication Checks',
    icon: 'lock',
    status: 'PASS',
    telemetrySummary: 'Brute-force limit ok (HTTP 429), JWT signature verified',
  },
  {
    id: 'tf-session',
    name: 'Session Security',
    icon: 'cookie',
    status: 'PASS',
    telemetrySummary: 'Session invalidation on logout ok, Secure/HttpOnly flags ON',
  },
  {
    id: 'tf-bac',
    name: 'Authorization (B.A.C.)',
    icon: 'no_encryption',
    status: 'FAIL',
    telemetrySummary: 'IDOR sur /api/user/42 vs ctx testeur -> Fuite de profil validée',
    evidenceTrace: {
      cwe: 'CVE-CWE-639: Insecure Direct Object References',
      req: 'GET /api/user/42 HTTP/1.1 [Auth-Bearer: test_user_session_token]',
      res: 'HTTP/1.1 200 OK {"id": 42, "email": "admin.corp@example.com", "role": "sysadmin"}',
    },
  },
  {
    id: 'tf-injection',
    name: 'Input Validation & Injection',
    icon: 'cyclone',
    status: 'TESTING',
    telemetrySummary: 'Testing SQLi & Command injection on 12 params (/search, /filter)',
    evidenceTrace: {
      cwe: 'CWE-89: SQL Injection',
      req: "GET /api/v1/search?sort=' OR 1=1-- HTTP/1.1",
      res: 'HTTP/1.1 500 Internal Server Error (PostgreSQL syntax error near "OR")',
    },
  },
  {
    id: 'tf-xss',
    name: 'XSS Browser Interpretation',
    icon: 'code_blocks',
    status: 'PASS',
    telemetrySummary: 'Contextual sanitization active, DOM parser safe check OK',
  },
  {
    id: 'tf-api',
    name: 'API Security & Object Level',
    icon: 'api',
    status: 'FAIL',
    telemetrySummary: 'Endpoint /api/orders consultation directe sans vérif de tenant',
    evidenceTrace: {
      cwe: 'CWE-284: Improper Access Control (Tenant Isolation)',
      req: 'POST /api/orders/lookup {"order_id": 9012} [Tenant: alpha]',
      res: 'HTTP/1.1 200 OK {"order_id": 9012, "owner_tenant": "beta_corp", "amount": 9200}',
    },
  },
  {
    id: 'tf-csrf',
    name: 'CSRF Protection',
    icon: 'shield',
    status: 'PASS',
    telemetrySummary: 'Anti-CSRF tokens validés sur mutations POST/PUT, SameSite=Strict',
  },
  {
    id: 'tf-rate',
    name: 'Rate Limiting & DoS Guard',
    icon: 'hourglass_empty',
    status: 'WARNING',
    telemetrySummary: 'Pas de throttling sur /api/search (250 req en 2s acceptées)',
  },
  {
    id: 'tf-upload',
    name: 'File Upload & MIME Verification',
    icon: 'upload_file',
    status: 'PASS',
    telemetrySummary: 'SVG sanitization active, magic bytes validation enforced',
  },
];

export const INITIAL_TERMINAL_LOGS: TerminalLog[] = [
  { id: '1', timestamp: '14:22:01', tag: 'RECON', text: 'Target: https://example.com identified (Nginx/1.24, Linux)' },
  { id: '2', timestamp: '14:22:04', tag: 'DISCOVERY', text: '137 endpoints found, 42 API routes categorized' },
  { id: '3', timestamp: '14:22:09', tag: 'ENGINE', text: 'Building contextual test vectors based on analysis...' },
  { id: '4', timestamp: '14:22:15', tag: 'TEST', text: 'Executing Authorization checks on /api/user/{id}' },
  { id: '5', timestamp: '14:22:16', tag: 'OBSERVATION', text: 'Behavior differs between user_A and user_B sessions' },
  { id: '6', timestamp: '14:22:18', tag: 'VALIDATION', text: 'Confirmation non-destructive: IDOR confirmed!' },
  { id: '7', timestamp: '14:22:18', tag: 'FINDING', text: 'Broken Access Control on /api/user/{id}', confidence: '94%', severity: 'HIGH' },
  { id: '8', timestamp: '14:22:24', tag: 'TEST', text: 'Testing Input Validation & SQL payloads on /search?q=...' },
  { id: '9', timestamp: '14:22:26', tag: 'ENGINE', text: "Injected 4 non-breaking boundary payloads into parameter 'q'" },
  { id: '10', timestamp: '14:22:27', tag: 'TELEMETRY', text: 'Latency response variance: 12ms (Threshold nominal)' },
  { id: '11', timestamp: '14:22:29', tag: 'FINDING', text: 'Broken Tenant Isolation on /api/orders', confidence: '99%', severity: 'CRITICAL' },
  { id: '12', timestamp: '14:22:31', tag: 'TEST', text: 'Rate limiting verification on /api/search (250 requests stream)' },
  { id: '13', timestamp: '14:22:33', tag: 'WARN', text: 'No 429 Too Many Requests response observed after burst' },
  { id: '14', timestamp: '14:22:35', tag: 'ACTIVE', text: 'Executing boundary checks on contextual endpoints...' },
];
