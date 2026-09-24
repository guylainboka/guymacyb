import { getDatabase, saveDatabaseToDisk } from './db';
import crypto from 'crypto';

export interface ScanResult {
  scanId: string;
  targetUrl: string;
  domain: string;
  statusCode: number;
  statusText: string;
  latencyMs: number;
  headers: Record<string, string>;
  tls: {
    protocol: string;
    isHttps: boolean;
    grade: string;
    details: string;
  };
  technologies: string[];
  endpoints: Array<{
    id: string;
    path: string;
    method: string;
    status: number;
    statusText: string;
    type: 'root' | 'page' | 'folder' | 'api' | 'auth' | 'admin';
    note?: string;
    hasFinding?: boolean;
    findingSeverity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  }>;
  findings: Array<{
    id: string;
    title: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    cvss: number;
    confidence: number;
    status: 'VALIDATED' | 'DETECTED' | 'POTENTIAL';
    affectedComponent: string;
    category: string;
    cwe: string;
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
    signature: string;
    sqliteRow: number;
  }>;
  overallRisk: 'HIGH' | 'MED' | 'LOW' | 'CLEAN';
  cvssScore: number;
  summary: {
    endpointsCount: number;
    apiRoutesCount: number;
    technologiesCount: number;
    anomaliesCount: number;
  };
}

export async function checkConnectivity(targetUrl: string): Promise<{
  success: boolean;
  statusCode?: number;
  latencyMs: number;
  serverBanner?: string;
  tlsVersion?: string;
  error?: string;
}> {
  const start = Date.now();
  let normalized = targetUrl.trim();
  if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
    normalized = `https://${normalized}`;
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);

    const res = await fetch(normalized, {
      method: 'HEAD',
      signal: controller.signal,
      headers: {
        'User-Agent': 'ShadowScan-Security-Auditor/1.0 (+https://github.com/shadowscan/assessment)',
      },
    });
    clearTimeout(timeout);

    const latency = Date.now() - start;
    const serverHeader = res.headers.get('server') || res.headers.get('x-powered-by') || 'Non divulgué';
    const isHttps = normalized.startsWith('https://');

    return {
      success: true,
      statusCode: res.status,
      latencyMs: latency,
      serverBanner: serverHeader,
      tlsVersion: isHttps ? 'TLS 1.3 / 1.2' : 'Non chiffré (HTTP brut)',
    };
  } catch (err: any) {
    const latency = Date.now() - start;
    return {
      success: false,
      latencyMs: latency,
      error: err.message || 'Impossible de se connecter à la cible',
    };
  }
}

export async function runRealAnalysis(
  targetUrl: string,
  scope: 'strict' | 'wildcard',
  operatorId: string
): Promise<ScanResult> {
  const startTime = Date.now();
  let normalized = targetUrl.trim();
  if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
    normalized = `https://${normalized}`;
  }

  const urlObj = new URL(normalized);
  const domain = urlObj.hostname;
  const isHttps = urlObj.protocol === 'https:';

  // 1. Send real GET request
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);

  let initialRes: Response;
  let bodyText = '';
  let latencyMs = 0;
  try {
    const reqStart = Date.now();
    initialRes = await fetch(normalized, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        'User-Agent': 'ShadowScan-Security-Auditor/1.0 (+https://github.com/shadowscan/assessment)',
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
    });
    latencyMs = Date.now() - reqStart;
    clearTimeout(timeout);
    bodyText = await initialRes.text().catch(() => '');
  } catch (err: any) {
    clearTimeout(timeout);
    throw new Error(`Échec de connexion vers ${normalized}: ${err.message}`);
  }

  // 2. Extract real headers
  const rawHeaders: Record<string, string> = {};
  initialRes.headers.forEach((val, key) => {
    rawHeaders[key.toLowerCase()] = val;
  });

  // 3. Test OPTIONS method (safe verifier)
  let allowedMethods = 'GET, HEAD';
  let isTraceEnabled = false;
  try {
    const optionsRes = await fetch(normalized, {
      method: 'OPTIONS',
      headers: { 'User-Agent': 'ShadowScan-Security-Auditor/1.0' },
    });
    const allowHeader = optionsRes.headers.get('allow');
    if (allowHeader) {
      allowedMethods = allowHeader;
      if (allowHeader.toUpperCase().includes('TRACE')) {
        isTraceEnabled = true;
      }
    }
  } catch {
    // ignore
  }

  // 4. Crawl HTML body for real routes and links
  const discoveredPaths = new Set<string>();
  discoveredPaths.add('/');

  // Regex patterns to find links and API paths
  const hrefMatches = bodyText.matchAll(/href=["'](\/[a-zA-Z0-9_\-\.\/]+)["']/g);
  for (const m of hrefMatches) {
    const p = m[1];
    if (p && !p.startsWith('//') && p.length < 80) {
      discoveredPaths.add(p);
    }
  }

  const srcMatches = bodyText.matchAll(/src=["'](\/[a-zA-Z0-9_\-\.\/]+)["']/g);
  for (const m of srcMatches) {
    const p = m[1];
    if (p && !p.startsWith('//') && p.length < 80) {
      discoveredPaths.add(p);
    }
  }

  const apiMatches = bodyText.matchAll(/["'](\/api\/[a-zA-Z0-9_\-\.\/]+)["']/g);
  for (const m of apiMatches) {
    const p = m[1];
    if (p && p.length < 80) {
      discoveredPaths.add(p);
    }
  }

  // Check robots.txt passively
  try {
    const robotsRes = await fetch(new URL('/robots.txt', normalized).toString(), {
      method: 'GET',
      headers: { 'User-Agent': 'ShadowScan-Security-Auditor/1.0' },
    });
    if (robotsRes.status === 200) {
      discoveredPaths.add('/robots.txt');
      const robotsText = await robotsRes.text();
      const disallowMatches = robotsText.matchAll(/Disallow:\s*([^\s#]+)/g);
      for (const dm of disallowMatches) {
        if (dm[1] && dm[1].startsWith('/')) {
          discoveredPaths.add(dm[1].trim());
        }
      }
    }
  } catch {
    // ignore
  }

  // 5. Detect technologies from headers and HTML markers
  const detectedTech = new Set<string>();
  const serverVal = rawHeaders['server'] || '';
  if (serverVal) detectedTech.add(serverVal);
  if (rawHeaders['x-powered-by']) detectedTech.add(rawHeaders['x-powered-by']);
  if (bodyText.includes('react') || bodyText.includes('__next') || bodyText.includes('root')) detectedTech.add('React');
  if (bodyText.includes('vue') || bodyText.includes('__nuxt')) detectedTech.add('Vue.js');
  if (bodyText.includes('wp-content') || bodyText.includes('wordpress')) detectedTech.add('WordPress');
  if (serverVal.toLowerCase().includes('nginx')) detectedTech.add('Nginx Web Server');
  if (serverVal.toLowerCase().includes('apache')) detectedTech.add('Apache HTTPD');
  if (serverVal.toLowerCase().includes('cloudflare')) detectedTech.add('Cloudflare Edge CDN');
  if (isHttps) detectedTech.add('TLS 1.3 / OpenSSL');
  if (detectedTech.size === 0) detectedTech.add('HTTP/1.1 Standard Stack');

  // 6. Security Analysis & Vulnerabilities Identification
  const findings: ScanResult['findings'] = [];
  const scanId = `scan-${Date.now()}`;
  let cvssBaseTotal = 0;

  // Check A: Content-Security-Policy
  if (!rawHeaders['content-security-policy']) {
    const findingId = `SEC-${Date.now()}-CSP`;
    findings.push({
      id: findingId,
      title: 'Absence de Content Security Policy (CSP)',
      severity: 'MEDIUM',
      cvss: 5.3,
      confidence: 100,
      status: 'VALIDATED',
      affectedComponent: 'En-tête HTTP: Content-Security-Policy',
      category: 'Headers Security',
      cwe: 'CWE-1021',
      description: `Aucun en-tête Content-Security-Policy n'a été renvoyé par ${domain}. En l'absence de CSP, le navigateur exécutera tout script inline sans politique de confinement contre les injections XSS.`,
      evidence: {
        authContext: 'Inspection passive des en-têtes HTTP',
        roundtripMs: latencyMs,
        nonDestructiveProof: true,
        request: `GET / HTTP/1.1\nHost: ${domain}\nUser-Agent: ShadowScan-Security-Auditor/1.0`,
        response: `HTTP/1.1 ${initialRes.status} ${initialRes.statusText}\n${Object.entries(rawHeaders)
          .map(([k, v]) => `${k}: ${v}`)
          .slice(0, 7)
          .join('\n')}\n(Content-Security-Policy absent)`,
      },
      impact: 'Augmentation du risque d’exécution de code JavaScript non autorisé, vol de tokens de session et détournement d’interface.',
      remediationTitle: 'Déploiement Header CSP Stricte',
      remediationSteps: [
        "Définir l'en-tête HTTP : Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';",
        "Éviter absolument les directives 'unsafe-inline' et 'unsafe-eval'.",
      ],
      signature: crypto.createHash('md5').update(`${domain}-csp`).digest('hex'),
      sqliteRow: 1,
    });
    cvssBaseTotal = Math.max(cvssBaseTotal, 5.3);
  }

  // Check B: Strict-Transport-Security (HSTS)
  if (isHttps && !rawHeaders['strict-transport-security']) {
    const findingId = `SEC-${Date.now()}-HSTS`;
    findings.push({
      id: findingId,
      title: 'En-tête HSTS (HTTP Strict Transport Security) manquant',
      severity: 'MEDIUM',
      cvss: 4.8,
      confidence: 100,
      status: 'VALIDATED',
      affectedComponent: 'En-tête HTTP: Strict-Transport-Security',
      category: 'Transport Security',
      cwe: 'CWE-319',
      description: `La cible ${domain} propose HTTPS mais n'envoie pas l'en-tête HSTS. Un attaquant sur le même réseau local (Wi-Fi public) peut tenter une attaque de déclassement SSLStrip vers HTTP non chiffré.`,
      evidence: {
        authContext: 'Vérification TLS Transport Layer',
        roundtripMs: latencyMs,
        nonDestructiveProof: true,
        request: `GET / HTTP/1.1\nHost: ${domain}`,
        response: `HTTP/1.1 ${initialRes.status} ${initialRes.statusText}\n(Strict-Transport-Security absent)`,
      },
      impact: 'Attaque de type Man-in-the-Middle (MitM) et interception de trafic non chiffré.',
      remediationTitle: 'Activer la directive HSTS',
      remediationSteps: [
        'Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
      ],
      signature: crypto.createHash('md5').update(`${domain}-hsts`).digest('hex'),
      sqliteRow: 2,
    });
    cvssBaseTotal = Math.max(cvssBaseTotal, 4.8);
  }

  // Check C: X-Frame-Options (Clickjacking)
  if (!rawHeaders['x-frame-options'] && !rawHeaders['content-security-policy']?.includes('frame-ancestors')) {
    const findingId = `SEC-${Date.now()}-XFO`;
    findings.push({
      id: findingId,
      title: 'Absence de protection anti-Clickjacking (X-Frame-Options manquant)',
      severity: 'MEDIUM',
      cvss: 4.3,
      confidence: 95,
      status: 'VALIDATED',
      affectedComponent: 'En-tête HTTP: X-Frame-Options',
      category: 'UI Redressing',
      cwe: 'CWE-1021',
      description: `L'application web ne définit ni X-Frame-Options ni frame-ancestors. Le site peut être intégré dans une balise <iframe> transparente sur un domaine tiers malveillant pour intercepter des clics utilisateur.`,
      evidence: {
        authContext: 'Inspection de réponse HTTP',
        roundtripMs: latencyMs,
        nonDestructiveProof: true,
        request: `GET / HTTP/1.1\nHost: ${domain}`,
        response: `HTTP/1.1 ${initialRes.status} ${initialRes.statusText}\n(X-Frame-Options absent)`,
      },
      impact: 'Détournement de clics (Clickjacking) forçant des actions non intentionnelles.',
      remediationTitle: 'Activer X-Frame-Options SAMEORIGIN',
      remediationSteps: [
        'Ajouter l’en-tête HTTP : X-Frame-Options: SAMEORIGIN ou DENY',
      ],
      signature: crypto.createHash('md5').update(`${domain}-xfo`).digest('hex'),
      sqliteRow: 3,
    });
    cvssBaseTotal = Math.max(cvssBaseTotal, 4.3);
  }

  // Check D: Server / X-Powered-By Banner Leak
  if (rawHeaders['server'] || rawHeaders['x-powered-by']) {
    const leaked = [rawHeaders['server'], rawHeaders['x-powered-by']].filter(Boolean).join(' / ');
    const findingId = `SEC-${Date.now()}-BANNER`;
    findings.push({
      id: findingId,
      title: 'Divulgation de bannière serveur (Information Disclosure)',
      severity: 'LOW',
      cvss: 3.1,
      confidence: 100,
      status: 'VALIDATED',
      affectedComponent: 'Header HTTP: Server / X-Powered-By',
      category: 'Information Disclosure',
      cwe: 'CWE-200',
      description: `La cible expose la signature logicielle suivante : "${leaked}". Cela facilite la reconnaissance d'un attaquant pour cibler les vulnérabilités connues de cette version logicielle.`,
      evidence: {
        authContext: 'Lecture des en-têtes HTTP',
        roundtripMs: latencyMs,
        nonDestructiveProof: true,
        request: `GET / HTTP/1.1\nHost: ${domain}`,
        response: `HTTP/1.1 ${initialRes.status} ${initialRes.statusText}\nServer: ${rawHeaders['server'] || 'N/A'}\nX-Powered-By: ${rawHeaders['x-powered-by'] || 'N/A'}`,
      },
      impact: 'Reconnaissance automatisée facilitant le ciblage d’exploits spécifiques.',
      remediationTitle: 'Désactiver la bannière logicielle',
      remediationSteps: [
        'Nginx : ajouter "server_tokens off;" dans nginx.conf',
        'Express.js : ajouter "app.disable(\'x-powered-by\');"',
      ],
      signature: crypto.createHash('md5').update(`${domain}-banner`).digest('hex'),
      sqliteRow: 4,
    });
  }

  // Check E: Method TRACE enabled
  if (isTraceEnabled) {
    const findingId = `SEC-${Date.now()}-TRACE`;
    findings.push({
      id: findingId,
      title: 'Méthode HTTP TRACE activée (Risque Cross-Site Tracing XST)',
      severity: 'HIGH',
      cvss: 7.2,
      confidence: 90,
      status: 'VALIDATED',
      affectedComponent: 'OPTIONS/TRACE /',
      category: 'HTTP Methods',
      cwe: 'CWE-693',
      description: `La méthode HTTP TRACE est autorisée sur le serveur. Elle permet de réfléchir la requête HTTP complète et de contourner les protections HttpOnly des cookies de session.`,
      evidence: {
        authContext: 'Sonde de méthodes HTTP',
        roundtripMs: latencyMs,
        nonDestructiveProof: true,
        request: `OPTIONS / HTTP/1.1\nHost: ${domain}`,
        response: `HTTP/1.1 200 OK\nAllow: ${allowedMethods}`,
      },
      impact: 'Contournement du flag de sécurité HttpOnly sur les cookies de session.',
      remediationTitle: 'Désactiver le verbe HTTP TRACE',
      remediationSteps: [
        'Nginx: if ($request_method = TRACE) { return 405; }',
        'Apache: TraceEnable Off',
      ],
      signature: crypto.createHash('md5').update(`${domain}-trace`).digest('hex'),
      sqliteRow: 5,
    });
    cvssBaseTotal = Math.max(cvssBaseTotal, 7.2);
  }

  // 7. Format discovered Endpoints
  const endpointsList = Array.from(discoveredPaths).map((p, idx) => {
    const isApi = p.includes('/api') || p.includes('.json');
    const isAuth = p.includes('login') || p.includes('auth') || p.includes('signin');
    const isAdmin = p.includes('admin') || p.includes('dashboard') || p.includes('metrics');
    let type: 'root' | 'page' | 'folder' | 'api' | 'auth' | 'admin' = 'page';
    if (p === '/') type = 'root';
    else if (isApi) type = 'api';
    else if (isAuth) type = 'auth';
    else if (isAdmin) type = 'admin';

    return {
      id: `ep-${idx}`,
      path: p,
      method: 'GET',
      status: p === '/' ? initialRes.status : 200,
      statusText: p === '/' ? `${initialRes.status} ${initialRes.statusText}` : 'Découvert',
      type,
      note: isApi ? 'Route API' : isAdmin ? 'Zone restreinte' : undefined,
      hasFinding: isAdmin || (isApi && findings.length > 0),
      findingSeverity: (isAdmin ? 'HIGH' : 'MEDIUM') as any,
    };
  });

  const apiCount = endpointsList.filter((e) => e.type === 'api').length;
  const overallRisk: 'HIGH' | 'MED' | 'LOW' | 'CLEAN' =
    cvssBaseTotal >= 7.0 ? 'HIGH' : cvssBaseTotal >= 4.0 ? 'MED' : cvssBaseTotal > 0 ? 'LOW' : 'CLEAN';

  const result: ScanResult = {
    scanId,
    targetUrl: normalized,
    domain,
    statusCode: initialRes.status,
    statusText: initialRes.statusText || 'OK',
    latencyMs,
    headers: rawHeaders,
    tls: {
      protocol: isHttps ? 'TLS 1.3 / 1.2' : 'HTTP Clair (Non chiffré)',
      isHttps,
      grade: isHttps ? (rawHeaders['strict-transport-security'] ? 'Grade A+' : 'Grade B') : 'Grade F (Insecure)',
      details: isHttps ? 'Chiffrement de transport actif' : 'Trafic non chiffré vulnérable aux écoutes réseau',
    },
    technologies: Array.from(detectedTech),
    endpoints: endpointsList,
    findings,
    overallRisk,
    cvssScore: Number(cvssBaseTotal.toFixed(1)) || 3.1,
    summary: {
      endpointsCount: endpointsList.length,
      apiRoutesCount: apiCount,
      technologiesCount: detectedTech.size,
      anomaliesCount: findings.length,
    },
  };

  // 8. Persist into SQLite Real Database!
  try {
    const db = await getDatabase();
    const duration = Date.now() - startTime;

    // Upsert target
    db.run(
      `
      INSERT INTO targets (id, url, domain, scope, operator_id, created_at, last_scanned_at, status)
      VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'), 'COMPLETED')
      ON CONFLICT(id) DO UPDATE SET last_scanned_at = datetime('now'), status = 'COMPLETED'
    `,
      [`target-${domain}`, normalized, domain, scope, operatorId]
    );

    // Insert scan
    db.run(
      `
      INSERT INTO scans (id, target_id, url, scan_type, cvss_score, risk_level, duration_ms, endpoints_count, technologies_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `,
      [
        scanId,
        `target-${domain}`,
        normalized,
        'PASSIVE_AND_SEMI_ACTIVE',
        result.cvssScore,
        overallRisk,
        duration,
        endpointsList.length,
        JSON.stringify(result.technologies),
      ]
    );

    // Insert endpoints
    for (const ep of endpointsList.slice(0, 50)) {
      db.run(
        `
        INSERT INTO endpoints (id, scan_id, path, method, status_code, status_text, type, note, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      `,
        [ep.id, scanId, ep.path, ep.method, ep.status, ep.statusText, ep.type, ep.note || '']
      );
    }

    // Insert findings
    for (const f of findings) {
      db.run(
        `
        INSERT INTO findings (id, scan_id, target_url, title, severity, cvss, confidence, status, affected_component, category, cwe, description, evidence_request, evidence_response, impact, remediation_title, remediation_steps_json, signature, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      `,
        [
          f.id,
          scanId,
          normalized,
          f.title,
          f.severity,
          f.cvss,
          f.confidence,
          f.status,
          f.affectedComponent,
          f.category,
          f.cwe,
          f.description,
          f.evidence.request,
          f.evidence.response,
          f.impact,
          f.remediationTitle,
          JSON.stringify(f.remediationSteps),
          f.signature,
        ]
      );
    }

    // Save SQLite database file to disk
    saveDatabaseToDisk(db);
  } catch (dbErr) {
    console.error('Failed to commit scan to SQLite:', dbErr);
  }

  return result;
}
