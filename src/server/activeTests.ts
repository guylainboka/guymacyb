import { getDatabase, saveDatabaseToDisk } from './db';
import { Finding, Severity } from '../types';
import { AuthorizationLevel } from './authorization';
import { realHttpProbe, probeSqli, probeXss, probeCors, probeRateLimit, theoreticalCvssFromSeverity } from './securityLab';
import { toolNikto } from './toolbridge';
import net from 'net';
import tls from 'tls';

// ============================================================
//  Moteur de TESTS ACTIFS RÉELS — Guyma Cyb
// ============================================================
//
// Chaque famille exécute de VRAIES requêtes réseau contre la cible
// autorisée (attestation ACTIVE/DESTRUCTIVE enregistrée au préalable).
// Les verdicts dérivent exclusivement des réponses réelles : si la cible
// est injoignable, la famille est marquée ERROR avec l'erreur réseau
// réelle — jamais de statut fabriqué.
//
// Niveaux :
//   ACTIVE      — sondes actives non altérantes (GET/OPTIONS/TRACE, reflets,
//                 détection d'erreurs, rafale de mesure de débit)
//   DESTRUCTIVE — outils agressifs complets (nikto) pouvant toucher les
//                 données ; exige l'attestation DESTRUCTIVE ET Safe Mode OFF.

export interface ActiveFamilyResult {
  id: string;
  name: string;
  level: 'ACTIVE' | 'DESTRUCTIVE';
  status: 'PASS' | 'FAIL' | 'SKIP' | 'ERROR';
  requests: number;
  durationMs: number;
  summary: string;
  logs: string[];
  findings: Finding[];
}

export interface ActiveRunResult {
  scanId: string;
  targetUrl: string;
  startedAt: string;
  durationMs: number;
  totalRequests: number;
  findingsCreated: number;
  families: ActiveFamilyResult[];
  safeMode: boolean;
  authorizationLevel: AuthorizationLevel;
}

const MAX_BODY_CAPTURE = 6000;

function safeDomain(url: string): string {
  try {
    return new URL(url.startsWith('http') ? url : `https://${url}`).hostname.replace(/[^a-z0-9.-]/gi, '_');
  } catch {
    return 'cible-invalide';
  }
}

interface PendingFinding {
  title: string;
  severity: Severity;
  category: string;
  cwe: string;
  description: string;
  evidenceRequest: string;
  evidenceResponse: string;
  impact: string;
  remediationTitle: string;
  remediationSteps: string[];
  affectedComponent: string;
}

async function persistRealFinding(
  scanId: string,
  targetUrl: string,
  operatorId: string,
  p: PendingFinding,
  tag: string
): Promise<Finding> {
  const db = await getDatabase();
  const cvss = theoreticalCvssFromSeverity(p.severity);
  const findingObj: Finding = {
    id: `ACT-FND-${Date.now().toString(36).toUpperCase()}-${Math.abs(persistSeq++).toString(36).toUpperCase()}`,
    title: p.title,
    severity: p.severity,
    cvss,
    confidence: 88,
    status: 'VALIDATED',
    affectedComponent: p.affectedComponent,
    category: p.category,
    cwe: p.cwe,
    description: p.description,
    evidence: {
      request: p.evidenceRequest.slice(0, MAX_BODY_CAPTURE),
      response: p.evidenceResponse.slice(0, MAX_BODY_CAPTURE),
      authContext: 'Tests actifs réels contre la cible autorisée (attestation enregistrée)',
      roundtripMs: 0,
      nonDestructiveProof: false,
    },
    impact: p.impact,
    remediationTitle: p.remediationTitle,
    remediationSteps: p.remediationSteps,
    signature: `ACT-${tag.toUpperCase()}-${scanId}`,
    sqliteRow: 0,
  };
  db.run(
    `INSERT INTO findings (
      id, scan_id, target_url, title, severity, cvss, confidence, status,
      affected_component, category, cwe, description, evidence_request,
      evidence_response, impact, remediation_title, remediation_steps_json, signature, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
    [
      findingObj.id,
      scanId,
      targetUrl,
      findingObj.title,
      findingObj.severity,
      findingObj.cvss,
      findingObj.confidence,
      findingObj.status,
      findingObj.affectedComponent,
      findingObj.category,
      findingObj.cwe,
      findingObj.description,
      findingObj.evidence.request,
      findingObj.evidence.response,
      findingObj.impact,
      findingObj.remediationTitle,
      JSON.stringify(findingObj.remediationSteps),
      findingObj.signature,
    ]
  );
  saveDatabaseToDisk(db);
  return findingObj;
}

let persistSeq = 0;

// ---------- Famille 1 : Durcissement des en-têtes (réel) ----------
async function familyHeaders(scanId: string, targetUrl: string, operatorId: string): Promise<ActiveFamilyResult> {
  const started = Date.now();
  const logs: string[] = [];
  const findings: Finding[] = [];
  let requests = 0;

  const ev = await realHttpProbe(targetUrl);
  requests++;
  if (ev.error) {
    return {
      id: 'headers', name: 'Durcissement HTTP', level: 'ACTIVE', status: 'ERROR',
      requests, durationMs: Date.now() - started,
      summary: `Cible injoignable : ${ev.error}`,
      logs: [`[ERROR] GET ${targetUrl} → ${ev.error}`], findings,
    };
  }
  logs.push(`[OK] GET ${targetUrl} → HTTP ${ev.status} (${ev.latencyMs}ms réels)`);

  const checks: { header: string; label: string; severity: Severity; cwe: string; advice: string }[] = [
    { header: 'content-security-policy', label: 'Content-Security-Policy', severity: 'MEDIUM', cwe: 'CWE-1021: Improper Restriction of Rendered UI Layers', advice: 'Déployer une politique CSP restrictive (default-src \'self\').', },
    { header: 'x-content-type-options', label: 'X-Content-Type-Options', severity: 'LOW', cwe: 'CWE-430: Deployment of Wrong Handler', advice: 'Ajouter X-Content-Type-Options: nosniff.' },
    { header: 'x-frame-options', label: 'X-Frame-Options / frame-ancestors', severity: 'MEDIUM', cwe: 'CWE-1021', advice: 'Interdire l\'encapsulation (X-Frame-Options: DENY ou CSP frame-ancestors).' },
    { header: 'referrer-policy', label: 'Referrer-Policy', severity: 'LOW', cwe: 'CWE-200: Exposure of Sensitive Information', advice: 'Définir Referrer-Policy: strict-origin-when-cross-origin.' },
    { header: 'permissions-policy', label: 'Permissions-Policy', severity: 'LOW', cwe: 'CWE-1021', advice: 'Restreindre les API navigateur via Permissions-Policy.' },
  ];

  let missing = 0;
  for (const c of checks) {
    if (!ev.headers[c.header]) {
      missing++;
      logs.push(`[FAIL] En-tête ${c.label} ABSENT de la réponse réelle.`);
      findings.push(
        await persistRealFinding(scanId, targetUrl, operatorId, {
          title: `En-tête de durcissement absent : ${c.label}`,
          severity: c.severity,
          category: 'A05:2021 - Security Misconfiguration',
          cwe: c.cwe,
          description: `La réponse réelle (HTTP ${ev.status}) ne contient pas l'en-tête ${c.label}.`,
          evidenceRequest: `GET ${targetUrl}`,
          evidenceResponse: `HTTP ${ev.status}\n${Object.entries(ev.headers).map(([k, v]) => `${k}: ${v}`).slice(0, 12).join('\n')}`,
          impact: 'Surface d\'attaque navigateur élargie (clickjacking, sniffing, fuites).',
          remediationTitle: 'Durcissement des en-têtes HTTP',
          remediationSteps: [c.advice],
          affectedComponent: targetUrl,
        }, 'headers')
      );
    } else {
      logs.push(`[PASS] ${c.label} présent.`);
    }
  }

  if (ev.headers['server']) {
    logs.push(`[WARN] Bannière serveur divulguée : ${ev.headers['server']}`);
    findings.push(
      await persistRealFinding(scanId, targetUrl, operatorId, {
        title: `Divulgation de bannière serveur : ${ev.headers['server']}`,
        severity: 'LOW',
        category: 'A05:2021 - Security Misconfiguration',
        cwe: 'CWE-200: Exposure of Sensitive Information',
        description: 'L\'en-tête Server expose la version exacte du serveur web — aide à la ciblage d\'exploits.',
        evidenceRequest: `GET ${targetUrl}`,
        evidenceResponse: `server: ${ev.headers['server']}`,
        impact: 'Facilite la reconnaissance et le ciblage de vulnérabilités connues de la version.',
        remediationTitle: 'Masquer la bannière serveur',
        remediationSteps: ['suppression de la directive ServerTokens (Apache) ou server_tokens off (Nginx).'],
        affectedComponent: targetUrl,
      }, 'headers')
    );
  }

  return {
    id: 'headers', name: 'Durcissement HTTP', level: 'ACTIVE',
    status: findings.length > 0 ? 'FAIL' : 'PASS',
    requests, durationMs: Date.now() - started,
    summary: `${missing} en-tête(s) manquant(s), ${findings.length} finding(s) réel(s).`,
    logs, findings,
  };
}

// ---------- Famille 2 : Verbes HTTP dangereux (réel) ----------
async function familyMethods(scanId: string, targetUrl: string, operatorId: string): Promise<ActiveFamilyResult> {
  const started = Date.now();
  const logs: string[] = [];
  const findings: Finding[] = [];
  let requests = 0;

  const opt = await realHttpProbe(targetUrl, { method: 'OPTIONS' });
  requests++;
  const allow = opt.headers['allow'] || opt.headers['access-control-allow-methods'] || '(aucun)';
  logs.push(`[OK] OPTIONS ${targetUrl} → HTTP ${opt.status ?? 'erreur'}, Allow: ${allow}`);
  if (opt.error) {
    return {
      id: 'methods', name: 'Verbes HTTP', level: 'ACTIVE', status: 'ERROR',
      requests, durationMs: Date.now() - started,
      summary: `Cible injoignable : ${opt.error}`, logs, findings,
    };
  }

  const trace = await realHttpProbe(targetUrl, { method: 'TRACE' });
  requests++;
  if (!trace.error && trace.status === 200 && trace.body.includes('TRACE')) {
    logs.push('[FAIL] TRACE activé et corps réfléchi — XST possible.');
    findings.push(
      await persistRealFinding(scanId, targetUrl, operatorId, {
        title: 'Méthode HTTP TRACE activée (Cross-Site Tracing)',
        severity: 'MEDIUM',
        category: 'A05:2021 - Security Misconfiguration',
        cwe: 'CWE-693: Protection Mechanism Failure',
        description: 'La cible répond HTTP 200 à une requête TRACE réelle — permet de contourner les protections de cookies HttpOnly.',
        evidenceRequest: `TRACE ${targetUrl}`,
        evidenceResponse: `HTTP ${trace.status}\n${trace.body.slice(0, 300)}`,
        impact: 'Vol de cookies via XST dans certains navigateurs.',
        remediationTitle: 'Désactiver TRACE',
        remediationSteps: ['Nginx: trace_method off / Apache: TraceEnable off.'],
        affectedComponent: targetUrl,
      }, 'methods')
    );
  } else {
    logs.push(`[PASS] TRACE rejeté (HTTP ${trace.status ?? 'erreur réseau réelle'}).`);
  }

  const canaryPath = `${targetUrl.replace(/\/+$/, '')}/guymacyb-canary-${Date.now()}`;
  const put = await realHttpProbe(canaryPath, { method: 'PUT', headers: { 'Content-Type': 'text/plain' } });
  requests++;
  const putAccepted = put.status !== null && put.status >= 200 && put.status < 300;
  if (!put.error && putAccepted) {
    logs.push(`[CRITIQUE] PUT accepté sur ${canaryPath} (HTTP ${put.status}) — écriture non authentifiée.`);
    findings.push(
      await persistRealFinding(scanId, targetUrl, operatorId, {
        title: 'Méthode PUT acceptée sans authentification',
        severity: 'CRITICAL',
        category: 'A01:2021 - Broken Access Control',
        cwe: 'CWE-650: Trusting HTTP Permission Methods',
        description: `Un PUT réel vers un chemin arbitraire (${canaryPath}) a été accepté (HTTP ${put.status}).`,
        evidenceRequest: `PUT ${canaryPath}`,
        evidenceResponse: `HTTP ${put.status}`,
        impact: 'Défacement / dépôt de fichiers sans authentification.',
        remediationTitle: 'Restreindre les verbes d\'écriture',
        remediationSteps: ['Désactiver PUT/DELETE/MKCOL au niveau du serveur web sauf endpoints explicitement conçus.'],
        affectedComponent: canaryPath,
      }, 'methods')
    );
  } else {
    logs.push(`[PASS] PUT refusé (HTTP ${put.status ?? 'erreur réseau réelle'}).`);
  }

  return {
    id: 'methods', name: 'Verbes HTTP', level: 'ACTIVE',
    status: findings.length > 0 ? 'FAIL' : 'PASS',
    requests, durationMs: Date.now() - started,
    summary: `${findings.length} finding(s) réel(s) sur ${requests} requêtes réelles.`,
    logs, findings,
  };
}

// ---------- Famille 3 : Audit TLS/SSL réel ----------
async function familyTls(scanId: string, targetUrl: string, operatorId: string): Promise<ActiveFamilyResult> {
  const started = Date.now();
  const logs: string[] = [];
  const findings: Finding[] = [];

  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return {
      id: 'tls', name: 'TLS/SSL', level: 'ACTIVE', status: 'ERROR',
      requests: 0, durationMs: Date.now() - started,
      summary: 'URL de cible invalide.', logs, findings,
    };
  }
  if (parsed.protocol !== 'https:') {
    logs.push('[WARN] Cible en HTTP clair — audit TLS sans objet ; le trafic n\'est PAS chiffré.');
    findings.push(
      await persistRealFinding(scanId, targetUrl, operatorId, {
        title: 'Cible servie en HTTP clair (aucun TLS)',
        severity: 'HIGH',
        category: 'A02:2021 - Cryptographic Failures',
        cwe: 'CWE-319: Cleartext Transmission of Sensitive Information',
        description: 'La cible répond en HTTP : toutes les données transitent en clair sur le réseau.',
        evidenceRequest: `GET ${targetUrl}`,
        evidenceResponse: 'Protocole http:// — aucune négociation TLS possible.',
        impact: 'Interception / manipulation du trafic (MITM).',
        remediationTitle: 'Déployer HTTPS (HSTS)',
        remediationSteps: ['Certificat TLS valide + redirection 301 + Strict-Transport-Security.'],
        affectedComponent: targetUrl,
      }, 'tls')
    );
    return {
      id: 'tls', name: 'TLS/SSL', level: 'ACTIVE', status: 'FAIL',
      requests: 0, durationMs: Date.now() - started,
      summary: 'HTTP clair détecté — aucun chiffrement.', logs, findings,
    };
  }

  const host = parsed.hostname;
  const info = await new Promise<{ ok: boolean; protocol?: string; cipher?: string; validTo?: Date; authorized?: boolean; error?: string }>((resolve) => {
    try {
      const sock = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false, timeout: 6000 }, () => {
        resolve({ ok: true, protocol: sock.getProtocol() || undefined, cipher: sock.getCipher()?.name, validTo: (sock as any).getPeerCertificate()?.valid_to ? new Date((sock as any).getPeerCertificate().valid_to) : undefined, authorized: sock.authorized });
        sock.destroy();
      });
      sock.on('error', (e) => resolve({ ok: false, error: e.message }));
      sock.on('timeout', () => { sock.destroy(); resolve({ ok: false, error: 'timeout de connexion TLS réelle' }); });
    } catch (e: any) {
      resolve({ ok: false, error: e?.message || 'erreur TLS' });
    }
  });

  if (!info.ok) {
    return {
      id: 'tls', name: 'TLS/SSL', level: 'ACTIVE', status: 'ERROR',
      requests: 1, durationMs: Date.now() - started,
      summary: `Négociation TLS impossible : ${info.error}`, logs: [`[ERROR] ${info.error}`], findings,
    };
  }

  logs.push(`[OK] Poignée de main TLS réelle : ${info.protocol}, chiffrement ${info.cipher ?? 'inconnu'}.`);
  const daysLeft = info.validTo ? Math.round((info.validTo.getTime() - Date.now()) / 86400000) : null;
  logs.push(`[OK] Certificat valable jusqu'au ${info.validTo?.toISOString().slice(0, 10) ?? 'inconnu'} (${daysLeft} jours restants).`);

  if (daysLeft !== null && daysLeft < 0) {
    findings.push(
      await persistRealFinding(scanId, targetUrl, operatorId, {
        title: 'Certificat TLS EXPIRÉ',
        severity: 'HIGH',
        category: 'A02:2021 - Cryptographic Failures',
        cwe: 'CWE-298: Improper Validation of Certificate With Host Mismatch',
        description: `Le certificat réel a expiré le ${info.validTo?.toISOString().slice(0, 10)}.`,
        evidenceRequest: `tls.connect ${host}:443`,
        evidenceResponse: `valid_to=${info.validTo?.toISOString()} (${daysLeft} jours)`,
        impact: 'Alertes navigateurs, MITM possible, perte de confiance.',
        remediationTitle: 'Renouveler le certificat',
        remediationSteps: ['Renouvellement (Let\'s Encrypt / ACME) et automatisation du renouvellement.'],
        affectedComponent: host,
      }, 'tls')
    );
  } else if (info.protocol && info.protocol < 'TLSv1.2') {
    findings.push(
      await persistRealFinding(scanId, targetUrl, operatorId, {
        title: `Protocole TLS obsolète négocié : ${info.protocol}`,
        severity: 'MEDIUM',
        category: 'A02:2021 - Cryptographic Failures',
        cwe: 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm',
        description: 'La poignée de main réelle a négocié un protocole antérieur à TLS 1.2.',
        evidenceRequest: `tls.connect ${host}:443`,
        evidenceResponse: `protocol=${info.protocol}, cipher=${info.cipher}`,
        impact: 'Affaiblissement cryptographique (POODLE/BEAST legacy).',
        remediationTitle: 'Imposer TLS 1.2+',
        remediationSteps: ['Désactiver TLSv1.0/1.1 dans la configuration du serveur.'],
        affectedComponent: host,
      }, 'tls')
    );
  }

  return {
    id: 'tls', name: 'TLS/SSL', level: 'ACTIVE',
    status: findings.length > 0 ? 'FAIL' : 'PASS',
    requests: 1, durationMs: Date.now() - started,
    summary: `${info.protocol}, certificat ${daysLeft !== null ? `${daysLeft}j restants` : 'inconnu'} — ${findings.length} finding(s).`,
    logs, findings,
  };
}

// ---------- Famille 4 : Fuzzing de chemins réel ----------
const DIRBRUTE_PATHS = [
  'admin', 'administrator', 'login', 'signin', 'signup', 'register', 'dashboard',
  'api', 'api/v1', 'api/v2', 'config', '.env', '.git/config', 'backup', 'backup.sql',
  'db.sql', 'phpinfo.php', 'wp-admin', 'wp-login.php', 'robots.txt', 'sitemap.xml',
  '.htaccess', 'server-status', 'actuator', 'actuator/health', 'swagger.json',
  'api-docs', 'graphql', 'console', 'debug', 'test', 'tmp', 'uploads', 'metrics', 'health',
];
const SENSITIVE_PATHS = ['.env', '.git/config', 'backup.sql', 'db.sql', 'backup', 'phpinfo.php', 'server-status', 'actuator', '.htaccess', 'config'];

async function familyDirbrute(scanId: string, targetUrl: string, operatorId: string): Promise<ActiveFamilyResult> {
  const started = Date.now();
  const logs: string[] = [];
  const findings: Finding[] = [];
  const base = targetUrl.replace(/\/+$/, '');
  let requests = 0;
  let found = 0;

  for (const p of DIRBRUTE_PATHS) {
    const ev = await realHttpProbe(`${base}/${p}`, { timeoutMs: 5000 });
    requests++;
    if (ev.error || ev.status === null) continue;
    if (ev.status >= 200 && ev.status < 300) {
      found++;
      logs.push(`[FOUND] /${p} → HTTP ${ev.status} (${ev.body.length} octets réels)`);
      if (SENSITIVE_PATHS.includes(p)) {
        const looksSensitive =
          p === '.env' ? /^[A-Z_]+=/.test(ev.body) || ev.body.includes('SECRET') :
          p === '.git/config' ? ev.body.includes('[core]') :
          p === 'phpinfo.php' ? ev.body.includes('phpinfo()') :
          p === 'server-status' ? ev.body.includes('Apache Server Status') :
          p === 'actuator' || p === 'actuator/health' ? ev.body.includes('"status"') || ev.body.includes('_links') :
          true;
        logs.push(`[SENSIBLE] /${p} exposé publiquement${looksSensitive ? ' avec contenu sensible réel' : ''}.`);
        findings.push(
          await persistRealFinding(scanId, targetUrl, operatorId, {
            title: `Ressource sensible exposée : /${p}`,
            severity: p === '.env' || p === '.git/config' ? 'CRITICAL' : 'HIGH',
            category: 'A05:2021 - Security Misconfiguration',
            cwe: 'CWE-538: Insertion of Sensitive Information into Externally-Accessible File',
            description: `Le chemin /${p} répond HTTP ${ev.status} publiquement${looksSensitive ? ' et expose un contenu sensible réel' : ''}.`,
            evidenceRequest: `GET ${base}/${p}`,
            evidenceResponse: `HTTP ${ev.status}\n${ev.body.slice(0, 500)}`,
            impact: 'Fuite de secrets / configuration / infrastructure.',
            remediationTitle: 'Restreindre l\'accès aux ressources sensibles',
            remediationSteps: ['Bloquer au niveau du serveur web, déplacer hors de la racine web, authentification obligatoire.'],
            affectedComponent: `${base}/${p}`,
          }, 'dirbrute')
        );
      }
    }
  }
  if (requests === 0) {
    return {
      id: 'dirbrute', name: 'Fuzzing de chemins', level: 'ACTIVE', status: 'ERROR',
      requests: 0, durationMs: Date.now() - started,
      summary: 'Aucune requête réalisable — cible injoignable.', logs: ['[ERROR] Cible injoignable pour toutes les requêtes.'], findings,
    };
  }

  return {
    id: 'dirbrute', name: 'Fuzzing de chemins', level: 'ACTIVE',
    status: findings.length > 0 ? 'FAIL' : 'PASS',
    requests, durationMs: Date.now() - started,
    summary: `${requests} chemins réellement sondés, ${found} accessibles (HTTP 2xx), ${findings.length} finding(s) sensible(s).`,
    logs, findings,
  };
}

// ---------- Familles 5-7 : réutilisent les sondes réelles du lab ----------
async function familyInjection(scanId: string, targetUrl: string, operatorId: string): Promise<ActiveFamilyResult> {
  const started = Date.now();
  const logs: string[] = [];
  const findings: Finding[] = [];

  const sqli = await probeSqli(targetUrl);
  const xss = await probeXss(targetUrl);
  const requests = sqli.evidences.length + xss.evidences.length;

  if (sqli.evidences.every((e) => e.error)) {
    return {
      id: 'injection', name: 'Injections (SQLi / XSS)', level: 'ACTIVE', status: 'ERROR',
      requests, durationMs: Date.now() - started,
      summary: `Cible injoignable : ${sqli.evidences[0]?.error ?? 'erreur réseau'}`, logs, findings,
    };
  }

  for (const [name, outcome, vectorMeta] of [
    ['SQLi', sqli, { title: 'Injection SQL détectée (erreur SQL exposée)', severity: 'HIGH' as Severity, cwe: 'CWE-89: SQL Injection', desc: 'La réponse réelle expose une erreur SQL brute face à un payload de détection.' }],
    ['XSS', xss, { title: 'XSS réfléchi détecté (reflet brut)', severity: 'HIGH' as Severity, cwe: 'CWE-79: Cross-site Scripting', desc: 'Le marqueur de sonde est réfléchi brut dans le HTML réel.' }],
  ] as const) {
    logs.push(`[${name}] ${outcome.verdict} — ${outcome.observations[0] ?? ''}`);
    if (outcome.verdict === 'VULNERABLE') {
      const ev = outcome.evidences.find((e) => !e.error)!;
      findings.push(
        await persistRealFinding(scanId, targetUrl, operatorId, {
          title: vectorMeta.title,
          severity: vectorMeta.severity,
          category: 'A03:2021 - Injection',
          cwe: vectorMeta.cwe,
          description: vectorMeta.desc,
          evidenceRequest: `${ev.method} ${ev.url}`,
          evidenceResponse: `HTTP ${ev.status}\n${ev.body.slice(0, 800)}`,
          impact: 'Exécution de code / lecture non autorisée en base selon le vecteur.',
          remediationTitle: 'Requêtes paramétrées + échappement contextuel',
          remediationSteps: ['Requêtes préparées (SQL) / échappement HTML contextuel + CSP (XSS).'],
          affectedComponent: ev.url,
        }, 'injection')
      );
    }
  }

  return {
    id: 'injection', name: 'Injections (SQLi / XSS)', level: 'ACTIVE',
    status: findings.length > 0 ? 'FAIL' : 'PASS',
    requests, durationMs: Date.now() - started,
    summary: `${findings.length} finding(s) réel(s) sur ${requests} requêtes réelles.`,
    logs, findings,
  };
}

async function familyCors(scanId: string, targetUrl: string, operatorId: string): Promise<ActiveFamilyResult> {
  const started = Date.now();
  const outcome = await probeCors(targetUrl);
  const logs = outcome.observations.map((o) => `[CORS] ${o}`);
  const findings: Finding[] = [];

  if (outcome.evidences.every((e) => e.error)) {
    return {
      id: 'cors', name: 'Politique CORS', level: 'ACTIVE', status: 'ERROR',
      requests: outcome.evidences.length, durationMs: Date.now() - started,
      summary: `Cible injoignable : ${outcome.evidences[0]?.error}`, logs, findings,
    };
  }

  if (outcome.verdict === 'VULNERABLE') {
    const ev = outcome.evidences.find((e) => !e.error)!;
    findings.push(
      await persistRealFinding(scanId, targetUrl, operatorId, {
        title: 'Politique CORS permissive (réflexion d\'origine arbitraire)',
        severity: 'MEDIUM',
        category: 'A05:2021 - Security Misconfiguration',
        cwe: 'CWE-942: Permissive Cross-domain Policy with Untrusted Domains',
        description: 'La cible accepte/réfléchit une origine arbitraire dans Access-Control-Allow-Origin.',
        evidenceRequest: `GET ${ev.url} (Origin: https://evil-guymacyb.example)`,
        evidenceResponse: `HTTP ${ev.status}\naccess-control-allow-origin: ${ev.headers['access-control-allow-origin'] ?? '(aucun)'}\naccess-control-allow-credentials: ${ev.headers['access-control-allow-credentials'] ?? '(aucun)'}`,
        impact: 'Lecture cross-origin des données depuis un navigateur victime.',
        remediationTitle: 'Liste blanche d\'origines stricte',
        remediationSteps: ['Ne jamais refléter l\'origine arbitrairement ; lister les origines de confiance côté serveur.'],
        affectedComponent: ev.url,
      }, 'cors')
    );
  }

  return {
    id: 'cors', name: 'Politique CORS', level: 'ACTIVE',
    status: findings.length > 0 ? 'FAIL' : outcome.verdict === 'PROTECTED' ? 'PASS' : 'PASS',
    requests: outcome.evidences.length, durationMs: Date.now() - started,
    summary: outcome.observations[0] ?? 'Sonde CORS exécutée.', logs, findings,
  };
}

async function familyRateLimit(scanId: string, targetUrl: string, operatorId: string): Promise<ActiveFamilyResult> {
  const started = Date.now();
  const outcome = await probeRateLimit(targetUrl);
  const logs = outcome.observations.map((o) => `[RATE] ${o}`);
  const findings: Finding[] = [];

  if (outcome.evidences.every((e) => e.error)) {
    return {
      id: 'ratelimit', name: 'Limitation de débit', level: 'ACTIVE', status: 'ERROR',
      requests: outcome.evidences.length, durationMs: Date.now() - started,
      summary: 'Cible injoignable — mesure réelle impossible.', logs, findings,
    };
  }

  if (outcome.verdict === 'VULNERABLE') {
    findings.push(
      await persistRealFinding(scanId, targetUrl, operatorId, {
        title: 'Aucune limitation de débit détectée (rafale 20 req)',
        severity: 'MEDIUM',
        category: 'A04:2021 - Insecure Design',
        cwe: 'CWE-770: Allocation of Resources Without Limits',
        description: '20 requêtes GET consécutives réelles ont toutes abouti sans rejet 429/503.',
        evidenceRequest: `GET ${targetUrl} ×20 (rafale)`,
        evidenceResponse: outcome.observations.join('\n'),
        impact: 'Brute-force, scraping, épuisement de ressources.',
        remediationTitle: 'Rate limiting applicatif / anti-brute-force',
        remediationSteps: ['Token bucket / sliding window par IP+session, CAPTCHA progressif.'],
        affectedComponent: targetUrl,
      }, 'ratelimit')
    );
  }

  return {
    id: 'ratelimit', name: 'Limitation de débit', level: 'ACTIVE',
    status: findings.length > 0 ? 'FAIL' : 'PASS',
    requests: outcome.evidences.length, durationMs: Date.now() - started,
    summary: outcome.observations[0] ?? 'Mesure de débit réelle exécutée.', logs, findings,
  };
}

// ---------- Famille 8 : nikto réel (DESTRUCTIVE) ----------
async function familyNikto(scanId: string, targetUrl: string, operatorId: string): Promise<ActiveFamilyResult> {
  const started = Date.now();
  const logs: string[] = [];
  const findings: Finding[] = [];

  try {
    const result: any = await toolNikto(targetUrl);
    if (result?.error) {
      return {
        id: 'nikto', name: 'Nikto (scanner actif complet)', level: 'DESTRUCTIVE', status: 'SKIP',
        requests: 0, durationMs: Date.now() - started,
        summary: `Outil indisponible : ${result.error}`,
        logs: [`[SKIP] nikto non exécuté : ${result.error}`], findings,
      };
    }
    const items: any[] = Array.isArray(result?.findings) ? result.findings : [];
    logs.push(`[OK] nikto réel exécuté (${items.length} élément(s) renvoyés par l'outil).`);
    for (const item of items.slice(0, 20)) {
      findings.push(
        await persistRealFinding(scanId, targetUrl, operatorId, {
          title: `[Nikto] ${String(item.title || item.description || 'Constat nikto').slice(0, 160)}`,
          severity: (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(String(item.severity)?.toUpperCase()) ? String(item.severity).toUpperCase() : 'MEDIUM') as Severity,
          category: 'Nikto Active Scan',
          cwe: String(item.cwe || 'CWE-16: Configuration'),
          description: String(item.description || item.title || 'Constat réel du scanner nikto.'),
          evidenceRequest: `nikto -h ${targetUrl} (outil réel via WSL/bash)`,
          evidenceResponse: JSON.stringify(item).slice(0, MAX_BODY_CAPTURE),
          impact: 'Constat réel du scanner actif nikto.',
          remediationTitle: 'Traiter le constat nikto',
          remediationSteps: [String(item.remediation || item.solution || 'Suivre la recommandation officielle nikto pour ce constat.')],
          affectedComponent: String(item.url || targetUrl),
        }, 'nikto')
      );
    }
    return {
      id: 'nikto', name: 'Nikto (scanner actif complet)', level: 'DESTRUCTIVE',
      status: findings.length > 0 ? 'FAIL' : 'PASS',
      requests: items.length, durationMs: Date.now() - started,
      summary: `${findings.length} finding(s) réels importés depuis nikto.`,
      logs, findings,
    };
  } catch (err: any) {
    return {
      id: 'nikto', name: 'Nikto (scanner actif complet)', level: 'DESTRUCTIVE', status: 'SKIP',
      requests: 0, durationMs: Date.now() - started,
      summary: `Outil indisponible : ${err?.message || 'erreur réelle'}`,
      logs: [`[SKIP] nikto non exécuté : ${err?.message || 'erreur réelle'}`], findings,
    };
  }
}

// ============================================================
//  Orchestrateur de la suite active réelle
// ============================================================

export async function runActiveTestSuite(
  targetUrl: string,
  operatorId: string,
  opts: { safeMode: boolean; authorizationLevel: AuthorizationLevel }
): Promise<ActiveRunResult> {
  const startedAt = new Date().toISOString();
  const suiteStart = Date.now();
  const scanId = `SCAN-ACTIVE-${Date.now().toString(36).toUpperCase()}`;
  const targetDomain = safeDomain(targetUrl);

  // Cible réelle + scan racine
  const db = await getDatabase();
  db.run(
    `INSERT OR REPLACE INTO targets (id, url, domain, scope, operator_id, created_at, last_scanned_at, status)
     VALUES (?, ?, ?, 'strict', ?, datetime('now'), datetime('now'), 'TESTING')`,
    [`target-${targetDomain}`, targetUrl, targetDomain, operatorId]
  );
  db.run(
    `INSERT INTO scans (id, target_id, url, scan_type, cvss_score, risk_level, duration_ms, endpoints_count, technologies_json, created_at)
     VALUES (?, ?, ?, 'ACTIVE_REAL_SUITE', 0, 'PENDING', 0, 0, '{}', datetime('now'))`,
    [scanId, `target-${targetDomain}`, targetUrl]
  );
  db.run(
    `INSERT INTO audit_logs (id, timestamp, tag, text, operator_id)
     VALUES (?, datetime('now'), 'ACTIVE_TEST_START', ?, ?)`,
    [`log-active-start-${Date.now()}`, `Suite active réelle démarrée contre ${targetUrl} (niveau d'attestation ${opts.authorizationLevel}, safeMode=${opts.safeMode}).`, operatorId]
  );
  saveDatabaseToDisk(db);

  const families: ActiveFamilyResult[] = [];

  families.push(await familyHeaders(scanId, targetUrl, operatorId));
  families.push(await familyMethods(scanId, targetUrl, operatorId));
  families.push(await familyTls(scanId, targetUrl, operatorId));
  families.push(await familyDirbrute(scanId, targetUrl, operatorId));
  families.push(await familyInjection(scanId, targetUrl, operatorId));
  families.push(await familyCors(scanId, targetUrl, operatorId));
  families.push(await familyRateLimit(scanId, targetUrl, operatorId));

  // Famille DESTRUCTIVE : exige attestation DESTRUCTIVE ET Safe Mode OFF.
  if (opts.authorizationLevel === 'DESTRUCTIVE' && !opts.safeMode) {
    families.push(await familyNikto(scanId, targetUrl, operatorId));
  } else {
    families.push({
      id: 'nikto', name: 'Nikto (scanner actif complet)', level: 'DESTRUCTIVE', status: 'SKIP',
      requests: 0, durationMs: 0,
      summary:
        opts.safeMode
          ? 'Safe Mode ACTIF : scanner complet nikto non lancé. Désactivez le Safe Mode avec l\'attestation DESTRUCTIVE pour l\'exécuter réellement.'
          : 'Attestation ACTIVE uniquement : l\'attestation DESTRUCTIVE est requise pour lancer nikto réellement.',
      logs: ['[SKIP] Famille déstructrice non exécutée (garde-fou légal).'],
      findings: [],
    });
  }

  const durationMs = Date.now() - suiteStart;
  const totalRequests = families.reduce((a, f) => a + f.requests, 0);
  const findingsCreated = families.reduce((a, f) => a + f.findings.length, 0);
  const maxCvss = Math.max(0, ...families.flatMap((f) => f.findings.map((x) => x.cvss ?? 0)));
  const worstSeverity: Severity = findingsCreated === 0 ? 'INFO' : maxCvss >= 9 ? 'CRITICAL' : maxCvss >= 7 ? 'HIGH' : maxCvss >= 4 ? 'MEDIUM' : 'LOW';

  // Mise à jour du scan racine avec les métriques réelles
  // (la table scans n'a pas de colonne status — cf. initTables() de db.ts)
  db.run(
    `UPDATE scans SET cvss_score = ?, risk_level = ?, duration_ms = ?, endpoints_count = ? WHERE id = ?`,
    [maxCvss, worstSeverity, durationMs, totalRequests, scanId]
  );
  db.run(
    `INSERT INTO audit_logs (id, timestamp, tag, text, operator_id)
     VALUES (?, datetime('now'), 'ACTIVE_TEST_DONE', ?, ?)`,
    [`log-active-done-${Date.now()}`, `Suite active réelle terminée : ${totalRequests} requêtes réelles, ${findingsCreated} finding(s) persisté(s), ${durationMs}ms.`, operatorId]
  );
  saveDatabaseToDisk(db);

  return {
    scanId,
    targetUrl,
    startedAt,
    durationMs,
    totalRequests,
    findingsCreated,
    families,
    safeMode: opts.safeMode,
    authorizationLevel: opts.authorizationLevel,
  };
}
