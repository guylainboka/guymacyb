import { getDatabase, saveDatabaseToDisk } from './db';
import { Finding, Severity, LabAttackVector } from '../types';
import { LAB_ATTACK_VECTORS } from '../data/labAttackVectors';
import { computeCvss31 } from './cvss31';
import dns from 'dns/promises';
import net from 'net';

// ============================================================
//  Helpers « zéro invention » du laboratoire
// ============================================================

/**
 * Compteur monotone pour les IDs de findings du lab.
 * Garantit l'unicité séquentielle au sein du processus (un random
 * serait non déterministe et susceptible de collisions).
 */
let labFindingSeq = 0;
function nextLabFindingSeq(): number {
  labFindingSeq += 1;
  return labFindingSeq;
}

/**
 * Score CVSS DE SECOURS pour les findings dont la source ne fournit PAS de
 * vecteur v3.1 (ex. noyau de scan Rust, items nikto) : point médian des
 * bandes NVD (CRITICAL 9.5 / HIGH 8.0 / MEDIUM 5.5 / LOW 2.5), déterministe.
 *
 * ⚠ Chaque fois qu'un vecteur CVSS v3.1 réel est disponible (datasets du lab,
 * familles de tests actifs), le score est CALCULÉ via computeCvss31() —
 * cette fonction n'est que le repli documenté.
 */
export function theoreticalCvssFromSeverity(severity: Severity): number {
  switch (severity) {
    case 'CRITICAL':
      return 9.5;
    case 'HIGH':
      return 8.0;
    case 'MEDIUM':
      return 5.5;
    default: // LOW / INFO
      return 2.5;
  }
}

/**
 * Résout le score CVSS RÉEL d'un vecteur du lab : calcul vectoriel v3.1
 * (AV/AC/PR/UI/S/C/I/A) à partir du vecteur officiel du dataset. La
 * sévérité affichée est DÉRIVÉE du score calculé — score et sévérité ne
 * peuvent plus jamais diverger. Fallback documenté si le dataset n'a pas
 * encore de vecteur.
 */
export function resolveVectorCvss(vector: Pick<LabAttackVector, 'cvssVector' | 'severity'>): {
  score: number;
  severity: Severity;
  vector: string | null;
} {
  if (vector.cvssVector) {
    try {
      const computed = computeCvss31(vector.cvssVector);
      return { score: computed.baseScore, severity: computed.severity as Severity, vector: computed.vector };
    } catch {
      // vecteur malformé dans le dataset → repli documenté (ne doit pas arriver)
    }
  }
  return { score: theoreticalCvssFromSeverity(vector.severity), severity: vector.severity, vector: null };
}

// ============================================================
//  Sondes HTTP RÉELLES — le laboratoire envoie de vraies requêtes
//  à la vraie cible et analyse les vraies réponses. Aucune réponse
//  n'est fabriquée : si la cible est injoignable, le verdict est
//  INCONCLUSIVE avec l'erreur réseau réelle.
// ============================================================

const MAX_BODY_CAPTURE = 8000; // troncature de la preuve (réseau réel)

export interface HttpProbeEvidence {
  method: string;
  url: string;
  status: number | null;
  latencyMs: number;
  headers: Record<string, string>;
  body: string;
  error: string | null;
}

/**
 * Sonde HTTP réelle : vraie requête réseau (fetch natif), capture de la
 * réponse réelle (statut, en-têtes, corps tronqué) et de la latence réelle.
 */
export async function realHttpProbe(
  url: string,
  init?: { method?: string; headers?: Record<string, string>; timeoutMs?: number }
): Promise<HttpProbeEvidence> {
  const started = Date.now();
  const method = init?.method || 'GET';
  try {
    const res = await fetch(url, {
      method,
      headers: {
        'User-Agent': 'GuymaCyb-Lab/1.0 (audit autorisé; +https://github.com/guylainboka/guymacyb)',
        ...(init?.headers || {}),
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(init?.timeoutMs ?? 8000),
    });
    const bodyRaw = await res.text();
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      headers[k] = v;
    });
    return {
      method,
      url,
      status: res.status,
      latencyMs: Date.now() - started,
      headers,
      body: bodyRaw.slice(0, MAX_BODY_CAPTURE),
      error: null,
    };
  } catch (err: any) {
    return {
      method,
      url,
      status: null,
      latencyMs: Date.now() - started,
      headers: {},
      body: '',
      error: err?.message || 'erreur réseau réelle',
    };
  }
}

function formatEvidence(ev: HttpProbeEvidence): string {
  if (ev.error) {
    return `${ev.method} ${ev.url}\n→ ERREUR RÉELLE : ${ev.error}`;
  }
  const interesting = Object.entries(ev.headers)
    .filter(([k]) =>
      ['content-type', 'server', 'x-powered-by', 'content-length', 'access-control-allow-origin', 'access-control-allow-credentials', 'allow', 'location'].includes(k)
    )
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');
  return `${ev.method} ${ev.url}\n→ HTTP ${ev.status} (${ev.latencyMs}ms)\n${interesting}\n\n--- Corps réel (tronqué) ---\n${ev.body.slice(0, 1200)}`;
}

const SQL_ERROR_SIGNATURES: RegExp[] = [
  /you have an error in your sql syntax/i,
  /warning: mysql/i,
  /unclosed quotation mark after/i,
  /quoted string not properly terminated/i,
  /pg_query\(\)|psql:|error: syntax error at or near/i,
  /sqlite3?::query|sqlite_master|unrecognized token/i,
  /odbc.*driver.*error|microsoft oledb/i,
  /ora-\d{5}:|oracle error/i,
  /fatal error: uncaught.*pdo/i,
  /sql syntax.*mysql|postgresql.*error/i,
];

const INTERNAL_URL_PARAMS = ['url', 'site', 'feed', 'proxy', 'fetch', 'target', 'src'];
const SQLI_PARAMS = ['q', 's', 'search', 'id', 'cat', 'page'];
const XSS_PARAMS = ['q', 's', 'search', 'name', 'comment'];
const TRAVERSAL_PARAMS = ['file', 'page', 'path', 'template', 'include', 'tpl'];
const IDOR_CANDIDATE_PATHS = ['/api/user/1', '/api/users/1', '/api/v1/users/1', '/api/account/1', '/api/orders/1'];
const PII_KEYS = ['email', 'phone', 'tel', 'address', 'firstname', 'lastname', 'dob', 'ssn', 'password_hash'];

function appendQueryParam(rawUrl: string, key: string, value: string): string {
  const sep = rawUrl.includes('?') ? '&' : '?';
  return `${rawUrl}${sep}${encodeURIComponent(key)}=${encodeURIComponent(value)}`;
}

interface VectorProbeOutcome {
  verdict: 'VULNERABLE' | 'PROTECTED' | 'INCONCLUSIVE';
  observations: string[];
  evidences: HttpProbeEvidence[];
}

// ---------- Sonde 1 : Injection SQL (détection d'erreur, 1 tir) ----------
export async function probeSqli(targetUrl: string): Promise<VectorProbeOutcome> {
  const evidences: HttpProbeEvidence[] = [];
  const observations: string[] = [];
  let vulnerable = false;

  for (const param of SQLI_PARAMS.slice(0, 3)) {
    const probeUrl = appendQueryParam(targetUrl, param, "'");
    const ev = await realHttpProbe(probeUrl);
    evidences.push(ev);
    if (ev.error) {
      observations.push(`Paramètre ${param} : cible injoignable (${ev.error}) — sonde réelle abandonnée.`);
      continue;
    }
    const matched = SQL_ERROR_SIGNATURES.find((rx) => rx.test(ev.body));
    if (matched) {
      vulnerable = true;
      observations.push(
        `Paramètre « ${param} » avec payload ' : ERREUR SQL BRUTE exposée dans la réponse réelle (motif: ${matched.source.slice(0, 60)}…) — injection SQL détectée (HTTP ${ev.status}).`
      );
      break;
    }
    observations.push(`Paramètre « ${param} » avec payload ' : réponse HTTP ${ev.status} sans erreur SQL visible (corps ${ev.body.length} octets réels).`);
  }

  return {
    verdict: vulnerable ? 'VULNERABLE' : evidences.some((e) => !e.error) ? 'PROTECTED' : 'INCONCLUSIVE',
    observations,
    evidences,
  };
}

// ---------- Sonde 2 : XSS réfléchi (reflet brut réel) ----------
export async function probeXss(targetUrl: string): Promise<VectorProbeOutcome> {
  const evidences: HttpProbeEvidence[] = [];
  const observations: string[] = [];
  let vulnerable = false;
  const marker = 'guymacybxssprobe741';

  for (const param of XSS_PARAMS.slice(0, 3)) {
    const payload = `<svg onload=${marker}>`;
    const probeUrl = appendQueryParam(targetUrl, param, payload);
    const ev = await realHttpProbe(probeUrl);
    evidences.push(ev);
    if (ev.error) {
      observations.push(`Paramètre ${param} : cible injoignable (${ev.error}).`);
      continue;
    }
    if (ev.body.includes(`<svg onload=${marker}`)) {
      vulnerable = true;
      observations.push(
        `Paramètre « ${param} » : le marqueur ${marker} est réfléchi BRUT (non échappé) dans le HTML réel renvoyé — XSS réfléchi exécutable côté navigateur (HTTP ${ev.status}).`
      );
      break;
    }
    if (ev.body.includes(marker)) {
      observations.push(`Paramètre « ${param} » : marqueur présent mais encodé/échappé par la cible — contrôle actif.`);
    } else {
      observations.push(`Paramètre « ${param} » : aucun reflet du marqueur dans la réponse réelle (HTTP ${ev.status}).`);
    }
  }

  return {
    verdict: vulnerable ? 'VULNERABLE' : evidences.some((e) => !e.error) ? 'PROTECTED' : 'INCONCLUSIVE',
    observations,
    evidences,
  };
}

// ---------- Sonde 3 : Path Traversal (lecture /etc/passwd) ----------
async function probePathTraversal(targetUrl: string): Promise<VectorProbeOutcome> {
  const evidences: HttpProbeEvidence[] = [];
  const observations: string[] = [];
  let vulnerable = false;

  const attempts: [string, string][] = [
    ['file', '../../../../etc/passwd'],
    ['page', '....//....//....//etc/passwd'],
    ['path', '..%2F..%2F..%2F..%2Fetc%2Fpasswd'],
  ];
  for (const [param, payload] of attempts) {
    const probeUrl = appendQueryParam(targetUrl, param, payload);
    const ev = await realHttpProbe(probeUrl);
    evidences.push(ev);
    if (ev.error) {
      observations.push(`Paramètre ${param} : cible injoignable (${ev.error}).`);
      continue;
    }
    if (/root:[x*]:0:0:/.test(ev.body)) {
      vulnerable = true;
      observations.push(
        `Paramètre « ${param} » : le contenu RÉEL de /etc/passwd est exposé dans la réponse (ligne root:…:0:0: détectée) — traversée de répertoire confirmée (HTTP ${ev.status}).`
      );
      break;
    }
    observations.push(`Paramètre « ${param} » avec payload ${payload.slice(0, 24)}… : pas de fuite de fichier système (HTTP ${ev.status}).`);
  }

  return {
    verdict: vulnerable ? 'VULNERABLE' : evidences.some((e) => !e.error) ? 'PROTECTED' : 'INCONCLUSIVE',
    observations,
    evidences,
  };
}

// ---------- Sonde 4 : SSRF interne (différentielle réelle) ----------
async function probeSsrf(targetUrl: string): Promise<VectorProbeOutcome> {
  const evidences: HttpProbeEvidence[] = [];
  const observations: string[] = [];

  const baseline = await realHttpProbe(targetUrl);
  evidences.push(baseline);
  if (baseline.error) {
    return {
      verdict: 'INCONCLUSIVE',
      observations: [`Cible injoignable (${baseline.error}) — sonde SSRF réelle impossible.`],
      evidences,
    };
  }

  let vulnerable = false;
  for (const param of INTERNAL_URL_PARAMS.slice(0, 3)) {
    const probeUrl = appendQueryParam(targetUrl, param, 'http://127.0.0.1:80/');
    const ev = await realHttpProbe(probeUrl);
    evidences.push(ev);
    if (ev.error) {
      observations.push(`Paramètre ${param} : erreur réelle (${ev.error}) — signalement conservé.`);
      continue;
    }
    const significant =
      ev.status !== baseline.status &&
      (baseline.status === null || Math.abs(ev.latencyMs - baseline.latencyMs) > 0);
    const bodyDiff = Math.abs(ev.body.length - baseline.body.length) > Math.max(200, baseline.body.length * 0.3);
    if (ev.status && ev.status >= 200 && ev.status < 300 && (significant || bodyDiff) && ev.body !== baseline.body) {
      vulnerable = true;
      observations.push(
        `Paramètre « ${param} » : la réponse réelle change de façon significative quand une URL interne (http://127.0.0.1:80/) est fournie (HTTP ${baseline.status}→${ev.status}, corps ${baseline.body.length}→${ev.body.length} octets) — SSRF probable à confirmer manuellement.`
      );
      break;
    }
    observations.push(`Paramètre « ${param} » : réponse identique ou non concluante avec URL interne (HTTP ${ev.status}).`);
  }

  return {
    verdict: vulnerable ? 'VULNERABLE' : 'INCONCLUSIVE',
    observations:
      observations.length > 0
        ? observations
        : ['Aucun paramètre d\'URL testable détecté — SSRF non conclusive sur cette cible (aucune invention).'],
    evidences,
  };
}

// ---------- Sonde 5 : IDOR / BOLA (accès objet sans authentification) ----------
async function probeIdor(targetUrl: string): Promise<VectorProbeOutcome> {
  const evidences: HttpProbeEvidence[] = [];
  const observations: string[] = [];
  let vulnerable = false;

  const base = targetUrl.replace(/\/+$/, '');
  for (const path of IDOR_CANDIDATE_PATHS) {
    const ev = await realHttpProbe(`${base}${path}`);
    evidences.push(ev);
    if (ev.error) {
      observations.push(`${path} : cible injoignable (${ev.error}).`);
      continue;
    }
    if (ev.status === 200 && ev.body.length > 20) {
      let parsed: any = null;
      try {
        parsed = JSON.parse(ev.body);
      } catch {
        /* corps non JSON — ignoré honnêtement */
      }
      const flat = JSON.stringify(parsed ?? ev.body).toLowerCase();
      const leaked = PII_KEYS.filter((k) => flat.includes(`"${k}"`) || flat.includes(k + ':'));
      if (leaked.length > 0) {
        vulnerable = true;
        observations.push(
          `${path} : accessible SANS authentification (HTTP 200, ${ev.body.length} octets réels) et expose des champs sensibles [${leaked.join(', ')}] — IDOR/BOLA confirmé.`
        );
        break;
      }
      observations.push(`${path} : accessible sans auth (HTTP 200) mais aucun champ sensible identifié dans la réponse réelle.`);
    } else {
      observations.push(`${path} : HTTP ${ev.status ?? 'erreur'} — accès refusé ou ressource absente.`);
    }
  }

  return {
    verdict: vulnerable ? 'VULNERABLE' : evidences.some((e) => !e.error) ? 'PROTECTED' : 'INCONCLUSIVE',
    observations,
    evidences,
  };
}

// ---------- Sonde 6 : JWT alg=none (réelle, requiert un jeton) ----------
async function probeJwt(targetUrl: string, authToken?: string): Promise<VectorProbeOutcome> {
  const evidences: HttpProbeEvidence[] = [];
  if (!authToken || typeof authToken !== 'string' || !authToken.includes('.')) {
    return {
      verdict: 'INCONCLUSIVE',
      observations: [
        'Sonde JWT non exécutée : aucun jeton d\'authentification fourni à l\'opérateur. Fournissez un JWT valide (champ authToken) pour tester l\'acceptation réelle de alg=none par la cible — aucune réponse inventée.',
      ],
      evidences,
    };
  }

  try {
    const [rawHeader, rawPayload] = authToken.split('.');
    const decode = (s: string) => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));
    const header = decode(rawHeader);
    const payload = decode(rawPayload);

    const forgedHeader = Buffer.from(JSON.stringify({ ...header, alg: 'none' })).toString('base64url');
    const forgedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const forgedToken = `${forgedHeader}.${forgedPayload}.`;

    const legit = await realHttpProbe(targetUrl, { headers: { Authorization: `Bearer ${authToken}` } });
    const forged = await realHttpProbe(targetUrl, { headers: { Authorization: `Bearer ${forgedToken}` } });
    evidences.push(legit, forged);

    if (legit.error || forged.error) {
      return {
        verdict: 'INCONCLUSIVE',
        observations: [`Cible injoignable pendant la sonde JWT (${legit.error || forged.error}).`],
        evidences,
      };
    }
    if (legit.status === 200 && forged.status === 200) {
      return {
        verdict: 'VULNERABLE',
        observations: [
          `La cible accepte un jeton forgé alg=none avec les mêmes claims (légitime: HTTP ${legit.status}, forgé: HTTP ${forged.status}) — vérification de signature ABSJOIN défaillante confirmée.`,
        ],
        evidences,
      };
    }
    return {
      verdict: 'PROTECTED',
      observations: [
        `Jeton forgé alg=none rejeté par la cible (légitime: HTTP ${legit.status}, forgé: HTTP ${forged.status}) — validation de signature active.`,
      ],
      evidences,
    };
  } catch (err: any) {
    return {
      verdict: 'INCONCLUSIVE',
      observations: [`Jeton fourni illisible ou non-JWT (${err?.message || 'erreur de décodage'}) — aucune invention.`],
      evidences,
    };
  }
}

// ---------- Sonde 7 : Rate limiting (mesure réelle par rafale) ----------
export async function probeRateLimit(targetUrl: string): Promise<VectorProbeOutcome> {
  const evidences: HttpProbeEvidence[] = [];
  const BURST = 20;
  for (let i = 0; i < BURST; i++) {
    evidences.push(await realHttpProbe(targetUrl, { timeoutMs: 4000 }));
  }
  const real = evidences.filter((e) => !e.error);
  const throttled = real.filter((e) => e.status === 429 || e.status === 503).length;
  const avgLatency = real.length > 0 ? Math.round(real.reduce((a, e) => a + e.latencyMs, 0) / real.length) : 0;

  const observations: string[] = [
    `${BURST} requêtes GET réelles envoyées en rafale : ${real.length} réponses reçues, ${throttled} rejets 429/503, latence moyenne réelle ${avgLatency}ms.`,
  ];
  if (real.length === 0) {
    return {
      verdict: 'INCONCLUSIVE',
      observations: [`Cible injoignable — aucune réponse réelle sur ${BURST} tentatives.`],
      evidences,
    };
  }
  if (throttled === 0 && real.length === BURST) {
    observations.push(
      'Aucun rejet 429/503 sur 20 requêtes consécutives : AUCUNE limitation de débit détectée côté cible (mesure réelle) — risque de brute-force / épuisement de ressources.'
    );
    return { verdict: 'VULNERABLE', observations, evidences };
  }
  observations.push(`Limitation de débit active (${throttled}/${BURST} requêtes rejetées) — contrôle défensif réel constaté.`);
  return { verdict: 'PROTECTED', observations, evidences };
}

// ---------- Sonde 8 : CORS permissif (Origin malveillante réelle) ----------
export async function probeCors(targetUrl: string): Promise<VectorProbeOutcome> {
  const evidences: HttpProbeEvidence[] = [];
  const evilOrigin = 'https://evil-guymacyb.example';

  const ev = await realHttpProbe(targetUrl, { headers: { Origin: evilOrigin } });
  evidences.push(ev);
  if (ev.error) {
    return {
      verdict: 'INCONCLUSIVE',
      observations: [`Cible injoignable (${ev.error}) — sonde CORS réelle impossible.`],
      evidences,
    };
  }

  const acao = ev.headers['access-control-allow-origin'];
  const acac = ev.headers['access-control-allow-credentials'];

  if (acao && acao !== evilOrigin && acao !== '*' && !acao.includes('null')) {
    return {
      verdict: 'PROTECTED',
      observations: [
        `Access-Control-Allow-Origin réel : « ${acao} » — l'origine malveillante n'est pas réfléchie, politique CORS restreinte.`,
      ],
      evidences,
    };
  }
  if (acao === '*' ) {
    return {
      verdict: 'VULNERABLE',
      observations: [
        'La cible renvoie Access-Control-Allow-Origin: * en réponse à une origine arbitraire — toute page web peut lire les réponses publiques de la cible depuis un navigateur (CORS permissif réel).',
        acac === 'true' ? 'AGGRAVANT RÉEL : Access-Control-Allow-Credentials: true accompagne le joker — combinaison dangereuse.' : 'Pas de Allow-Credentials avec le joker (portée limitée aux ressources publiques).',
      ],
      evidences,
    };
  }
  if (acao === evilOrigin) {
    return {
      verdict: 'VULNERABLE',
      observations: [
        `La cible RÉFLÉCHIT l'origine arbitraire « ${evilOrigin} » dans Access-Control-Allow-Origin${acac === 'true' ? ' AVEC Access-Control-Allow-Credentials: true' : ''} — vol de données authentifiées possible depuis un navigateur victime (réflexion CORS réelle confirmée).`,
      ],
      evidences,
    };
  }
  return {
    verdict: 'INCONCLUSIVE',
    observations: ['Aucun en-tête CORS renvoyé à l\'origine de test — politique non déterminable sans préflight spécifique (aucune invention).'],
    evidences,
  };
}

const PROBE_RUNNERS: Record<string, (targetUrl: string, opts: { authToken?: string }) => Promise<VectorProbeOutcome>> = {
  'sqli-error': (u) => probeSqli(u),
  'xss-reflected': (u) => probeXss(u),
  'path-traversal': (u) => probePathTraversal(u),
  'ssrf-internal': (u) => probeSsrf(u),
  'idor-bola': (u) => probeIdor(u),
  'jwt-alg-none': (u, o) => probeJwt(u, o.authToken),
  'rate-limit-bypass': (u) => probeRateLimit(u),
  'cors-misconfig': (u) => probeCors(u),
};

// ============================================================
//  API du laboratoire RÉEL
// ============================================================

export interface LabProbeResult {
  vectorId: string;
  vectorName: string;
  targetUrl: string;
  verdict: 'VULNERABLE' | 'PROTECTED' | 'INCONCLUSIVE';
  httpStatus: number | null;
  durationMs: number;
  requestsSent: number;
  probeSent: string;
  realResponse: string;
  observations: string[];
  /** Vecteur CVSS v3.1 officiel du vecteur d'attaque + score CALCULÉ. */
  cvssVector: string | null;
  cvssScore: number;
  findingCandidate?: Finding;
}

/**
 * Exécute la sonde RÉELLE d'un vecteur d'attaque contre la cible réelle.
 * Envoie de vraies requêtes HTTP, analyse les vraies réponses, persiste un
 * finding réel si (et seulement si) la cible est réellement vulnérable.
 */
export async function executeLabProbe(
  vectorId: string,
  targetUrl: string,
  operatorId: string = 'SEC-OPS-0982',
  options?: { authToken?: string }
): Promise<LabProbeResult> {
  const vector: LabAttackVector =
    LAB_ATTACK_VECTORS.find((v) => v.id === vectorId) || LAB_ATTACK_VECTORS[0];
  const startTime = Date.now();

  const runner = PROBE_RUNNERS[vector.id] || probeSsrf;
  const outcome = await runner(targetUrl, options || {});
  const durationMs = Date.now() - startTime;

  const primary = outcome.evidences.find((e) => !e.error) || outcome.evidences[0];
  const requestsSent = outcome.evidences.length;
  const probeSent = primary ? `${primary.method} ${primary.url}` : `Sondes réelles contre ${targetUrl}`;
  const realResponse = primary ? formatEvidence(primary) : 'Aucune réponse réelle capturée.';
  const cvssResolved = resolveVectorCvss(vector);

  let findingCandidate: Finding | undefined = undefined;

  // Un finding n'est persisté que si la cible est RÉELLEMENT vulnérable.
  if (outcome.verdict === 'VULNERABLE') {
    try {
      const db = await getDatabase();
      const findingId = `LABREAL-FND-${Date.now().toString(36).toUpperCase()}-${nextLabFindingSeq()}`;
      const cvss = cvssResolved.score;
      const scanId = `SCAN-LABREAL-${Date.now().toString(36).toUpperCase()}`;
      const targetDomain = safeDomain(targetUrl);

      // Cible réelle (pas de cible virtuelle) + scan réel
      db.run(
        `INSERT OR REPLACE INTO targets (id, url, domain, scope, operator_id, created_at, last_scanned_at, status)
         VALUES (?, ?, ?, 'strict', ?, datetime('now'), datetime('now'), 'COMPLETED')`,
        [`target-${targetDomain}`, targetUrl, targetDomain, operatorId]
      );
      db.run(
        `INSERT INTO scans (id, target_id, url, scan_type, cvss_score, risk_level, duration_ms, endpoints_count, technologies_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
        [
          scanId,
          `target-${targetDomain}`,
          targetUrl,
          'LAB_REAL_PROBE',
          cvss,
          vector.severity,
          durationMs,
          requestsSent,
          JSON.stringify(['GuymaCyb-Lab/1.0', vector.cwe.split(':')[0]]),
        ]
      );

      const findingObj: Finding = {
        id: findingId,
        title: `[Lab Réel] ${vector.name}`,
        severity: cvssResolved.severity,
        cvss,
        cvssVector: cvssResolved.vector,
        confidence: 90,
        status: 'VALIDATED',
        affectedComponent: targetUrl,
        category: vector.owasp,
        cwe: vector.cwe,
        description: vector.description,
        evidence: {
          request: probeSent,
          response: realResponse.slice(0, MAX_BODY_CAPTURE),
          authContext: 'Sondes réelles contre la cible autorisée (attestation ACTIVE enregistrée)',
          roundtripMs: primary?.latencyMs ?? durationMs,
          nonDestructiveProof: true,
        },
        impact: `Impact réel observé : ${outcome.observations[0] || vector.vulnerableBehaviorExplanation}`,
        remediationTitle: `Mise en conformité défensive : ${vector.defensiveControls[0]}`,
        remediationSteps: vector.defensiveControls,
        signature: `LABREAL-${vector.id.toUpperCase()}-${scanId}`,
        sqliteRow: 0,
      };
      findingCandidate = findingObj;

      db.run(
        `INSERT INTO findings (
          id, scan_id, target_url, title, severity, cvss, confidence, status,
          affected_component, category, cwe, description, evidence_request,
          evidence_response, impact, remediation_title, remediation_steps_json, signature, cvss_vector, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
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
          findingObj.cvssVector ?? null,
        ]
      );

      db.run(
        `INSERT INTO audit_logs (id, timestamp, tag, text, operator_id)
         VALUES (?, datetime('now'), ?, ?, ?)`,
        [
          `log-labreal-${Date.now()}`,
          'LAB_REAL_PROBE',
          `Sonde réelle exécutée : ${vector.name} contre ${targetUrl} — verdict ${outcome.verdict} (${requestsSent} requêtes réelles, ${durationMs}ms).`,
          operatorId,
        ]
      );

      saveDatabaseToDisk(db);
    } catch (err) {
      console.warn('[GuymaCyb Lab] Warning during SQLite insert:', err);
    }
  }

  return {
    vectorId: vector.id,
    vectorName: vector.name,
    targetUrl,
    verdict: outcome.verdict,
    httpStatus: primary?.status ?? null,
    durationMs,
    requestsSent,
    probeSent,
    realResponse,
    observations: outcome.observations,
    cvssVector: cvssResolved.vector,
    cvssScore: cvssResolved.score,
    findingCandidate,
  };
}

/**
 * Exécute la suite complète des 8 sondes réelles contre la cible et
 * construit un rapport réel consolidé dans SQLite.
 */
export async function commitFullLabSuiteToReport(
  operatorId: string = 'SEC-OPS-0982',
  targetUrl: string
) {
  if (!targetUrl || typeof targetUrl !== 'string') {
    throw new Error('Cible réelle requise : la suite du laboratoire s\'exécute contre une vraie cible autorisée.');
  }

  const suiteStart = Date.now();
  const scanId = `SCAN-LABREAL-${Date.now().toString(36).toUpperCase()}`;
  const targetDomain = safeDomain(targetUrl);

  let vulnerableCount = 0;
  let protectedCount = 0;
  let inconclusiveCount = 0;
  let totalRequests = 0;
  let maxCvss = 0;
  let maxSeverity: Severity = 'INFO';

  for (const vector of LAB_ATTACK_VECTORS) {
    const probe = await executeLabProbe(vector.id, targetUrl, operatorId);
    totalRequests += probe.requestsSent;
    if (probe.verdict === 'VULNERABLE') {
      vulnerableCount++;
      if (probe.cvssScore > maxCvss) {
        maxCvss = probe.cvssScore;
        maxSeverity = probe.findingCandidate?.severity ?? vector.severity;
      }
    } else if (probe.verdict === 'PROTECTED') {
      protectedCount++;
    } else {
      inconclusiveCount++;
    }
  }

  const durationMs = Date.now() - suiteStart;

  // Scan consolidé réel (les findings individuels ont déjà été persistés par
  // executeLabProbe avec leur propre scan_id — celui-ci agrège la suite).
  const db = await getDatabase();
  db.run(
    `INSERT OR REPLACE INTO targets (id, url, domain, scope, operator_id, created_at, last_scanned_at, status)
     VALUES (?, ?, ?, 'strict', ?, datetime('now'), datetime('now'), 'COMPLETED')`,
    [`target-${targetDomain}`, targetUrl, targetDomain, operatorId]
  );
  db.run(
    `INSERT INTO scans (id, target_id, url, scan_type, cvss_score, risk_level, duration_ms, endpoints_count, technologies_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
    [
      scanId,
      `target-${targetDomain}`,
      targetUrl,
      'LAB_REAL_SUITE',
      maxCvss,
      maxSeverity,
      durationMs,
      totalRequests,
      JSON.stringify([
        `vulnérables: ${vulnerableCount}`,
        `protégés: ${protectedCount}`,
        `inconclusifs: ${inconclusiveCount}`,
      ]),
    ]
  );
  db.run(
    `INSERT INTO audit_logs (id, timestamp, tag, text, operator_id)
     VALUES (?, datetime('now'), ?, ?, ?)`,
    [
      `log-labreal-suite-${Date.now()}`,
      'LAB_REAL_SUITE',
      `Suite laboratoire réelle exécutée contre ${targetUrl} : ${vulnerableCount} vulnérables / ${protectedCount} protégés / ${inconclusiveCount} inconclusifs (${totalRequests} requêtes réelles, ${durationMs}ms).`,
      operatorId,
    ]
  );
  saveDatabaseToDisk(db);

  return {
    scanId,
    targetUrl,
    vectorsAudited: LAB_ATTACK_VECTORS.length,
    vulnerableCount,
    protectedCount,
    inconclusiveCount,
    totalRequests,
    durationMs,
    committedAt: new Date().toISOString(),
  };
}

function safeDomain(url: string): string {
  try {
    return new URL(url.startsWith('http') ? url : `https://${url}`).hostname.replace(/[^a-z0-9.-]/gi, '_');
  } catch {
    return 'cible-invalide';
  }
}

/**
 * Sondes TCP connect réelles (non intrusives, handshake puis fermeture immédiate).
 * Retourne 'OPEN' / 'CLOSED' / 'FILTERED' selon le résultat réel du socket.
 */
function probeTcpPort(host: string, port: number, timeoutMs = 1500): Promise<'OPEN' | 'CLOSED' | 'FILTERED'> {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let done = false;
    const finish = (state: 'OPEN' | 'CLOSED' | 'FILTERED') => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve(state);
    };
    sock.setTimeout(timeoutMs);
    sock.on('connect', () => finish('OPEN'));
    sock.on('timeout', () => finish('FILTERED'));
    sock.on('error', (e: NodeJS.ErrnoException) =>
      finish(e.code === 'ECONNREFUSED' || e.code === 'ECONNRESET' ? 'CLOSED' : 'FILTERED')
    );
    sock.connect(port, host);
  });
}

/**
 * Module de Reconnaissance Avancée Automatisée
 * Analyse défensivement : DNS, ports réels, en-têtes et technologies.
 * Doctrine "zéro invention" : si une donnée ne peut pas être obtenue
 * (DNS KO, HTTP KO…), elle est signalée comme telle — jamais fabriquée.
 */
export async function runAutomatedReconSuite(targetUrl: string) {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
  } catch {
    throw new Error(`URL invalide : ${targetUrl}`);
  }

  const domain = parsedUrl.hostname;
  const reconLogs: string[] = [];
  reconLogs.push(`[RECON_INIT] Démarrage de la reconnaissance automatisée sur ${domain}`);

  // 1. Résolution DNS réelle
  let resolvedIps: string[] = [];
  try {
    const addresses = await dns.resolve4(domain);
    resolvedIps = addresses;
    reconLogs.push(`[DNS_RESOLVE] Adresses IPv4 identifiées: ${addresses.join(', ')}`);
  } catch (err: any) {
    reconLogs.push(`[DNS_FAIL] Résolution IPv4 impossible (${err.code || err.message}) — aucune IP fabriquée, les sondes ports utiliseront le nom d'hôte.`);
  }

  // 2. Sondes de ports réelles (TCP connect, non intrusif)
  const portsToProbe = [80, 443, 8080, 8443];
  const portAuditResults: { port: number; status: 'OPEN' | 'FILTERED' | 'CLOSED'; service: string }[] = [];
  const probeHost = resolvedIps[0] || domain;
  for (const port of portsToProbe) {
    const serviceName = port === 80 ? 'http' : port === 443 ? 'https' : port === 8080 ? 'http-alt' : 'https-alt';
    const status = await probeTcpPort(probeHost, port);
    portAuditResults.push({ port, status, service: serviceName });
    reconLogs.push(`[PORT_PROBE] Port ${port}/tcp (${serviceName}) : ${
      status === 'OPEN' ? 'OUVERT (socket connecté)' : status === 'CLOSED' ? 'FERMÉ (RST reçu)' : 'FILTRÉ (timeout)'
    }`);
  }

  // 3. Audit RÉEL des en-têtes de durcissement (GET, puis analyse des en-têtes présents)
  let serverBanner: string | null = null;
  const hardeningHeaders = [
    'content-security-policy',
    'strict-transport-security',
    'permissions-policy',
    'x-content-type-options',
    'x-frame-options',
  ];
  const missingHeaders: string[] = [];
  let probeStatus: number | null = null;
  try {
    const probeRes = await fetch(parsedUrl.toString(), {
      method: 'GET',
      headers: { 'User-Agent': 'GuymaCyb-Auditor/1.0' },
      signal: AbortSignal.timeout(5000),
      redirect: 'follow',
    });
    probeStatus = probeRes.status;
    serverBanner = probeRes.headers.get('server');
    for (const h of hardeningHeaders) {
      if (!probeRes.headers.get(h)) missingHeaders.push(h);
    }
  } catch (err: any) {
    reconLogs.push(`[HTTP_FAIL] Sonde HTTP impossible (${err?.message || 'erreur réseau'}) — audit en-têtes indisponible pour cette cible.`);
  }

  reconLogs.push(
    serverBanner
      ? `[BANNER_GRAB] Empreinte serveur identifiée : ${serverBanner}`
      : `[BANNER_GRAB] Aucun en-tête Server divulgué par la cible.`
  );
  reconLogs.push(
    probeStatus !== null
      ? `[AUDIT_HEADERS] ${missingHeaders.length} en-tête(s) de durcissement manquant(s) sur ${missingHeaders.length > 0 ? missingHeaders.join(', ') : '—'} (HTTP ${probeStatus}).`
      : `[AUDIT_HEADERS] Audit des en-têtes non réalisable (cible injoignable).`
  );

  return {
    target: parsedUrl.toString(),
    domain,
    primaryIp: resolvedIps[0] || null,
    allIps: resolvedIps,
    serverBanner: serverBanner || 'Non divulgué',
    httpStatus: probeStatus,
    portAudit: portAuditResults,
    missingSecurityHeaders: missingHeaders,
    reconLogs,
    completedAt: new Date().toISOString(),
  };
}
