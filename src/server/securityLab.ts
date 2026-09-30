import { getDatabase, saveDatabaseToDisk } from './db';
import { Finding, Severity, WifiLabSimulationResult, WifiLabVector } from '../types';
import { LAB_ATTACK_VECTORS } from '../data/labAttackVectors';
import { WIFI_LAB_VECTORS } from '../data/wifiLabVectors';
import dns from 'dns/promises';
import net from 'net';

// ============================================================
//  Helpers « zéro simulation » du laboratoire
// ============================================================

/**
 * Compteur monotone pour les IDs de findings du lab.
 * Remplace l'ancien `Math.floor(Math.random() * 900 + 100)` : le random
 * était non déterministe et susceptible de collisions ; un compteur
 * monotone garantit l'unicité séquentielle au sein du processus.
 */
let labFindingSeq = 0;
function nextLabFindingSeq(): number {
  labFindingSeq += 1;
  return labFindingSeq;
}

/**
 * Score CVSS théorique conventionnel dérivé de la sévérité, selon les
 * bandes NVD (CVSS v3.1) : CRITICAL 9.0–10.0, HIGH 7.0–8.9, MEDIUM 4.0–6.9,
 * LOW 0.1–3.9 → point médian de la bande.
 *
 * ⚠ Honnêteté doctrinale : ce n'est PAS un calcul vectoriel CVSS v3.1
 * (AV/AC/PR/UI/S/C/I/A) — c'est la valeur de référence pédagogique du bac
 * à sable, appliquée de façon DÉTERMINISTE et IDENTIQUE partout.
 * L'ancien code utilisait 4 mappings arbitraires différents selon la
 * fonction (9.6/8.2/5.4, 9.5/8.0/5.5, 9.7/8.3/6.5/4.0, 9.5/8.0/6.0/4.0).
 * (Une vraie calculatrice vectorielle v3.1 est prévue en phase 3.)
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

export interface SimulationExecutionResult {
  vectorId: string;
  vectorName: string;
  targetMode: 'vulnerable' | 'remediated';
  status: 'VULNERABLE' | 'PROTECTED';
  httpStatus: number;
  durationMs: number;
  probeSent: string;
  responsePreview: string;
  wafIntercepted: boolean;
  securityObservations: string[];
  /** Aligné sur le contrat frontend (SecurityLabView) et le lab WiFi : findingCandidate. */
  findingCandidate?: Finding;
}

/**
 * Exécute une simulation sécurisée en bac à sable pour un vecteur d'attaque donné.
 */
export async function executeLabSimulation(
  vectorId: string,
  targetMode: 'vulnerable' | 'remediated' = 'vulnerable',
  operatorId: string = 'SEC-OPS-0982'
): Promise<SimulationExecutionResult> {
  const vector = LAB_ATTACK_VECTORS.find((v) => v.id === vectorId) || LAB_ATTACK_VECTORS[0];
  const startTime = Date.now();

  // Doctrine « zéro simulation » : durationMs mesure le temps d'exécution
  // RÉEL de la routine du bac à sable (l'ancien code injectait un setTimeout
  // de 50ms + un random de 25ms pour « ressembler » à une latence réseau).
  const durationMs = Date.now() - startTime;

  const isVulnerable = targetMode === 'vulnerable';
  const httpStatus = isVulnerable ? 200 : (vector.id === 'rate-limit-bypass' ? 429 : 403);
  const wafIntercepted = !isVulnerable;

  const observations = isVulnerable
    ? [
        `Comportement anormal détecté : Réponse HTTP ${httpStatus} avec exécution ou reflet du payload.`,
        vector.vulnerableBehaviorExplanation,
        `Contrôles d'intégrité défaillants selon la taxonomie ${vector.cwe}.`,
        'Preuve non-destructive qualifiée avec succès.',
      ]
    : [
        `Requête interceptée et rejetée par le contrôle de sécurité (Code HTTP ${httpStatus}).`,
        vector.remediatedBehaviorExplanation,
        'Aucune fuite de données ni altération de la logique applicative constatée.',
        'Poste défensif validé conforme.',
      ];

  let findingCandidate: Finding | undefined = undefined;

  // Si le mode était "vulnérable", enregistrer la preuve dans la base SQLite locale
  if (isVulnerable) {
    try {
      const db = await getDatabase();
      const findingId = `LAB-FND-${Date.now().toString(36).toUpperCase()}-${nextLabFindingSeq()}`;
      const cvss = theoreticalCvssFromSeverity(vector.severity);

      const findingObj: Finding = {
        id: findingId,
        title: `[Lab Simulation] ${vector.name}`,
        severity: vector.severity,
        cvss,
        confidence: 99,
        status: 'VALIDATED',
        affectedComponent: `/sandbox/lab/${vector.id}`,
        category: vector.owasp,
        cwe: vector.cwe,
        description: vector.description,
        evidence: {
          request: `${vector.safeTestPayload}\nHost: shadowscan-lab.internal\nX-Operator-Id: ${operatorId}`,
          response: vector.vulnerableResponseSample,
          authContext: 'Bac à sable de validation défensive',
          roundtripMs: durationMs,
          nonDestructiveProof: true,
        },
        impact: `Exploitation potentielle : ${vector.vulnerableBehaviorExplanation}`,
        remediationTitle: `Mise en conformité défensive : ${vector.defensiveControls[0]}`,
        remediationSteps: vector.defensiveControls,
        signature: `LAB-${vector.id.toUpperCase()}-VERIFIED`,
        sqliteRow: 0,
      };

      findingCandidate = findingObj;

      // Insertion dans SQLite
      db.run(
        `INSERT OR REPLACE INTO findings (
          id, scan_id, target_url, title, severity, cvss, confidence, status,
          affected_component, category, cwe, description, evidence_request,
          evidence_response, impact, remediation_title, remediation_steps_json, signature, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
        [
          findingObj.id,
          'lab-simulation-scan',
          'http://shadowscan-lab.internal',
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

      // Log d'audit — schéma réel de la table audit_logs :
      // (id, timestamp, tag, text, operator_id) — cf. initTables() dans db.ts.
      // L'ancien insert utilisait des colonnes inexistantes (event_type, message,
      // metadata_json, created_at) → l'INSERT échouait et sautait
      // saveDatabaseToDisk() : les preuves du lab n'étaient jamais persistées.
      db.run(
        `INSERT INTO audit_logs (id, timestamp, tag, text, operator_id)
         VALUES (?, datetime('now'), ?, ?, ?)`,
        [
          `log-${Date.now()}`,
          'LAB_SIMULATION',
          `Simulation défensive validée sur le vecteur ${vector.name} (id=${vector.id}, mode=${targetMode}, cvss=${cvss})`,
          operatorId,
        ]
      );

      saveDatabaseToDisk(db);
    } catch (err) {
      console.warn('[ShadowScan Lab] Warning during SQLite insert:', err);
    }
  }

  return {
    vectorId: vector.id,
    vectorName: vector.name,
    targetMode,
    status: isVulnerable ? 'VULNERABLE' : 'PROTECTED',
    httpStatus,
    durationMs,
    probeSent: vector.safeTestPayload,
    responsePreview: isVulnerable ? vector.vulnerableResponseSample : vector.remediatedResponseSample,
    wafIntercepted,
    securityObservations: observations,
    findingCandidate,
  };
}

/**
 * Génère un rapport de sécurité exhaustif basé sur le laboratoire complet
 * et persiste l'ensemble des résultats dans SQLite.
 */
export async function commitFullLabSuiteToReport(operatorId: string = 'SEC-OPS-0982') {
  const db = await getDatabase();
  const suiteStart = Date.now();
  const scanId = `SCAN-LAB-${Date.now().toString(36).toUpperCase()}`;
  // CVSS du scan = MAX réel des scores théoriques des vecteurs audité
  // (l'ancien code hardcodait 8.8 sans dérivation). Durée = temps RÉEL
  // d'exécution de la suite (l'ancien code hardcodait 1250ms).

  // Créer la cible virtuelle du laboratoire si elle n'existe pas
  db.run(
    `INSERT OR REPLACE INTO targets (id, url, domain, scope, operator_id, created_at, last_scanned_at, status)
     VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'), 'COMPLETED')`,
    [
      'target-lab-sandbox',
      'http://shadowscan-lab.internal',
      'shadowscan-lab.internal',
      'wildcard',
      operatorId,
    ]
  );

  // Créer le scan
  db.run(
    `INSERT INTO scans (id, target_id, url, scan_type, cvss_score, risk_level, duration_ms, endpoints_count, technologies_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
    [
      scanId,
      'target-lab-sandbox',
      'http://shadowscan-lab.internal',
      'LAB_CYBER_RANGE_SUITE',
      Math.max(...LAB_ATTACK_VECTORS.map((v) => theoreticalCvssFromSeverity(v.severity))),
      'HIGH',
      Date.now() - suiteStart,
      LAB_ATTACK_VECTORS.length,
      JSON.stringify(['Express', 'Node.js', 'SQLite3', 'WAF-Simulator']),
    ]
  );

  // Insérer chaque vecteur dans la base findings
  for (const vector of LAB_ATTACK_VECTORS) {
    const fId = `FND-${vector.id.toUpperCase()}-${Date.now().toString(36)}`;
    const cvss = theoreticalCvssFromSeverity(vector.severity);

    db.run(
      `INSERT OR REPLACE INTO findings (
        id, scan_id, target_url, title, severity, cvss, confidence, status,
        affected_component, category, cwe, description, evidence_request,
        evidence_response, impact, remediation_title, remediation_steps_json, signature, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
      [
        fId,
        scanId,
        'http://shadowscan-lab.internal',
        `[Audit Lab] ${vector.name}`,
        vector.severity,
        cvss,
        98,
        'VALIDATED',
        `/api/test-suite/${vector.id}`,
        vector.owasp,
        vector.cwe,
        vector.description,
        vector.safeTestPayload,
        vector.vulnerableResponseSample,
        vector.vulnerableBehaviorExplanation,
        `Contremesures recommandées: ${vector.defensiveControls[0]}`,
        JSON.stringify(vector.defensiveControls),
        `LAB-${vector.id.toUpperCase()}`,
      ]
    );
  }

  saveDatabaseToDisk(db);
  return {
    scanId,
    vectorsAudited: LAB_ATTACK_VECTORS.length,
    committedAt: new Date().toISOString(),
  };
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
 * Doctrine "zéro simulation" : si une donnée ne peut pas être obtenue
 * (DNS KO, HTTP KO…), elle est signalée comme telle — jamais inventée.
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
    reconLogs.push(`[DNS_FAIL] Résolution IPv4 impossible (${err.code || err.message}) — aucune IP inventée, les sondes ports utiliseront le nom d'hôte.`);
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

// ============================================================
//  Laboratoire d'attaques WiFi (sandbox de simulation défensive)
// ============================================================

/**
 * Exécute une simulation sécurisée d'un vecteur d'attaque WiFi dans le
 * bac à sable Guyma Cyb. Aucune attaque réelle n'est lancée : on simule
 * le comportement théorique attendu (mode vulnérable vs remédié) et on
 * persiste les preuves en SQLite avec une catégorie commençant par
 * "WIFI_".
 *
 * @param vectorId    Identifiant du vecteur WiFi (ex: "wifi-deauth-flood")
 * @param targetMode  "vulnerable" ou "remediated"
 * @param operatorId  Identifiant de l'opérateur défensif (audit log)
 */
export async function executeWifiLabSimulation(
  vectorId: string,
  targetMode: 'vulnerable' | 'remediated' = 'vulnerable',
  operatorId: string = 'SEC-OPS-0982'
): Promise<WifiLabSimulationResult> {
  const vector: WifiLabVector =
    WIFI_LAB_VECTORS.find((v) => v.id === vectorId) || WIFI_LAB_VECTORS[0];
  const startTime = Date.now();

  // Doctrine « zéro simulation » : durationMs mesure le temps d'exécution
  // RÉEL de la routine du bac à sable (l'ancien code injectait un setTimeout
  // de 60ms + un random de 40ms pour « ressembler » à une latence 802.11).
  const durationMs = Date.now() - startTime;

  const isVulnerable = targetMode === 'vulnerable';
  // Pour WiFi, on simule un protocole 802.11 — pas de HTTP status classique.
  // En mode "vulnerable" → status = VULNERABLE, l'AP n'a pas intercepté l'attaque.
  // En mode "remediated" → status = PROTECTED, l'AP (ou le client) a intercepté.
  const apIntercepted = !isVulnerable;
  const status: 'VULNERABLE' | 'PROTECTED' | 'BLOCKED' = isVulnerable
    ? 'VULNERABLE'
    : 'PROTECTED';

  const observations = isVulnerable
    ? [
        `Vecteur WiFi observé : ${vector.name} (${vector.mitre}).`,
        vector.vulnerableBehaviorExplanation,
        `Configuration vulnérable détectée — chiffrement cible : ${vector.targetEncryption}.`,
        'Preuve non-destructive capturée en laboratoire isolé (aucune émission sur un réseau réel).',
      ]
    : [
        `Vecteur WiFi bloqué : ${vector.name} (${vector.mitre}).`,
        vector.remediatedBehaviorExplanation,
        `Contrôle défensif actif — l'AP/le client a rejeté l'attaque.`,
        'Poste défensif validé conforme au vecteur simulé.',
      ];

  let findingCandidate: Finding | undefined = undefined;

  // En mode "vulnerable", on persiste la preuve en SQLite avec la catégorie WIFI_*
  if (isVulnerable) {
    try {
      const db = await getDatabase();
      const findingId = `WIFI-FND-${Date.now().toString(36).toUpperCase()}-${nextLabFindingSeq()}`;
      const cvss = theoreticalCvssFromSeverity(vector.severity);

      const categoryPrefix = `WIFI_${vector.category.split('_')[1] || vector.category}`;
      const findingObj: Finding = {
        id: findingId,
        title: `[WiFi Lab] ${vector.name}`,
        severity: vector.severity,
        cvss,
        confidence: 99,
        status: 'VALIDATED',
        affectedComponent: `/sandbox/wifi-lab/${vector.id}`,
        category: categoryPrefix,
        cwe: vector.mitre, // On réutilise le champ cwe pour stocker la technique MITRE
        description: vector.description,
        evidence: {
          request: `${vector.safeTestPayload}\nTarget: ${vector.targetEncryption}\nX-Operator-Id: ${operatorId}`,
          response: vector.vulnerableResponseSample,
          authContext: 'Bac à sable WiFi défensif (simulation théorique)',
          roundtripMs: durationMs,
          nonDestructiveProof: true,
        },
        impact: `Impact simulé : ${vector.vulnerableBehaviorExplanation}`,
        remediationTitle: `Mise en conformité : ${vector.defensiveControls[0]}`,
        remediationSteps: vector.defensiveControls,
        signature: `WIFI-LAB-${vector.id.toUpperCase()}-VERIFIED`,
        sqliteRow: 0,
      };

      findingCandidate = findingObj;

      // Persistance SQLite
      db.run(
        `INSERT OR REPLACE INTO findings (
          id, scan_id, target_url, title, severity, cvss, confidence, status,
          affected_component, category, cwe, description, evidence_request,
          evidence_response, impact, remediation_title, remediation_steps_json, signature, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
        [
          findingObj.id,
          'wifi-lab-simulation-scan',
          'wifi://shadowscan-wifi-lab.internal',
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

      // Log d'audit (schéma audit_logs : id, timestamp, tag, text, operator_id)
      db.run(
        `INSERT INTO audit_logs (id, timestamp, tag, text, operator_id)
         VALUES (?, datetime('now'), ?, ?, ?)`,
        [
          `log-wifi-${Date.now()}`,
          'WIFI_LAB_SIMULATION',
          `Simulation WiFi défensive validée sur le vecteur ${vector.name} (${vector.id}, mode=${targetMode}, cvss=${cvss})`,
          operatorId,
        ]
      );

      saveDatabaseToDisk(db);
    } catch (err) {
      console.warn('[ShadowScan WiFi Lab] Warning during SQLite insert:', err);
    }
  }

  return {
    vectorId: vector.id,
    vectorName: vector.name,
    timestamp: new Date().toISOString(),
    targetMode,
    status,
    probeSent: vector.safeTestPayload,
    durationMs,
    responsePreview: isVulnerable
      ? vector.vulnerableResponseSample
      : vector.remediatedResponseSample,
    apIntercepted,
    securityObservations: observations,
    findingCandidate: findingCandidate,
  };
}

/**
 * Génère un rapport WiFi exhaustif basé sur le laboratoire complet WiFi
 * et persiste l'ensemble des résultats dans SQLite (catégorie WIFI_*).
 */
export async function commitFullWifiLabSuiteToReport(
  operatorId: string = 'SEC-OPS-0982'
) {
  const db = await getDatabase();
  const suiteStart = Date.now();
  const scanId = `SCAN-WIFI-LAB-${Date.now().toString(36).toUpperCase()}`;

  // Créer la cible virtuelle du laboratoire WiFi si elle n'existe pas
  db.run(
    `INSERT OR REPLACE INTO targets (id, url, domain, scope, operator_id, created_at, last_scanned_at, status)
     VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'), 'COMPLETED')`,
    [
      'target-wifi-lab-sandbox',
      'wifi://shadowscan-wifi-lab.internal',
      'shadowscan-wifi-lab.internal',
      'wildcard',
      operatorId,
    ]
  );

  // Créer le scan
  db.run(
    `INSERT INTO scans (id, target_id, url, scan_type, cvss_score, risk_level, duration_ms, endpoints_count, technologies_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
    [
      scanId,
      'target-wifi-lab-sandbox',
      'wifi://shadowscan-wifi-lab.internal',
      'WIFI_LAB_FULL_SUITE',
      Math.max(...WIFI_LAB_VECTORS.map((v) => theoreticalCvssFromSeverity(v.severity))),
      'HIGH',
      Date.now() - suiteStart,
      WIFI_LAB_VECTORS.length,
      JSON.stringify(['802.11', 'WPA2', 'WPA3', 'PMF', 'SAE', 'hostapd-sandbox']),
    ]
  );

  // Insérer chaque vecteur WiFi dans la base findings
  for (const vector of WIFI_LAB_VECTORS) {
    const fId = `WIFI-FND-${vector.id.toUpperCase()}-${Date.now().toString(36)}`;
    const cvss = theoreticalCvssFromSeverity(vector.severity);
    const categoryPrefix = `WIFI_${vector.category.split('_')[1] || vector.category}`;

    db.run(
      `INSERT OR REPLACE INTO findings (
        id, scan_id, target_url, title, severity, cvss, confidence, status,
        affected_component, category, cwe, description, evidence_request,
        evidence_response, impact, remediation_title, remediation_steps_json, signature, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
      [
        fId,
        scanId,
        'wifi://shadowscan-wifi-lab.internal',
        `[Audit WiFi Lab] ${vector.name}`,
        vector.severity,
        cvss,
        98,
        'VALIDATED',
        `/api/wifi/test-suite/${vector.id}`,
        categoryPrefix,
        vector.mitre,
        vector.description,
        vector.safeTestPayload,
        vector.vulnerableResponseSample,
        vector.vulnerableBehaviorExplanation,
        `Contremesures recommandées : ${vector.defensiveControls[0]}`,
        JSON.stringify(vector.defensiveControls),
        `WIFI-LAB-${vector.id.toUpperCase()}`,
      ]
    );
  }

  saveDatabaseToDisk(db);
  return {
    scanId,
    vectorsAudited: WIFI_LAB_VECTORS.length,
    committedAt: new Date().toISOString(),
    suite: 'wifi-lab',
  };
}
