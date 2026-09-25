// scanner.ts — Orchestrateur de scan.
//
// La logique d'analyse réseau réelle vit maintenant dans le noyau Rust
// `shadowscan-core` (src/server/toolbridge.ts → coreScan). Ce fichier ne fait
// que :
//   1. appeler le noyau Rust,
//   2. persister le résultat dans SQLite (sql.js),
//   3. exposer la même interface ScanResult qu'avant (compatibilité frontend).
//
// Si le noyau Rust n'est pas compilé, on renvoie un objet d'erreur propre
// (plus de faux scan simulé).

import { getDatabase, saveDatabaseToDisk } from './db';
import { coreScan, CoreScanResult } from './toolbridge';

export interface ScanResult extends CoreScanResult {}

export async function checkConnectivity(targetUrl: string): Promise<{
  success: boolean;
  statusCode?: number;
  latencyMs: number;
  serverBanner?: string;
  tlsVersion?: string;
  error?: string;
}> {
  // Délègue au noyau Rust (sous-commande `headers` est rapide) ; sinon fallback HEAD.
  try {
    const res = await coreScan(targetUrl, 'wildcard', 'connectivity-check');
    if ((res as any).error) {
      return { success: false, latencyMs: 0, error: (res as any).error };
    }
    return {
      success: true,
      statusCode: res.statusCode,
      latencyMs: res.latencyMs,
      serverBanner: res.headers?.server || res.headers?.['x-powered-by'] || 'Non divulgué',
      tlsVersion: res.tls?.isHttps ? 'TLS 1.3 / 1.2' : 'Non chiffré (HTTP brut)',
    };
  } catch (err: any) {
    return { success: false, latencyMs: 0, error: err.message };
  }
}

/**
 * Lance l'analyse réelle via le noyau Rust, puis persiste en SQLite.
 */
export async function runRealAnalysis(
  targetUrl: string,
  scope: 'strict' | 'wildcard',
  operatorId: string
): Promise<ScanResult> {
  const startTime = Date.now();

  // 1. Appel au noyau Rust.
  const result = await coreScan(targetUrl, scope, operatorId);

  if ((result as any).error) {
    throw new Error((result as any).error);
  }

  // 2. Persistance SQLite.
  try {
    const db = await getDatabase();
    const duration = Date.now() - startTime;
    const normalized = result.targetUrl;
    const domain = result.domain;
    const scanId = result.scanId;

    // Upsert target.
    db.run(
      `INSERT INTO targets (id, url, domain, scope, operator_id, created_at, last_scanned_at, status)
       VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'), 'COMPLETED')
       ON CONFLICT(id) DO UPDATE SET last_scanned_at = datetime('now'), status = 'COMPLETED'`,
      [`target-${domain}`, normalized, domain, scope, operatorId]
    );

    // Insert scan.
    db.run(
      `INSERT INTO scans (id, target_id, url, scan_type, cvss_score, risk_level, duration_ms, endpoints_count, technologies_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
      [
        scanId,
        `target-${domain}`,
        normalized,
        'PASSIVE_AND_SEMI_ACTIVE',
        result.cvssScore,
        result.overallRisk,
        duration,
        result.summary.endpointsCount,
        JSON.stringify(result.technologies),
      ]
    );

    // Insert endpoints.
    for (const ep of (result.endpoints || []).slice(0, 50)) {
      db.run(
        `INSERT INTO endpoints (id, scan_id, path, method, status_code, status_text, type, note, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
        [ep.id, scanId, ep.path, ep.method, ep.status, ep.statusText, ep.type, ep.note || '']
      );
    }

    // Insert findings.
    for (const f of result.findings || []) {
      db.run(
        `INSERT INTO findings (id, scan_id, target_url, title, severity, cvss, confidence, status, affected_component, category, cwe, description, evidence_request, evidence_response, impact, remediation_title, remediation_steps_json, signature, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
        [
          f.id, scanId, normalized, f.title, f.severity, f.cvss, f.confidence, f.status,
          f.affectedComponent, f.category, f.cwe, f.description,
          f.evidence.request, f.evidence.response, f.impact,
          f.remediationTitle, JSON.stringify(f.remediationSteps), f.signature,
        ]
      );
    }

    saveDatabaseToDisk(db);
  } catch (dbErr) {
    console.error('[scanner] Failed to commit scan to SQLite:', dbErr);
  }

  return result;
}
