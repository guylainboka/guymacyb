import { getDatabase, saveDatabaseToDisk } from './db';
import { realHttpProbe, probeSqli, probeXss, probeCors, probeRateLimit, executeLabProbe } from './securityLab';
import tls from 'tls';

// ============================================================
//  Re-test RÉEL d'un finding — Guyma Cyb
// ============================================================
//
// Ré-exécute la sonde d'origine contre la cible réelle et compare :
//   CONFIRMED   — la faille est toujours présente (réponse réelle identique
//                 au constat d'origine)
//   RESOLVED    — le contrôle défensif est maintenant actif
//   INCONCLUSIVE — cible injoignable, sonde non applicable, ou données
//                  insuffisantes (jamais de verdict inventé)

export interface RetestResult {
  findingId: string;
  targetUrl: string;
  retestAt: string;
  verdict: 'CONFIRMED' | 'RESOLVED' | 'INCONCLUSIVE';
  method: string;
  durationMs: number;
  requestsSent: number;
  details: string[];
  realEvidence: string | null;
}

interface FindingRow {
  id: string;
  scan_id: string;
  target_url: string;
  title: string;
  severity: string;
  signature: string;
  cwe: string;
  evidence_request: string;
}

function loadFinding(db: any, findingId: string): FindingRow | null {
  const stmt = db.prepare('SELECT id, scan_id, target_url, title, severity, signature, cwe, evidence_request FROM findings WHERE id = ?');
  try {
    stmt.bind([findingId]);
    if (stmt.step()) {
      return stmt.getAsObject() as FindingRow;
    }
    return null;
  } finally {
    stmt.free();
  }
}

const HEADER_PROBES: { match: RegExp; header: string; label: string }[] = [
  { match: /content.security.policy|csp/i, header: 'content-security-policy', label: 'Content-Security-Policy' },
  { match: /hsts|strict.transport/i, header: 'strict-transport-security', label: 'Strict-Transport-Security' },
  { match: /x.frame|clickjack/i, header: 'x-frame-options', label: 'X-Frame-Options' },
  { match: /x.content.type|nosniff/i, header: 'x-content-type-options', label: 'X-Content-Type-Options' },
  { match: /referrer/i, header: 'referrer-policy', label: 'Referrer-Policy' },
  { match: /permissions.policy/i, header: 'permissions-policy', label: 'Permissions-Policy' },
];

/**
 * Exécute le re-test réel d'un finding : identifie le type de sonde à partir
 * de la signature / du titre / du CWE, puis la ré-exécute réellement.
 */
export async function retestFinding(findingId: string, operatorId: string = 'SEC-OPS-0982'): Promise<RetestResult> {
  const started = Date.now();
  const db = await getDatabase();
  const finding = loadFinding(db, findingId);

  if (!finding) {
    throw new Error(`Finding introuvable en base : ${findingId}`);
  }

  const targetUrl = finding.target_url;
  const details: string[] = [];
  let verdict: RetestResult['verdict'] = 'INCONCLUSIVE';
  let method = 'Sonde réelle non déterminée';
  let requestsSent = 0;
  let realEvidence: string | null = null;

  // ---- 1. Findings du laboratoire réel : ré-exécution exacte de la sonde ----
  // Signature générée par executeLabProbe : LABREAL-<VECTOR_ID>-SCAN-LABREAL-<ts>
  // (le vector_id contient lui-même des tirets → on isole sur le séparateur -SCAN-LABREAL-)
  const labRealMatch = /^LABREAL-(.+?)-SCAN-LABREAL-/.exec(finding.signature || '');
  if (labRealMatch) {
    const vectorId = labRealMatch[1].toLowerCase();
    const vectorMap: Record<string, string> = {
      'sqli-error': 'sqli-error',
      'xss-reflected': 'xss-reflected',
      'path-traversal': 'path-traversal',
      'ssrf-internal': 'ssrf-internal',
      'idor-bola': 'idor-bola',
      'jwt-alg-none': 'jwt-alg-none',
      'rate-limit-bypass': 'rate-limit-bypass',
      'cors-misconfig': 'cors-misconfig',
    };
    const vid = vectorMap[vectorId];
    if (vid && targetUrl && !targetUrl.startsWith('wifi://')) {
      const probe = await executeLabProbe(vid, targetUrl, operatorId);
      requestsSent = probe.requestsSent;
      method = `Ré-exécution réelle de la sonde du lab (${probe.vectorName})`;
      realEvidence = probe.realResponse;
      details.push(...probe.observations);
      verdict = probe.verdict === 'VULNERABLE' ? 'CONFIRMED' : probe.verdict === 'PROTECTED' ? 'RESOLVED' : 'INCONCLUSIVE';
    } else {
      details.push('Finding du lab réel dont la cible d\'origine n\'est plus adressable en HTTP — re-test réseau impossible.');
    }
  }

  // ---- 2. Findings de tests actifs / scan : routage par signature et titre ----
  else {
    const sigTag = /^ACT-([A-Z0-9]+)-/.exec(finding.signature || '')?.[1] || '';
    const title = finding.title || '';

    // 2a. En-tête de durcissement manquant → re-vérification réelle de l'en-tête
    const headerProbe = HEADER_PROBES.find((h) => h.match.test(title));
    if (headerProbe) {
      const ev = await realHttpProbe(targetUrl);
      requestsSent = 1;
      method = `Re-sonde GET réelle + vérification de l'en-tête ${headerProbe.label}`;
      if (ev.error) {
        details.push(`Cible injoignable : ${ev.error}`);
      } else {
        realEvidence = `HTTP ${ev.status}\n${headerProbe.header}: ${ev.headers[headerProbe.header] ?? '(toujours absent)'}`;
        if (ev.headers[headerProbe.header]) {
          verdict = 'RESOLVED';
          details.push(`L'en-tête ${headerProbe.label} est maintenant PRÉSENT dans la réponse réelle (HTTP ${ev.status}) — contrôle déployé.`);
        } else {
          verdict = 'CONFIRMED';
          details.push(`L'en-tête ${headerProbe.label} est TOUJOURS absent de la réponse réelle (HTTP ${ev.status}) — faille confirmée.`);
        }
      }
    }

    // 2b. Bannière serveur / fuite d'information → re-GET réel
    else if (/banni[e]re|banner|server:|x-powered|divulgat|fuite/i.test(title)) {
      const ev = await realHttpProbe(targetUrl);
      requestsSent = 1;
      method = 'Re-sonde GET réelle + vérification des bannières';
      if (ev.error) {
        details.push(`Cible injoignable : ${ev.error}`);
      } else {
        const banner = ev.headers['server'] || ev.headers['x-powered-by'];
        realEvidence = `HTTP ${ev.status}\nserver: ${ev.headers['server'] ?? '(absent)'}\nx-powered-by: ${ev.headers['x-powered-by'] ?? '(absent)'}`;
        if (banner) {
          verdict = 'CONFIRMED';
          details.push(`La bannière « ${banner} » est toujours divulguée réellement (HTTP ${ev.status}).`);
        } else {
          verdict = 'RESOLVED';
          details.push('Aucune bannière serveur divulguée dans la réponse réelle — information masquée.');
        }
      }
    }

    // 2c. TRACE / méthodes HTTP → re-test réel
    else if (/trace|verbes? http|méthode/i.test(title)) {
      const trace = await realHttpProbe(targetUrl, { method: 'TRACE' });
      requestsSent = 1;
      method = 'Re-sonde TRACE réelle';
      if (trace.error) {
        details.push(`Cible injoignable : ${trace.error}`);
      } else {
        realEvidence = `HTTP ${trace.status}\n${trace.body.slice(0, 300)}`;
        if (trace.status === 200 && trace.body.includes('TRACE')) {
          verdict = 'CONFIRMED';
          details.push('TRACE est toujours activé et réfléchit la requête réellement.');
        } else {
          verdict = 'RESOLVED';
          details.push(`TRACE est maintenant rejeté (HTTP ${trace.status}).`);
        }
      }
    }

    // 2d. TLS / certificat → nouvelle poignée de main réelle
    else if (/tls|ssl|certificat/i.test(title)) {
      let host = targetUrl;
      try {
        host = new URL(targetUrl).hostname;
      } catch { /* cible brute */ }
      method = `Nouvelle poignée de main TLS réelle vers ${host}:443`;
      const info = await new Promise<{ ok: boolean; validTo?: Date; protocol?: string; error?: string }>((resolve) => {
        try {
          const sock = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false, timeout: 6000 }, () => {
            const cert = (sock as any).getPeerCertificate?.();
            resolve({ ok: true, validTo: cert?.valid_to ? new Date(cert.valid_to) : undefined, protocol: sock.getProtocol() || undefined });
            sock.destroy();
          });
          sock.on('error', (e) => resolve({ ok: false, error: e.message }));
          sock.on('timeout', () => { sock.destroy(); resolve({ ok: false, error: 'timeout TLS' }); });
        } catch (e: any) {
          resolve({ ok: false, error: e?.message });
        }
      });
      requestsSent = 1;
      if (!info.ok) {
        details.push(`Négociation TLS impossible : ${info.error}`);
      } else {
        const daysLeft = info.validTo ? Math.round((info.validTo.getTime() - Date.now()) / 86400000) : null;
        realEvidence = `protocol=${info.protocol}, valid_to=${info.validTo?.toISOString() ?? 'inconnu'} (${daysLeft} jours)`;
        if (/expir/i.test(title)) {
          verdict = daysLeft !== null && daysLeft >= 0 ? 'RESOLVED' : 'CONFIRMED';
          details.push(`Certificat réel : ${daysLeft !== null && daysLeft >= 0 ? `valide (${daysLeft} jours restants) — renouvelé` : `toujours expiré (${daysLeft} jours)`}.`);
        } else if (/obsol|tlsv1\.0|tlsv1\.1/i.test(title)) {
          verdict = info.protocol && info.protocol >= 'TLSv1.2' ? 'RESOLVED' : 'CONFIRMED';
          details.push(`Protocole réellement négocié : ${info.protocol}.`);
        } else {
          verdict = 'INCONCLUSIVE';
          details.push(`État TLS réel relevé (${info.protocol}) — comparez avec le constat d'origine.`);
        }
      }
    }

    // 2e. Ressource exposée (dirbrute) → re-GET réel du chemin
    else if (/expos|\/[a-z0-9._-]+$/i.test(title) && (finding.evidence_request || '').startsWith('GET ')) {
      const path = (finding.evidence_request || '').replace(/^GET\s+/, '').split(/\s/)[0];
      const ev = await realHttpProbe(path);
      requestsSent = 1;
      method = `Re-sonde GET réelle de la ressource exposée`;
      if (ev.error) {
        details.push(`Ressource injoignable : ${ev.error}`);
      } else {
        realEvidence = `HTTP ${ev.status ?? 'erreur'} (${ev.body.length} octets réels)`;
        if (ev.status !== null && ev.status >= 200 && ev.status < 300) {
          verdict = 'CONFIRMED';
          details.push(`La ressource ${path} est TOUJOURS accessible publiquement (HTTP ${ev.status}).`);
        } else {
          verdict = 'RESOLVED';
          details.push(`La ressource ${path} n'est plus accessible (HTTP ${ev.status}).`);
        }
      }
    }

    // 2f. Injections / CORS / rate limit (findings ACT) → sondes réelles dédiées
    else if (sigTag === 'INJECTION') {
      const [sqli, xss] = await Promise.all([probeSqli(targetUrl), probeXss(targetUrl)]);
      requestsSent = sqli.evidences.length + xss.evidences.length;
      method = 'Ré-exécution réelle des sondes SQLi + XSS';
      realEvidence = [sqli, xss].flatMap((o) => o.observations).join('\n');
      details.push(...sqli.observations, ...xss.observations);
      const anyVuln = [sqli, xss].some((o) => o.verdict === 'VULNERABLE');
      const anyProtected = [sqli, xss].every((o) => o.verdict === 'PROTECTED');
      verdict = anyVuln ? 'CONFIRMED' : anyProtected ? 'RESOLVED' : 'INCONCLUSIVE';
    } else if (sigTag === 'CORS') {
      const outcome = await probeCors(targetUrl);
      requestsSent = outcome.evidences.length;
      method = 'Ré-exécution réelle de la sonde CORS (origine arbitraire)';
      realEvidence = outcome.observations.join('\n');
      details.push(...outcome.observations);
      verdict = outcome.verdict === 'VULNERABLE' ? 'CONFIRMED' : outcome.verdict === 'PROTECTED' ? 'RESOLVED' : 'INCONCLUSIVE';
    } else if (sigTag === 'RATELIMIT') {
      const outcome = await probeRateLimit(targetUrl);
      requestsSent = outcome.evidences.length;
      method = 'Ré-exécution réelle de la mesure de débit (rafale 20)';
      realEvidence = outcome.observations.join('\n');
      details.push(...outcome.observations);
      verdict = outcome.verdict === 'VULNERABLE' ? 'CONFIRMED' : outcome.verdict === 'PROTECTED' ? 'RESOLVED' : 'INCONCLUSIVE';
    }

    // 2g. Findings du bac à sable historique (LAB-*) : honnêteté totale
    else if (/^LAB-|^WIFI-LAB-/.test(finding.signature || '')) {
      method = 'Constat du bac à sable historique (non re-testable)';
      details.push(
        'Ce finding provient de l\'ancien bac à sable (constat théorique, pas une sonde réseau réelle). Un re-test réel est sans objet : lancez la sonde réelle correspondante depuis le Laboratoire réel contre la cible autorisée.'
      );
      verdict = 'INCONCLUSIVE';
    }

    // 2h. Dernier recours : sonde de joignabilité réelle
    else {
      const ev = await realHttpProbe(targetUrl);
      requestsSent = 1;
      method = 'Sonde de joignabilité réelle (type de constat non routable)';
      if (ev.error) {
        details.push(`Cible injoignable : ${ev.error} — verdict réel impossible pour le moment.`);
      } else {
        details.push(
          `Cible joignable (HTTP ${ev.status}) mais le type de constat ne permet pas de ré-exécuter automatiquement la sonde d'origine. Vérification manuelle recommandée — aucun verdict fabriqué.`
        );
      }
      verdict = 'INCONCLUSIVE';
    }
  }

  const durationMs = Date.now() - started;

  // Journal d'audit du re-test (traçabilité légale complète)
  try {
    db.run(
      `INSERT INTO audit_logs (id, timestamp, tag, text, operator_id)
       VALUES (?, datetime('now'), 'RETEST', ?, ?)`,
      [
        `log-retest-${Date.now()}`,
        `Re-test réel du finding ${findingId} contre ${targetUrl} : ${verdict} (${method}, ${requestsSent} requête(s) réelle(s), ${durationMs}ms).`,
        operatorId,
      ]
    );
    saveDatabaseToDisk(db);
  } catch (err) {
    console.warn('[Retest] Échec de journalisation:', err);
  }

  return {
    findingId,
    targetUrl,
    retestAt: new Date().toISOString(),
    verdict,
    method,
    durationMs,
    requestsSent,
    details,
    realEvidence,
  };
}
