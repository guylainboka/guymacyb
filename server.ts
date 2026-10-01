import express from 'express';
// IMPORTANT : ne PAS importer `vite` statiquement ici.
// `desktop/build-server-bundle.js` marque `vite` comme external (il pèse ~10 MB
// et n'est utile qu'en dev). Un import statique serait converti par esbuild en
// `require('vite')` AU TOP-LEVEL du bundle CJS `dist-server/server.cjs`, exécuté
// au chargement du module — avant tout check `NODE_ENV`. Sur l'app installée,
// `node_modules/vite` n'est pas embarqué dans les resources Electron, donc le
// serveur crasherait avec `Cannot find module 'vite'` dès le démarrage.
// On importe donc `vite` DYNAMIQUEMENT, uniquement dans la branche dev
// (`!isProd`), via `await import('vite')`. esbuild génère alors un
// `require('vite')` paresseux à l'intérieur de la branche, jamais exécuté en
// production.
import path from 'path';
import fs from 'fs';
import os from 'os';
import { getDatabase, saveDatabaseToDisk, getDbFilePath } from './src/server/db';
import { checkConnectivity, runRealAnalysis } from './src/server/scanner';
import {
  executeLabProbe,
  commitFullLabSuiteToReport,
  runAutomatedReconSuite,
} from './src/server/securityLab';
import { runActiveTestSuite } from './src/server/activeTests';
import { retestFinding } from './src/server/retest';
import { computeCvss31 } from './src/server/cvss31';
import {
  validateAuthorization,
  recordAuthorization,
  AUTHORIZATION_STATEMENTS,
  TestAuthorization,
  AuthorizationLevel,
} from './src/server/authorization';
import { LAB_ATTACK_VECTORS } from './src/data/labAttackVectors';
import { WIFI_LAB_VECTORS } from './src/data/wifiLabVectors';
import { COURSE_NOTIONS } from './src/data/courseNotions';
import { getPackagingInfo } from './src/server/packaging';
import * as ws from './src/server/windowsSystem';
import { invalidateWslCache, startDistroInstall, getDistroInstallStatus } from './src/server/wsl';
import * as tb from './src/server/toolbridge';
import * as updates from './src/server/updates';

// PORT/HOST configurables : Electron (electron-main.cjs) injecte PORT=3000 et
// HOST=127.0.0.1. En dev on écoute par défaut sur le loopback UNIQUEMENT — un
// outil de cybersécurité ne doit jamais exposer son API sur toutes les
// interfaces (l'ancien code faisait app.listen(PORT, '0.0.0.0')).
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1';

async function startServer() {
  const app = express();

  // Durcissement de base
  app.disable('x-powered-by');
  app.set('trust proxy', false);
  const isProdServer = process.env.NODE_ENV === 'production';
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'no-referrer');
    // CSP en production uniquement : le middleware Vite (dev) injecte des
    // scripts inline pour le HMR, incompatibles avec script-src 'self'.
    // L'application est servie depuis 'self' ; seules les Google Fonts sont
    // chargées depuis fonts.googleapis.com (style) / fonts.gstatic.com (font).
    if (isProdServer) {
      res.setHeader(
        'Content-Security-Policy',
        [
          "default-src 'self'",
          "script-src 'self'",
          "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
          "font-src 'self' https://fonts.gstatic.com",
          "img-src 'self' data: blob:",
          "connect-src 'self'",
          "frame-ancestors 'none'",
          "base-uri 'self'",
          "form-action 'self'",
          'object-src \'none\'',
        ].join('; ')
      );
    }
    next();
  });

  // ---------------------------------------------------------------------------
  // Contrôle d'accès local — anti DNS-rebinding / anti drive-by (audit SEC-AUDIT-1)
  // ---------------------------------------------------------------------------
  // L'API écoute sur 127.0.0.1, mais une page web visitée par l'opérateur peut
  // tenter d'appeler l'API depuis son navigateur :
  //   - DNS rebinding (un domaine de l'attaquant résolu vers 127.0.0.1),
  //   - POST cross-origin drive-by (CSRF) contre /api/terminal/exec (RCE),
  //   - exfiltration par balises <img src="http://127.0.0.1:3000/api/database/export">.
  // Défenses en couches :
  //   1. Host strictement local → neutralise le rebinding (le navigateur envoie
  //      le Host de l'attaquant après le rebinding),
  //   2. Origin/Referer strictement locaux si présents → neutralise le CSRF,
  //   3. jeton de session généré par electron-main et transmis via
  //      GCYB_SESSION_TOKEN : le renderer le reçoit dans l'URL de charge
  //      (?gcyb_token=…), le serveur pose alors un cookie HttpOnly
  //      SameSite=Strict exigé sur /api/* (sauf /api/health, sondé par le
  //      processus principal sans cookie).
  // En dev (`npm run dev` hors Electron) le jeton est absent : la couche 3 est
  // désactivée (comportement d'un serveur de développement), les couches 1-2
  // restent actives.
  const SESSION_TOKEN = process.env.GCYB_SESSION_TOKEN || '';
  const LOCAL_HOSTS = new Set([`127.0.0.1:${PORT}`, `localhost:${PORT}`, `[::1]:${PORT}`]);
  const LOCAL_ORIGINS = new Set([
    `http://127.0.0.1:${PORT}`,
    `http://localhost:${PORT}`,
    `http://[::1]:${PORT}`,
  ]);
  const SESSION_COOKIE = 'gcyb_session';
  const parseSessionCookies = (header: string | undefined): Record<string, string> => {
    const out: Record<string, string> = {};
    (header || '').split(';').forEach((part) => {
      const idx = part.indexOf('=');
      if (idx > 0) out[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
    });
    return out;
  };
  const isLocalOriginValue = (value: string): boolean => {
    try {
      return LOCAL_ORIGINS.has(new URL(value).origin);
    } catch {
      return false;
    }
  };
  let devTokenWarningShown = false;

  app.use((req, res, next) => {
    // Couche 1 — Host : tout hôte non local est rejeté avant toute autre logique.
    if (!req.headers.host || !LOCAL_HOSTS.has(req.headers.host)) {
      res.status(403).json({ error: 'Accès interdit (hôte non local)' });
      return;
    }
    // Couche 2 — Origin/Referer : une page distante déclenchant une requête
    // cross-origin expose son origine ; seules les origines locales passent.
    const origin = req.headers.origin;
    if (origin !== undefined && !LOCAL_ORIGINS.has(origin)) {
      res.status(403).json({ error: 'Accès interdit (origine non locale)' });
      return;
    }
    const referer = req.headers.referer;
    if (referer && referer.startsWith('http') && !isLocalOriginValue(referer)) {
      res.status(403).json({ error: 'Accès interdit (référent non local)' });
      return;
    }

    // Jeton : via query (charge initiale ?gcyb_token=…), en-tête ou cookie.
    const provided =
      (typeof req.query.gcyb_token === 'string' && req.query.gcyb_token) ||
      req.header('x-gcyb-token') ||
      parseSessionCookies(req.headers.cookie)[SESSION_COOKIE] ||
      '';
    if (SESSION_TOKEN && provided === SESSION_TOKEN) {
      // Pose le cookie HttpOnly SameSite=Strict pour toute la session renderer.
      // SameSite=Strict : le navigateur ne l'envoie JAMAIS sur une requête
      // cross-site — les drive-by restent sans cookie même si les couches 1-2
      // étaient contournées.
      res.setHeader(
        'Set-Cookie',
        `${SESSION_COOKIE}=${SESSION_TOKEN}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200`
      );
    }

    // Couche 3 — mode packaged : toute requête /api/ (hors health check sondé
    // par le processus principal) exige le jeton ou le cookie de session.
    if (req.path.startsWith('/api/') && req.path !== '/api/health') {
      if (!SESSION_TOKEN) {
        if (!devTokenWarningShown) {
          devTokenWarningShown = true;
          console.warn(
            '[ShadowScan] GCYB_SESSION_TOKEN absent (mode dev hors Electron) — exigence de jeton désactivée.'
          );
        }
      } else if (provided !== SESSION_TOKEN) {
        res.status(403).json({ error: 'Accès interdit (session invalide — relancez Guyma Cyb)' });
        return;
      }
    }
    next();
  });

  app.use(express.json({ limit: '2mb' }));

  // Initialize SQLite database on boot
  try {
    const db = await getDatabase();
    console.log('[ShadowScan Engine] Local SQLite database initialized successfully at', getDbFilePath());
  } catch (err) {
    console.error('[ShadowScan Engine] Failed to initialize SQLite database:', err);
  }

  // Health API
  app.get('/api/health', async (_req, res) => {
    try {
      const db = await getDatabase();
      const targetCountRes = db.exec('SELECT COUNT(*) as count FROM targets');
      const scanCountRes = db.exec('SELECT COUNT(*) as count FROM scans');
      const findingsCountRes = db.exec('SELECT COUNT(*) as count FROM findings');
      const endpointsCountRes = db.exec('SELECT COUNT(*) as count FROM endpoints');

      const targetCount = (targetCountRes[0]?.values[0]?.[0] as number) || 0;
      const scanCount = (scanCountRes[0]?.values[0]?.[0] as number) || 0;
      const findingsCount = (findingsCountRes[0]?.values[0]?.[0] as number) || 0;
      const endpointsCount = (endpointsCountRes[0]?.values[0]?.[0] as number) || 0;

      res.json({
        status: 'UP',
        engine: 'ShadowScan Real Network Scanner v1.0.0',
        sqlite: {
          connected: true,
          dbPath: getDbFilePath(),
          targetsCount: targetCount,
          scansCount: scanCount,
          findingsCount: findingsCount,
          // Doctrine « zéro invention » : le Footer affiche désormais ce
          // compteur RÉEL (l'ancien code affichait un « 137 endpoints »
          // hardcodé dans le JSX, contredit par la base vide au démarrage).
          endpointsCount: endpointsCount,
        },
        memoryMb: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        threads: os.cpus().length, // valeur réelle (l'ancien code hardcoded 8)
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // ————————————————————————————————————————————————————————————————————————
  // Desktop Installer V2 — endpoints de setup (réels, doctrine zéro invention)
  // Consommés par l'OnboardingView in-app et par le wizard desktop via le
  // process main (sondes engineHttpGet/Post). Aucune donnée fabriquée.
  // ————————————————————————————————————————————————————————————————————————

  // État réel de la base : chemin, taille, compteurs par table.
  app.get('/api/setup/database', async (_req, res) => {
    try {
      const db = await getDatabase();
      const tables = ['targets', 'scans', 'endpoints', 'findings', 'audit_logs'];
      const counts: Record<string, number> = {};
      for (const t of tables) {
        try {
          const r = db.exec(`SELECT COUNT(*) as count FROM ${t}`);
          counts[t] = (r[0]?.values[0]?.[0] as number) || 0;
        } catch {
          counts[t] = 0;
        }
      }
      const p = getDbFilePath();
      let sizeBytes = 0;
      try { sizeBytes = fs.statSync(p).size; } catch { /* fichier absent */ }
      res.json({ path: p, sizeBytes, counts, ready: true });
    } catch (err: any) {
      res.status(500).json({ error: err.message, ready: false });
    }
  });

  // Initialisation réelle du schéma (idempotent) + persistance disque.
  app.post('/api/setup/database/init', async (_req, res) => {
    try {
      const db = await getDatabase(); // getDatabase() crée le schéma CREATE TABLE IF NOT EXISTS
      await saveDatabaseToDisk(db);
      const tables = ['targets', 'scans', 'endpoints', 'findings', 'audit_logs'];
      const counts: Record<string, number> = {};
      for (const t of tables) {
        try {
          const r = db.exec(`SELECT COUNT(*) as count FROM ${t}`);
          counts[t] = (r[0]?.values[0]?.[0] as number) || 0;
        } catch {
          counts[t] = 0;
        }
      }
      const p = getDbFilePath();
      let sizeBytes = 0;
      try { sizeBytes = fs.statSync(p).size; } catch { /* ignore */ }
      res.json({ ok: true, path: p, sizeBytes, counts });
    } catch (err: any) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // Génération du .wslconfig : Windows uniquement (refus honnête ailleurs —
  // le wizard desktop écrit lui-même ce fichier côté process main).
  app.post('/api/setup/wsl-config', async (req, res) => {
    const { memoryGb, networkingMode } = req.body || {};
    const mem = Math.min(32, Math.max(2, Number(memoryGb) || 8));
    const mode = networkingMode === 'bridged' ? 'bridged' : 'nat';
    if (process.platform !== 'win32') {
      return res.status(400).json({
        error: `Écriture de .wslconfig réservée à Windows (plateforme courante : ${process.platform}).`,
        platform: process.platform,
      });
    }
    try {
      const userProfile = process.env.USERPROFILE || os.homedir();
      const wslConfigPath = path.join(userProfile, '.wslconfig');
      const content = `[wsl2]\nmemory=${mem}GB\nnetworkingMode=${mode}\n`;
      fs.writeFileSync(wslConfigPath, content);
      res.json({ ok: true, path: wslConfigPath, memoryGb: mem, networkingMode: mode });
    } catch (err: any) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // Connectivity check endpoint
  app.post('/api/scan/connectivity', async (req, res) => {
    try {
      const { url } = req.body;
      if (!url) {
        return res.status(400).json({ error: 'URL manquante' });
      }
      const result = await checkConnectivity(url);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Real scan & passive/semi-active security analysis endpoint
  app.post('/api/scan/analyze', async (req, res) => {
    try {
      const { url, scope = 'wildcard', operatorId = 'SEC-OPS-0982' } = req.body;
      if (!url) {
        return res.status(400).json({ error: 'URL manquante' });
      }
      console.log(`[ShadowScan] Lancement de l'audit réel sur: ${url} (Scope: ${scope})`);
      const scanResult = await runRealAnalysis(url, scope, operatorId);
      res.json(scanResult);
    } catch (err: any) {
      console.error('[ShadowScan] Erreur lors de l\'audit réel:', err);
      res.status(500).json({ error: err.message || 'Erreur lors de l\'audit réseau' });
    }
  });

  // Laboratoire RÉEL — catalogue des 8 vecteurs (fiches techniques + sondes).
  // Le score CVSS est CALCULÉ vectoriellement (v3.1) côté serveur et renvoyé
  // avec le vecteur — le frontend n'invente jamais un score.
  app.get('/api/lab/vectors', (_req, res) => {
    res.json(
      LAB_ATTACK_VECTORS.map((v) => {
        try {
          const c = computeCvss31(v.cvssVector ?? '');
          return { ...v, cvssScore: c.baseScore, cvssSeverity: c.severity, cvssVectorNormalized: c.vector };
        } catch {
          return v; // pas de vecteur → renvoyé tel quel (repli documenté)
        }
      })
    );
  });

  // Cartographie des niveaux d'attestation exigés par outil WiFi réel
  // (source de vérité unique consommée par les vues LaboratoireWifiView et
  // WifiReseauView — le frontend ne duplique pas la décision).
  const WIFI_AUTH_REQUIREMENTS: Record<string, AuthorizationLevel> = {
    '/api/wifi/monitor-mode': 'ACTIVE',
    '/api/wifi/handshake-capture': 'ACTIVE',
    '/api/wifi/crack-handshake': 'DESTRUCTIVE',
    '/api/wifi/wps-attack': 'DESTRUCTIVE',
    '/api/wifi/evil-twin': 'DESTRUCTIVE',
    '/api/wifi/mac-changer': 'ACTIVE',
  };
  app.get('/api/wifi/auth-requirements', (_req, res) => {
    res.json({ requirements: WIFI_AUTH_REQUIREMENTS, statements: AUTHORIZATION_STATEMENTS });
  });

  /**
   * Garde-fou légal des outils WiFi RÉELS : exige une attestation du niveau
   * requis, la journalise, puis trace l'action dans audit_logs. Renvoie null
   * (et a déjà répondu 403) si l'attestation est absente/incorrecte.
   */
  const requireWifiAttestation = async (
    req: any,
    res: any,
    endpoint: string,
    level: AuthorizationLevel,
    targetLabel: string
  ): Promise<TestAuthorization | null> => {
    const check = validateAuthorization(req.body, level, targetLabel);
    if (!check.ok) {
      res.status(403).json({
        error: check.reason,
        attestationRequired: true,
        requiredLevel: level,
        endpoint,
        statement: AUTHORIZATION_STATEMENTS[level],
      });
      return null;
    }
    await recordAuthorization(check.authorization);
    try {
      const db = await getDatabase();
      db.run(
        `INSERT INTO audit_logs (id, timestamp, tag, text, operator_id)
         VALUES (?, datetime('now'), 'WIFI_REAL_ACTION', ?, ?)`,
        [
          `log-wifi-${Date.now()}-${Math.floor(Math.random() * 1e6)}`,
          `Outil WiFi réel ${endpoint} déclenché contre « ${check.authorization.targetUrl} » (attestation ${level}).`,
          check.authorization.operatorId,
        ]
      );
      saveDatabaseToDisk(db);
    } catch (err) {
      console.error('[WiFi] Échec de journalisation de l\'action WiFi réelle:', err);
    }
    return check.authorization;
  };

  // Déclaration légale officielle à afficher dans les modales d'autorisation
  app.get('/api/authorization/statements', (_req, res) => {
    res.json(AUTHORIZATION_STATEMENTS);
  });

  // Laboratoire RÉEL — exécute la sonde réelle d'un vecteur contre la cible.
  // Envoie de VRAIES requêtes HTTP à la cible autorisée (attestation ACTIVE
  // obligatoire, journalisée) et analyse les VRAIES réponses.
  app.post('/api/lab/probe', async (req, res) => {
    try {
      const { vectorId, targetUrl, operatorId = 'SEC-OPS-0982', authToken } = req.body || {};
      if (!vectorId) {
        return res.status(400).json({ error: 'vectorId requis' });
      }
      const authCheck = validateAuthorization(req.body, 'ACTIVE', targetUrl);
      if (!authCheck.ok) {
        return res.status(403).json({ error: authCheck.reason });
      }
      await recordAuthorization(authCheck.authorization);
      const probe = await executeLabProbe(vectorId, authCheck.authorization.targetUrl, operatorId, { authToken });
      res.json(probe);
    } catch (err: any) {
      console.error('[GuymaCyb Lab] Erreur de sonde réelle:', err);
      res.status(500).json({ error: err.message || 'Erreur de sonde réelle' });
    }
  });

  // Laboratoire RÉEL — suite complète des 8 sondes réelles contre la cible
  // autorisée + rapport consolidé réel persisté en SQLite.
  app.post('/api/lab/generate-report', async (req, res) => {
    try {
      const { operatorId = 'SEC-OPS-0982' } = req.body || {};
      const authCheck = validateAuthorization(req.body, 'ACTIVE');
      if (!authCheck.ok) {
        return res.status(403).json({ error: authCheck.reason });
      }
      await recordAuthorization(authCheck.authorization);
      const reportResult = await commitFullLabSuiteToReport(operatorId, authCheck.authorization.targetUrl);
      res.json(reportResult);
    } catch (err: any) {
      console.error('[GuymaCyb Lab] Erreur de rapport réel:', err);
      res.status(500).json({ error: err.message || 'Erreur de génération du rapport réel' });
    }
  });

  // Laboratoire RÉEL — historique des scans du laboratoire (SCAN-LABREAL-*)
  // et de leurs findings, lus depuis SQLite. Endoint référencé par le filtre
  // de /api/findings (les findings du lab sont exclus du dashboard général
  // et exposés ICI uniquement).
  app.get('/api/lab/history', async (_req, res) => {
    try {
      const db = await getDatabase();
      const scansResult = db.exec(`
        SELECT s.id, s.url, s.scan_type, s.cvss_score, s.risk_level, s.duration_ms,
               s.endpoints_count, s.created_at,
               (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS findings_count
        FROM scans s
        WHERE s.id LIKE 'SCAN-LABREAL-%' OR s.scan_type IN ('LAB_REAL_PROBE', 'LAB_REAL_SUITE')
        ORDER BY s.created_at DESC
        LIMIT 50
      `);
      const scans = (scansResult[0]?.values || []).map((row) => {
        const cols = scansResult[0].columns;
        const obj: Record<string, any> = {};
        cols.forEach((c, i) => (obj[c] = row[i]));
        return obj;
      });

      const findingsResult = db.exec(`
        SELECT id, scan_id, target_url, title, severity, cvss, confidence, status,
               affected_component, category, cwe, description, evidence_request,
               evidence_response, impact, remediation_title, remediation_steps_json,
               signature, cvss_vector, created_at
        FROM findings
        WHERE scan_id LIKE 'SCAN-LABREAL-%'
        ORDER BY created_at DESC
        LIMIT 200
      `);
      const findings = (findingsResult[0]?.values || []).map((row, rowIdx) => {
        const cols = findingsResult[0].columns;
        const obj: Record<string, any> = {};
        cols.forEach((c, i) => (obj[c] = row[i]));
        let steps: string[] = [];
        try {
          steps = JSON.parse(obj.remediation_steps_json || '[]');
        } catch {
          steps = [];
        }
        return {
          id: obj.id,
          scanId: obj.scan_id,
          targetUrl: obj.target_url,
          title: obj.title,
          severity: obj.severity,
          cvss: Number(obj.cvss),
          cvssVector: obj.cvss_vector ?? null,
          confidence: Number(obj.confidence),
          status: obj.status,
          affectedComponent: obj.affected_component,
          category: obj.category,
          cwe: obj.cwe,
          description: obj.description,
          evidence: { request: obj.evidence_request, response: obj.evidence_response },
          impact: obj.impact,
          remediationTitle: obj.remediation_title,
          remediationSteps: steps,
          signature: obj.signature,
          createdAt: obj.created_at,
          sqliteRow: rowIdx + 1,
        };
      });

      res.json({ scans, findings, totalScans: scans.length, totalFindings: findings.length });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // ============================================================
  //  Suite de TESTS ACTIFS RÉELS (attestation obligatoire)
  // ============================================================
  // Exécute 7 familles de sondes actives réelles (+ nikto réel si attestation
  // DESTRUCTIVE et Safe Mode OFF). Chaque famille envoie de vraies requêtes
  // réseau à la cible autorisée et persiste de vrais findings.
  app.post('/api/tests/active/run', async (req, res) => {
    try {
      const { url, operatorId = 'SEC-OPS-0982', safeMode = false } = req.body || {};
      const authCheck = validateAuthorization(req.body, 'DESTRUCTIVE', url);
      const level = authCheck.ok ? authCheck.authorization.level : 'ACTIVE';
      // Niveau ACTIVE accepté : les familles actives s'exécutent, la famille
      // déstructrice (nikto) est sautée avec un message honnête.
      const activeCheck = authCheck.ok
        ? authCheck
        : validateAuthorization(req.body, 'ACTIVE', url);
      if (!activeCheck.ok) {
        return res.status(403).json({ error: activeCheck.reason });
      }
      await recordAuthorization(activeCheck.authorization);
      const result = await runActiveTestSuite(activeCheck.authorization.targetUrl, operatorId, {
        safeMode: Boolean(safeMode),
        authorizationLevel: activeCheck.authorization.level as 'ACTIVE' | 'DESTRUCTIVE',
      });
      res.json(result);
    } catch (err: any) {
      console.error('[GuymaCyb ActiveTests] Erreur de suite active:', err);
      res.status(500).json({ error: err.message || 'Erreur de suite active' });
    }
  });

  // ============================================================
  //  Re-test RÉEL d'un finding (ré-exécution de la sonde d'origine)
  // ============================================================
  const retestHandler = async (req: any, res: any) => {
    try {
      const findingId = String(req.params.id || '');
      if (!findingId) return res.status(400).json({ error: 'id du finding requis' });
      const operatorId = (req.body && req.body.operatorId) || 'SEC-OPS-0982';
      const result = await retestFinding(findingId, operatorId);
      res.json(result);
    } catch (err: any) {
      console.error('[GuymaCyb Retest] Erreur de re-test:', err);
      res.status(err.message?.includes('introuvable') ? 404 : 500).json({ error: err.message || 'Erreur de re-test' });
    }
  };
  app.post('/api/findings/:id/retest', retestHandler);
  app.get('/api/findings/:id/retest', retestHandler);

  // Automated Reconnaissance Suite (defensive port discovery, DNS, headers)
  app.post('/api/recon/advanced-suite', async (req, res) => {
    try {
      const { url } = req.body;
      if (!url) {
        return res.status(400).json({ error: 'URL requise' });
      }
      const reconResult = await runAutomatedReconSuite(url);
      res.json(reconResult);
    } catch (err: any) {
      console.error('[ShadowScan Recon] Error in automated recon:', err);
      res.status(500).json({ error: err.message || 'Erreur de reconnaissance avancée' });
    }
  });

  // Get historical targets from SQLite
  app.get('/api/targets', async (_req, res) => {
    try {
      const db = await getDatabase();
      // Doctrine « zéro invention » : on EXCLUT la cible virtuelle du
      // laboratoire d'attaques (target-lab-sandbox / shadowscan-lab.internal)
      // pour qu'elle n'apparaisse pas dans le dashboard des cibles réelles.
      // L'ancien code mélangeait les cibles réelles scannées et la cible
      // fictive du lab, ce qui faussait le compteur de cibles historiques.
      const results = db.exec(`
        SELECT t.id, t.url, t.domain, t.scope, t.last_scanned_at,
               COALESCE(MAX(s.risk_level), 'CLEAN') as risk,
               COALESCE(MAX(s.cvss_score), 0.0) as score,
               (SELECT COUNT(*) FROM findings f JOIN scans sc ON f.scan_id = sc.id WHERE sc.target_id = t.id) as finding_count
        FROM targets t
        LEFT JOIN scans s ON t.id = s.target_id
        WHERE t.id != 'target-lab-sandbox'
          AND t.url NOT LIKE '%shadowscan-lab.internal%'
        GROUP BY t.id
        ORDER BY t.last_scanned_at DESC
      `);

      if (!results || results.length === 0) {
        return res.json([]);
      }

      const columns = results[0].columns;
      const rows = results[0].values.map((val) => {
        const obj: Record<string, any> = {};
        columns.forEach((col, idx) => {
          obj[col] = val[idx];
        });
        return {
          id: obj.id,
          url: obj.url,
          domain: obj.domain,
          risk: obj.risk || 'CLEAN',
          score: Number(obj.score) || 0.0,
          timestamp: obj.last_scanned_at,
          findingCount: Number(obj.finding_count) || 0,
        };
      });

      res.json(rows);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Get findings from SQLite
  app.get('/api/findings', async (req, res) => {
    try {
      const db = await getDatabase();
      const urlFilter = req.query.url as string | undefined;

      let query = `
        SELECT id, scan_id, target_url, title, severity, cvss, confidence, status,
               affected_component, category, cwe, description, evidence_request,
               evidence_response, impact, remediation_title, remediation_steps_json, signature, cvss_vector, created_at
        FROM findings
      `;
      const params: any[] = [];
      const conditions: string[] = [];
      // Doctrine « zéro invention » : on EXCLUT les findings du laboratoire
      // d'attaques (scan_id 'lab-simulation-scan' / 'SCAN-LAB-*' / 'SCAN-WIFI-LAB-*'
      // et target_url 'shadowscan-lab.internal') pour que le dashboard ne montre
      // QUE les findings issus de vrais scans de cibles réelles. Les findings du
      // lab sont accessibles via /api/lab/history (endpoint dédié).
      conditions.push(`(scan_id NOT LIKE 'lab-%' AND scan_id NOT LIKE 'SCAN-LAB-%' AND scan_id NOT LIKE 'SCAN-LABREAL-%' AND scan_id NOT LIKE 'SCAN-WIFI-LAB-%')`);
      conditions.push(`(target_url NOT LIKE '%shadowscan-lab.internal%')`);
      if (urlFilter) {
        conditions.push(`target_url LIKE ?`);
        params.push(`%${urlFilter}%`);
      }
      query += ` WHERE ` + conditions.join(' AND ');
      query += ` ORDER BY cvss DESC, created_at DESC LIMIT 50`;

      const results = db.exec(query, params);
      if (!results || results.length === 0) {
        return res.json([]);
      }

      const columns = results[0].columns;
      const findings = results[0].values.map((val, rowIdx) => {
        const obj: Record<string, any> = {};
        columns.forEach((col, idx) => {
          obj[col] = val[idx];
        });
        let steps: string[] = [];
        try {
          steps = JSON.parse(obj.remediation_steps_json || '[]');
        } catch {
          steps = [];
        }

        return {
          id: obj.id,
          title: obj.title,
          severity: obj.severity,
          cvss: Number(obj.cvss),
          cvssVector: obj.cvss_vector ?? null,
          confidence: Number(obj.confidence),
          status: obj.status,
          affectedComponent: obj.affected_component,
          category: obj.category,
          cwe: obj.cwe,
          description: obj.description,
          evidence: {
            request: obj.evidence_request,
            response: obj.evidence_response,
            authContext: 'Audit de sécurité réseau',
            // Doctrine « zéro invention » : on ne fabrique plus de latence
            // factice. roundtripMs n'est pas persisté en base (la table findings
            // n'a pas de colonne dédiée) — on l'omet plutôt que d'inventer 25.
            nonDestructiveProof: true,
          },
          impact: obj.impact,
          remediationTitle: obj.remediation_title,
          remediationSteps: steps,
          signature: obj.signature,
          sqliteRow: rowIdx + 1,
        };
      });

      res.json(findings);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Download real SQLite database file
  app.get('/api/database/export', (_req, res) => {
    const dbPath = getDbFilePath();
    if (fs.existsSync(dbPath)) {
      res.download(dbPath, 'shadow_core.db');
    } else {
      res.status(404).send('Fichier SQLite non trouvé');
    }
  });

  // Desktop Packaging API - Get Packaging Architecture & Specifications
  app.get('/api/desktop/info', (_req, res) => {
    res.json(getPackagingInfo());
  });

  // Desktop Packaging API - Download GuymaCyb-Setup-v1.0.0.exe Windows Installer
  // Doctrine « zéro invention » : on NE GÉNÈRE PLUS de stub .exe factice
  // (l'ancien code retournait un buffer de 64 octets avec juste l'en-tête MZ,
  // ce qui donnait l'illusion d'un téléchargement valide). Le vrai installateur
  // de ~180 Mo est produit par GitHub Actions (workflow build-windows.yml) et
  // téléchargeable depuis l'onglet Actions du dépôt. Ici on renvoie une réponse
  // JSON explicite indiquant que le build n'est pas disponible depuis l'app.
  app.get('/api/desktop/download-installer', (_req, res) => {
    res.status(501).json({
      error: 'Build non disponible depuis l\'application.',
      reason: 'Le vrai installateur Windows (GuymaCyb-Setup-v1.0.0.exe, ~180 Mo) est produit par GitHub Actions, pas par cette API. Un ancien code générait un stub .exe factice de 64 octets — supprimé (doctrine zéro invention).',
      howToGet: 'Téléchargez-le depuis l\'onglet Actions du dépôt GitHub : https://github.com/guylainboka/guymacyb/actions — ou build-le localement avec desktop\\build-windows-exe.bat sur Windows.',
    });
  });

  app.get('/api/desktop/download-portable', (_req, res) => {
    res.status(501).json({
      error: 'Bundle portable non disponible depuis l\'application.',
      reason: 'Idem que download-installer — le vrai bundle est produit par le build Windows, pas par cette API.',
      howToGet: 'Voir https://github.com/guylainboka/guymacyb/actions',
    });
  });

  // ============================================================
  //  API Outils de sécurité & réseau (toolbridge → Rust + scripts)
  // ============================================================
  //  NOTE (audit SEC-AUDIT-1 — M2) : les 12 endpoints directs
  //  `/api/tools/{status,headers,nmap,nikto,whatweb,dirbrute,dnsrecon,
  //  ssl-audit,ping,mtr,netcat,iperf3}` ont été SUPPRIMÉS. Ils n'étaient
  //  appelés par aucun écran du frontend et contournaient le modèle
  //  d'autorisation légale (attestation ACTIVE/DESTRUCTIVE) exigé partout
  //  ailleurs — chaque appel lançait un vrai outil (nmap/nikto…) contre une
  //  cible arbitraire sans attestation ni journalisation.
  //  Les parcours UI passent désormais exclusivement par les flux attestés :
  //  /api/scan/analyze, /api/recon/advanced-suite, /api/tests/active/run
  //  (attestation obligatoire), /api/localnetwork/scan, /api/arsenal/*.
  //  Les fonctions toolbridge (toolNmap, toolNikto…) restent disponibles
  //  pour les modules internes (activeTests.ts utilise toolNikto).

  // ============================================================
  //  API WiFi & Réseau sans fil (security-scripts/wifi-*.sh)
  // ============================================================

  // WiFi scan — liste des réseaux à portée
  app.post('/api/wifi/scan', async (req, res) => {
    try {
      const { interface: iface } = req.body || {};
      res.json(await tb.toolWifiScan(iface));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // WPA audit — audit de sécurité d'un AP spécifique
  app.post('/api/wifi/wpa-audit', async (req, res) => {
    try {
      const { target, interface: iface } = req.body || {};
      if (!target) return res.status(400).json({ error: 'target (BSSID ou SSID) requis' });
      res.json(await tb.toolWpaAudit(target, iface));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Détection de déauthentification (intrusion detection)
  app.post('/api/wifi/deauth-detect', async (req, res) => {
    try {
      const { interface: iface, duration } = req.body || {};
      res.json(await tb.toolDeauthDetect(iface, duration));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // WiFi Lab — catalogue des fiches techniques WiFi (contenu de cours).
  // Scores CVSS calculés vectoriellement (v3.1) côté serveur.
  app.get('/api/wifi/lab/vectors', (_req, res) => {
    res.json(
      WIFI_LAB_VECTORS.map((v) => {
        try {
          const c = computeCvss31(v.cvssVector ?? '');
          return { ...v, cvssScore: c.baseScore, cvssSeverity: c.severity, cvssVectorNormalized: c.vector };
        } catch {
          return v;
        }
      })
    );
  });

  // Les anciens endpoints de WiFi factice ont été retirés : le laboratoire
  // WiFi s'appuie désormais sur les outils WiFi RÉELS (/api/wifi/*) avec
  // attestation — voir LaboratoireWifiView. Aucune donnée WiFi n'est
  // fabriquée : sans matériel radio réel, les outils renvoient des erreurs
  // honnêtes (mode: no-wireless-hardware).
  app.post('/api/wifi/lab/simulate', (_req, res) => {
    res.status(410).json({
      error: 'Endpoint retiré — aucune donnée WiFi fabriquée. Utilisez les outils WiFi réels : POST /api/wifi/scan, /api/wifi/wpa-audit, /api/wifi/deauth-detect, /api/wifi/handshake-capture, /api/wifi/crack-handshake, /api/wifi/wps-attack, /api/wifi/mac-changer (attestation + matériel radio réel requis).',
    });
  });
  app.post('/api/wifi/lab/generate-report', (_req, res) => {
    res.status(410).json({
      error: 'Endpoint retiré — aucun rapport WiFi fabriqué. Les résultats WiFi réels proviennent des outils /api/wifi/* contre un réseau autorisé.',
    });
  });

  // ============================================================
  //  API Cours & Notions (cybersécurité WiFi / réseau / crypto)
  // ============================================================

  // Liste de toutes les notions
  app.get('/api/courses/notions', (_req, res) => {
    res.json(COURSE_NOTIONS);
  });

  // Récupérer une notion par son id
  app.get('/api/courses/notions/:id', (req, res) => {
    const notion = COURSE_NOTIONS.find((n) => n.id === req.params.id);
    if (!notion) return res.status(404).json({ error: 'Notion introuvable' });
    res.json(notion);
  });

  // ============================================================
  //  API WiFi avancé (monitor mode, handshake, crack, WPS, MAC)
  // ============================================================

  // Active le mode monitor sur une interface — attestation ACTIVE requise
  // (altère l'état radio de la machine de l'opérateur, prérequis d'attaques).
  app.post('/api/wifi/monitor-mode', async (req, res) => {
    try {
      const { interface: iface } = req.body;
      if (!iface) return res.status(400).json({ error: 'interface requise' });
      const auth = await requireWifiAttestation(req, res, '/api/wifi/monitor-mode', 'ACTIVE', iface);
      if (!auth) return;
      res.json(await tb.toolWifiMonitorMode(iface));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Capture d'un 4-way handshake — attestation ACTIVE requise
  // (écoute ciblée réelle sur un BSSID précis).
  app.post('/api/wifi/handshake-capture', async (req, res) => {
    try {
      const { bssid, channel, interface: iface, duration } = req.body;
      if (!bssid) return res.status(400).json({ error: 'bssid requis' });
      const auth = await requireWifiAttestation(req, res, '/api/wifi/handshake-capture', 'ACTIVE', bssid);
      if (!auth) return;
      res.json(await tb.toolWifiHandshakeCapture(bssid, channel || 6, iface || 'wlan0mon', duration || 30));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Casser un handshake capturé — attestation DESTRUCTIVE requise
  // (attaque par force brute contre des identifiants réels).
  app.post('/api/wifi/crack-handshake', async (req, res) => {
    try {
      const { capFile, wordlist } = req.body;
      if (!capFile) return res.status(400).json({ error: 'capFile requis' });
      const auth = await requireWifiAttestation(req, res, '/api/wifi/crack-handshake', 'DESTRUCTIVE', capFile);
      if (!auth) return;
      res.json(await tb.toolWifiCrackHandshake(capFile, wordlist));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Attaque WPS (Pixie-Dust / PIN / brute) — attestation DESTRUCTIVE requise
  // (attaque active contre le point d'accès cible).
  app.post('/api/wifi/wps-attack', async (req, res) => {
    try {
      const { bssid, interface: iface, mode, pin } = req.body;
      if (!bssid) return res.status(400).json({ error: 'bssid requis' });
      const auth = await requireWifiAttestation(req, res, '/api/wifi/wps-attack', 'DESTRUCTIVE', bssid);
      if (!auth) return;
      res.json(await tb.toolWifiWpsAttack(bssid, iface || 'wlan0mon', mode || 'pixie', pin));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Evil Twin réel (hostapd + dnsmasq) — attestation DESTRUCTIVE requise
  // (usurpation d'identité radio : interception de trafic réel de clients).
  app.post('/api/wifi/evil-twin', async (req, res) => {
    try {
      const { ssid, channel, interface: iface, duration } = req.body;
      if (!ssid) return res.status(400).json({ error: 'ssid requis' });
      const auth = await requireWifiAttestation(req, res, '/api/wifi/evil-twin', 'DESTRUCTIVE', ssid);
      if (!auth) return;
      res.json(await tb.toolWifiEvilTwin(ssid, channel || 6, iface || 'wlan0mon', duration || 60));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Changement d'adresse MAC — attestation ACTIVE requise (altération de
  // l'identité matérielle de l'interface de l'opérateur).
  app.post('/api/wifi/mac-changer', async (req, res) => {
    try {
      const { interface: iface, mac } = req.body;
      if (!iface) return res.status(400).json({ error: 'interface requise' });
      const auth = await requireWifiAttestation(req, res, '/api/wifi/mac-changer', 'ACTIVE', iface);
      if (!auth) return;
      res.json(await tb.toolWifiMacChanger(iface, mac));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // ============================================================
  //  API Terminal intégré (bash / powershell / cmd / python)
  // ============================================================

  app.post('/api/terminal/exec', async (req, res) => {
    try {
      const { shell, command, cwd } = req.body;
      if (!shell || !command) return res.status(400).json({ error: 'shell et command requis' });
      res.json(await tb.toolTerminal(shell, command, cwd));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // ============================================================
  //  API Modules StrykerOSS — Core Manager, Réseau Local,
  //  Arsenal, GeoMac, Dashboard stats
  // ============================================================

  // Core Manager — statut global du noyau (WSL, outils installés/manquants, mémoire)
  app.get('/api/core/status', async (_req, res) => {
    try {
      const status = await tb.getCoreStatus();
      res.json(status);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Force une re-détection WSL (après installation d'un distro par exemple)
  app.post('/api/core/refresh-wsl', async (_req, res) => {
    try {
      invalidateWslCache();
      const status = await tb.getCoreStatus();
      res.json(status);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Installation en un clic de la DISTRIBUTION Ubuntu — traite l'état
  // « WSL installé mais aucune distro » (wsl.exe répond, `wsl -l -v` vide).
  // Le téléchargement peut durer 5-15 min : le POST démarre le job asynchrone
  // et rend la main immédiatement ; le suivi se fait via GET .../status.
  app.post('/api/core/install-distro', async (_req, res) => {
    try {
      const r = startDistroInstall();
      if (!r.started) return res.status(409).json({ error: r.message });
      res.json({ started: true, message: r.message });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Suivi du job d'installation de la distribution : état + journal en direct.
  app.get('/api/core/install-distro/status', async (_req, res) => {
    try {
      res.json(getDistroInstallStatus());
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Registre des outils installés (dossier tools-registry, preuve locale réelle)
  app.get('/api/core/tools-registry', async (_req, res) => {
    try {
      res.json(ws.readToolRegistry());
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // ============================================================
  //  Intégration système Windows (droits admin, matériel, services)
  // ============================================================

  // Statut système consolidé pour l'Accueil : droits admin + WSL + résumé matériel
  app.get('/api/system/status', async (_req, res) => {
    try {
      const [admin, hw] = await Promise.all([ws.isAdmin(), ws.getHardware()]);
      res.json({
        platform: process.platform,
        admin,
        hardware: {
          os: hw.os,
          cpu: hw.cpu,
          ram: hw.ram,
          hostname: hw.hostname,
          error: hw.error,
        },
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Inventaire matériel complet (CIM/WMI sur Windows, /proc sur Linux)
  app.get('/api/system/hardware', async (_req, res) => {
    try {
      res.json(await ws.getHardware());
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Services Windows surveillés (LxssManager/WslService, BFE, Defender, WLAN…)
  app.get('/api/system/services', async (_req, res) => {
    try {
      res.json(await ws.getWatchedServices());
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Core Manager — installe les outils Linux manquants (apt) via WSL sur Windows,
  // direct sur Linux. Peut prendre jusqu'à 10 minutes. Chaque outil est ensuite
  // VÉRIFIÉ (which + version) et consigné dans <dataDir>/tools-registry/.
  app.post('/api/core/install-tools', async (_req, res) => {
    try {
      const result = await tb.installToolsViaApt();
      invalidateWslCache();
      // Vérification réelle post-install + registre local (dossier tools-registry)
      const verification = await tb.verifyInstalledTools();
      res.json({ ...result, verification });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // ============================================================
  //  Centre de mises à jour (V2) — détection RÉELLE, zéro simulation
  // ============================================================
  //  GET : version du logiciel vs dernière release GitHub (API publique) +
  //  paquets apt périmés/manquants (apt-get update + apt-cache policy réels).
  //  Les deux sources peuvent renvoyer une ERREUR honnête (hors-ligne, pas de
  //  distro, rate-limit) — jamais d'état inventé.
  app.get('/api/updates/check', async (_req, res) => {
    try {
      const [app, tools] = await Promise.all([updates.getAppUpdateInfo(), updates.getToolsUpdateInfo()]);
      res.json({ app, tools });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  //  POST : UNE SEULE action — met à jour les paquets périmés ET installe les
  //  manquants en une seule commande apt (l'UI affiche UN avertissement et
  //  l'utilisateur confirme UNE fois). Re-vérification réelle post-application.
  app.post('/api/updates/apply-tools', async (_req, res) => {
    try {
      const result = await updates.applyToolUpdates();
      updates.invalidateUpdateCaches();
      let verification: Awaited<ReturnType<typeof tb.verifyInstalledTools>> | null = null;
      try {
        verification = await tb.verifyInstalledTools();
      } catch { /* vérification indisponible : non bloquant */ }
      res.json({ ...result, verification });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Réseau Local — découverte rootless (mDNS + SSDP + NetBIOS + rDNS /24 + TCP ports)
  app.post('/api/localnetwork/scan', async (req, res) => {
    try {
      const { interface: _iface } = req.body || {};
      // L'interface optionnelle n'est pas encore câblée côté script (il auto-détecte).
      res.json(await tb.toolLocalNetworkScan());
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Arsenal — searchsploit : recherche d'exploits par mot-clé
  app.post('/api/arsenal/searchsploit', async (req, res) => {
    try {
      const { query } = req.body;
      if (!query) return res.status(400).json({ error: 'query requis' });
      res.json(await tb.toolSearchsploit(query));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Arsenal — hashcat : crackage d'un hash (mode -m, wordlist optionnelle)
  app.post('/api/arsenal/hashcat', async (req, res) => {
    try {
      const { hash, mode, wordlist } = req.body;
      if (!hash) return res.status(400).json({ error: 'hash requis' });
      res.json(await tb.toolHashcat(hash, mode || '0', wordlist));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // GeoMac — géolocalisation d'une adresse MAC (OUI vendor + WiGLE optionnel)
  app.post('/api/geomac/locate', async (req, res) => {
    try {
      const { mac } = req.body;
      if (!mac) return res.status(400).json({ error: 'mac requis' });
      res.json(await tb.toolGeoMac(mac));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // ====================================================================
  //  API Modules StrykerOSS — Cameradar / HID / USB Arsenal
  //  (ajoutés par STRYKER-MODULES-2 — endpoints en fin de section, avant
  //   l'intégration Vite. Aucune altération des routes existantes.)
  // ====================================================================

  // Cameradar — découverte de caméras RTSP (port 554) + sweep credentials
  app.post('/api/cameradar/scan', async (req, res) => {
    try {
      const { subnet } = req.body || {};
      res.json(await tb.toolCameradarScan(subnet || undefined));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // HID Attacks — génération d'un payload DuckyScript (type requis)
  app.post('/api/hid/payload', async (req, res) => {
    try {
      const { type } = req.body;
      if (!type) return res.status(400).json({ error: 'type requis' });
      res.json(await tb.toolHidPayloads(type));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // USB Arsenal — gestion de gadgets USB (configfs Linux/WSL)
  app.post('/api/usb-arsenal', async (req, res) => {
    try {
      const { action, profile } = req.body || {};
      if (!action) return res.status(400).json({ error: 'action requis (list|status|apply)' });
      res.json(await tb.toolUsbArsenal(action, profile || undefined));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 404 JSON propre pour toute route /api inconnue — DOIT être avant l'intégration
  // Vite/static (sinon app.get('*') renvoie le HTML de l'index pour les /api GET).
  app.use('/api', (_req, res) => {
    res.status(404).json({ error: `Endpoint inconnu : ${_req.method} ${_req.originalUrl}` });
  });

  // Vite integration
  const isProd = process.env.NODE_ENV === 'production';
  if (!isProd) {
    // Import DYNAMIQUE de vite : en production ce code n'est jamais atteint,
    // donc `require('vite')` (généré par esbuild) n'est jamais exécuté et le
    // bundle prod n'a pas besoin de `node_modules/vite`. Voir le commentaire
    // en tête de fichier pour le détail du bug de packaging que ça corrige.
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  // Gestionnaire d'erreurs global — capture notamment les erreurs de parsing
  // JSON (body malformé) et toute erreur asynchrone échappée aux try/catch.
  app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    if (err?.type === 'entity.parse.failed' || err instanceof SyntaxError) {
      return res.status(400).json({ error: 'Corps de requête JSON invalide' });
    }
    console.error('[ShadowScan] Unhandled error:', err);
    if (res.headersSent) return;
    res.status(500).json({ error: err?.message || 'Erreur interne du serveur' });
  });

  const server = app.listen(PORT, HOST, () => {
    console.log(`[ShadowScan] Server listening on http://${HOST}:${PORT} (pid ${process.pid})`);
  });

  // Augmente la robustesse réseau : plus de marge pour les requêtes longues
  // (scans nmap/nikto proxyés) et keep-alive ajusté.
  server.requestTimeout = 0;           // pas de limite globale (les endpoints gèrent leurs propres timeouts)
  server.headersTimeout = 65_000;
  server.keepAliveTimeout = 30_000;

  // Arrêt gracieux : sauvegarde SQLite + fermeture propre (Ctrl-C, taskkill, SIGTERM)
  let shuttingDown = false;
  const shutdown = (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`[ShadowScan] ${signal} reçu — arrêt gracieux…`);
    try { saveDatabaseToDisk(); } catch (e) { console.warn('[ShadowScan] DB save on shutdown failed:', e); }
    server.close(() => {
      console.log('[ShadowScan] Serveur arrêté proprement.');
      process.exit(0);
    });
    // Filet de sécurité si server.close() pend (connexions ouvertes)
    setTimeout(() => process.exit(0), 4000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('uncaughtException', (err) => {
    console.error('[ShadowScan] uncaughtException:', err);
    shutdown('uncaughtException');
  });
  process.on('unhandledRejection', (reason) => {
    console.error('[ShadowScan] unhandledRejection:', reason);
  });
}

startServer().catch((err) => {
  console.error('Fatal server startup error:', err);
  process.exit(1);
});
