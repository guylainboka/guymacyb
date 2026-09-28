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
  executeLabSimulation,
  commitFullLabSuiteToReport,
  runAutomatedReconSuite,
  executeWifiLabSimulation,
  commitFullWifiLabSuiteToReport,
} from './src/server/securityLab';
import { LAB_ATTACK_VECTORS } from './src/data/labAttackVectors';
import { WIFI_LAB_VECTORS } from './src/data/wifiLabVectors';
import { COURSE_NOTIONS } from './src/data/courseNotions';
import { getPackagingInfo } from './src/server/packaging';
import * as tb from './src/server/toolbridge';

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
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'no-referrer');
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

      const targetCount = (targetCountRes[0]?.values[0]?.[0] as number) || 0;
      const scanCount = (scanCountRes[0]?.values[0]?.[0] as number) || 0;
      const findingsCount = (findingsCountRes[0]?.values[0]?.[0] as number) || 0;

      res.json({
        status: 'UP',
        engine: 'ShadowScan Real Network Scanner v1.0.0',
        sqlite: {
          connected: true,
          dbPath: getDbFilePath(),
          targetsCount: targetCount,
          scansCount: scanCount,
          findingsCount: findingsCount,
        },
        memoryMb: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        threads: os.cpus().length, // valeur réelle (l'ancien code hardcoded 8)
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
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

  // Cyber Security Lab API - List all attack vectors
  app.get('/api/lab/vectors', (_req, res) => {
    res.json(LAB_ATTACK_VECTORS);
  });

  // Cyber Security Lab API - Simulate attack vector in sandbox
  app.post('/api/lab/simulate', async (req, res) => {
    try {
      const { vectorId, targetMode = 'vulnerable', operatorId = 'SEC-OPS-0982' } = req.body;
      if (!vectorId) {
        return res.status(400).json({ error: 'vectorId requis' });
      }
      const simulation = await executeLabSimulation(vectorId, targetMode, operatorId);
      res.json(simulation);
    } catch (err: any) {
      console.error('[ShadowScan Lab] Simulation error:', err);
      res.status(500).json({ error: err.message || 'Erreur de simulation' });
    }
  });

  // Cyber Security Lab API - Generate full lab audit report and persist in SQLite
  app.post('/api/lab/generate-report', async (req, res) => {
    try {
      const { operatorId = 'SEC-OPS-0982' } = req.body;
      const reportResult = await commitFullLabSuiteToReport(operatorId);
      res.json(reportResult);
    } catch (err: any) {
      console.error('[ShadowScan Lab] Report generation error:', err);
      res.status(500).json({ error: err.message || 'Erreur de génération du rapport' });
    }
  });

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
      // Doctrine « zéro simulation » : on EXCLUT la cible virtuelle du
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
               evidence_response, impact, remediation_title, remediation_steps_json, signature, created_at
        FROM findings
      `;
      const params: any[] = [];
      const conditions: string[] = [];
      // Doctrine « zéro simulation » : on EXCLUT les findings du laboratoire
      // d'attaques (scan_id 'lab-simulation-scan' / 'SCAN-LAB-*' / 'SCAN-WIFI-LAB-*'
      // et target_url 'shadowscan-lab.internal') pour que le dashboard ne montre
      // QUE les findings issus de vrais scans de cibles réelles. Les findings du
      // lab sont accessibles via /api/lab/history (endpoint dédié).
      conditions.push(`(scan_id NOT LIKE 'lab-%' AND scan_id NOT LIKE 'SCAN-LAB-%' AND scan_id NOT LIKE 'SCAN-WIFI-LAB-%')`);
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
            // Doctrine « zéro simulation » : on ne fabrique plus de latence
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
  // Doctrine « zéro simulation » : on NE GÉNÈRE PLUS de stub .exe factice
  // (l'ancien code retournait un buffer de 64 octets avec juste l'en-tête MZ,
  // ce qui donnait l'illusion d'un téléchargement valide). Le vrai installateur
  // de ~180 Mo est produit par GitHub Actions (workflow build-windows.yml) et
  // téléchargeable depuis l'onglet Actions du dépôt. Ici on renvoie une réponse
  // JSON explicite indiquant que le build n'est pas disponible depuis l'app.
  app.get('/api/desktop/download-installer', (_req, res) => {
    res.status(501).json({
      error: 'Build non disponible depuis l\'application.',
      reason: 'Le vrai installateur Windows (GuymaCyb-Setup-v1.0.0.exe, ~180 Mo) est produit par GitHub Actions, pas par cette API. Un ancien code générait un stub .exe factice de 64 octets — supprimé (doctrine zéro simulation).',
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

  // Vérifie quels outils sont installés sur le système hôte.
  app.get('/api/tools/status', async (_req, res) => {
    try {
      const status = await tb.checkInstalledTools();
      res.json(status);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Audit d'en-têtes HTTP via le noyau Rust.
  app.post('/api/tools/headers', async (req, res) => {
    try {
      const { url } = req.body;
      if (!url) return res.status(400).json({ error: 'URL requise' });
      const result = await tb.coreHeaders(url);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Nmap — scan de ports
  app.post('/api/tools/nmap', async (req, res) => {
    try {
      const { url, ports } = req.body;
      if (!url) return res.status(400).json({ error: 'URL requise' });
      res.json(await tb.toolNmap(url, ports));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Nikto — vulnérabilités serveur web
  app.post('/api/tools/nikto', async (req, res) => {
    try {
      const { url } = req.body;
      if (!url) return res.status(400).json({ error: 'URL requise' });
      res.json(await tb.toolNikto(url));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // WhatWeb — empreinte technologies web
  app.post('/api/tools/whatweb', async (req, res) => {
    try {
      const { url } = req.body;
      if (!url) return res.status(400).json({ error: 'URL requise' });
      res.json(await tb.toolWhatweb(url));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Dirbrute — découverte de chemins
  app.post('/api/tools/dirbrute', async (req, res) => {
    try {
      const { url, wordlist } = req.body;
      if (!url) return res.status(400).json({ error: 'URL requise' });
      res.json(await tb.toolDirbrute(url, wordlist));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // DNS recon — enregistrements DNS
  app.post('/api/tools/dnsrecon', async (req, res) => {
    try {
      const { url } = req.body;
      if (!url) return res.status(400).json({ error: 'URL requise' });
      res.json(await tb.toolDnsrecon(url));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // SSL/TLS audit — certificats + versions TLS
  app.post('/api/tools/ssl-audit', async (req, res) => {
    try {
      const { url, port } = req.body;
      if (!url) return res.status(400).json({ error: 'URL requise' });
      res.json(await tb.toolSslAudit(url, port));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Ping — connectivité ICMP
  app.post('/api/tools/ping', async (req, res) => {
    try {
      const { url, count } = req.body;
      if (!url) return res.status(400).json({ error: 'URL requise' });
      res.json(await tb.toolPing(url, count));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // MTR / traceroute — chemin réseau
  app.post('/api/tools/mtr', async (req, res) => {
    try {
      const { url, count } = req.body;
      if (!url) return res.status(400).json({ error: 'URL requise' });
      res.json(await tb.toolMtr(url, count));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Netcat — sonde TCP
  app.post('/api/tools/netcat', async (req, res) => {
    try {
      const { url, port, data } = req.body;
      if (!url) return res.status(400).json({ error: 'URL requise' });
      res.json(await tb.toolNetcat(url, port, data));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // iperf3 — mesure de bande passante (client)
  app.post('/api/tools/iperf3', async (req, res) => {
    try {
      const { server, port, udp, time, reverse } = req.body;
      if (!server) return res.status(400).json({ error: 'server requis' });
      res.json(await tb.toolIperf3(server, { port, udp, time, reverse }));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

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

  // WiFi Lab — liste de tous les vecteurs d'attaque WiFi
  app.get('/api/wifi/lab/vectors', (_req, res) => {
    res.json(WIFI_LAB_VECTORS);
  });

  // WiFi Lab — simuler un vecteur d'attaque dans le sandbox
  app.post('/api/wifi/lab/simulate', async (req, res) => {
    try {
      const { vectorId, targetMode = 'vulnerable', operatorId = 'SEC-OPS-0982' } = req.body || {};
      if (!vectorId) return res.status(400).json({ error: 'vectorId requis' });
      const simulation = await executeWifiLabSimulation(vectorId, targetMode, operatorId);
      res.json(simulation);
    } catch (err: any) {
      console.error('[ShadowScan WiFi Lab] Simulation error:', err);
      res.status(500).json({ error: err.message || 'Erreur de simulation WiFi' });
    }
  });

  // WiFi Lab — générer un rapport WiFi complet et le persister en SQLite
  app.post('/api/wifi/lab/generate-report', async (req, res) => {
    try {
      const { operatorId = 'SEC-OPS-0982' } = req.body || {};
      const reportResult = await commitFullWifiLabSuiteToReport(operatorId);
      res.json(reportResult);
    } catch (err: any) {
      console.error('[ShadowScan WiFi Lab] Report generation error:', err);
      res.status(500).json({ error: err.message || 'Erreur de génération du rapport WiFi' });
    }
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

  // Active le mode monitor sur une interface
  app.post('/api/wifi/monitor-mode', async (req, res) => {
    try {
      const { interface: iface } = req.body;
      if (!iface) return res.status(400).json({ error: 'interface requise' });
      res.json(await tb.toolWifiMonitorMode(iface));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Capture d'un 4-way handshake
  app.post('/api/wifi/handshake-capture', async (req, res) => {
    try {
      const { bssid, channel, interface: iface, duration } = req.body;
      if (!bssid) return res.status(400).json({ error: 'bssid requis' });
      res.json(await tb.toolWifiHandshakeCapture(bssid, channel || 6, iface || 'wlan0mon', duration || 30));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Casser un handshake capturé
  app.post('/api/wifi/crack-handshake', async (req, res) => {
    try {
      const { capFile, wordlist } = req.body;
      if (!capFile) return res.status(400).json({ error: 'capFile requis' });
      res.json(await tb.toolWifiCrackHandshake(capFile, wordlist));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Attaque WPS (Pixie-Dust / PIN / brute)
  app.post('/api/wifi/wps-attack', async (req, res) => {
    try {
      const { bssid, interface: iface, mode, pin } = req.body;
      if (!bssid) return res.status(400).json({ error: 'bssid requis' });
      res.json(await tb.toolWifiWpsAttack(bssid, iface || 'wlan0mon', mode || 'pixie', pin));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Changement d'adresse MAC
  app.post('/api/wifi/mac-changer', async (req, res) => {
    try {
      const { interface: iface, mac } = req.body;
      if (!iface) return res.status(400).json({ error: 'interface requise' });
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

  // Core Manager — installe les outils Linux manquants (apt) via WSL sur Windows,
  // direct sur Linux. Peut prendre jusqu'à 3 minutes.
  app.post('/api/core/install-tools', async (_req, res) => {
    try {
      res.json(await tb.installToolsViaApt());
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

  // Dashboard — statistiques agrégées depuis SQLite (compteurs + derniers 5)
  // Doctrine « zéro simulation » : on EXCLUT systématiquement les entrées du
  // laboratoire d'attaques (target-lab-sandbox / shadowscan-lab.internal /
  // scans 'lab-%' / 'SCAN-LAB-%' / 'SCAN-WIFI-LAB-%') pour que le dashboard
  // ne reflète QUE les vrais scans de cibles réelles.
  app.get('/api/dashboard/stats', async (_req, res) => {
    try {
      const db = await getDatabase();
      const LAB_TARGET_CLAUSE = `id != 'target-lab-sandbox' AND url NOT LIKE '%shadowscan-lab.internal%'`;
      const LAB_SCAN_CLAUSE = `id NOT LIKE 'lab-%' AND id NOT LIKE 'SCAN-LAB-%' AND id NOT LIKE 'SCAN-WIFI-LAB-%'`;
      const LAB_FINDING_CLAUSE = `scan_id NOT LIKE 'lab-%' AND scan_id NOT LIKE 'SCAN-LAB-%' AND scan_id NOT LIKE 'SCAN-WIFI-LAB-%' AND target_url NOT LIKE '%shadowscan-lab.internal%'`;

      const targetCount = Number(db.exec(`SELECT COUNT(*) FROM targets WHERE ${LAB_TARGET_CLAUSE}`)[0]?.values[0]?.[0] || 0);
      const scanCount = Number(db.exec(`SELECT COUNT(*) FROM scans WHERE ${LAB_SCAN_CLAUSE}`)[0]?.values[0]?.[0] || 0);
      const findingsCount = Number(db.exec(`SELECT COUNT(*) FROM findings WHERE ${LAB_FINDING_CLAUSE}`)[0]?.values[0]?.[0] || 0);

      // Findings par sévérité (CRITICAL / HIGH / MEDIUM / LOW / INFO + autres)
      const sevRes = db.exec(`SELECT severity, COUNT(*) FROM findings WHERE ${LAB_FINDING_CLAUSE} GROUP BY severity`);
      const bySeverity: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
      if (sevRes[0]) {
        for (const row of sevRes[0].values) {
          const sev = String(row[0] || '').toUpperCase();
          const count = Number(row[1]) || 0;
          if (sev in bySeverity) bySeverity[sev] = count;
          else bySeverity[sev] = (bySeverity[sev] || 0) + count;
        }
      }

      // 5 derniers findings (excluant le lab)
      const recentFindingsRes = db.exec(
        `SELECT id, target_url, title, severity, cvss, created_at
         FROM findings WHERE ${LAB_FINDING_CLAUSE} ORDER BY created_at DESC LIMIT 5`
      );
      const recentFindings: any[] = [];
      if (recentFindingsRes[0]) {
        const cols = recentFindingsRes[0].columns;
        for (const row of recentFindingsRes[0].values) {
          const obj: Record<string, any> = {};
          cols.forEach((c, i) => (obj[c] = row[i]));
          recentFindings.push(obj);
        }
      }

      // 5 dernières targets (excluant le lab)
      const recentTargetsRes = db.exec(
        `SELECT id, url, domain, scope, status, last_scanned_at
         FROM targets WHERE ${LAB_TARGET_CLAUSE} ORDER BY last_scanned_at DESC LIMIT 5`
      );
      const recentTargets: any[] = [];
      if (recentTargetsRes[0]) {
        const cols = recentTargetsRes[0].columns;
        for (const row of recentTargetsRes[0].values) {
          const obj: Record<string, any> = {};
          cols.forEach((c, i) => (obj[c] = row[i]));
          recentTargets.push(obj);
        }
      }

      res.json({
        targets: targetCount,
        scans: scanCount,
        findings: findingsCount,
        bySeverity,
        recentFindings,
        recentTargets,
        engine: 'wsl-bridge-real',
        platform: process.platform,
      });
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
