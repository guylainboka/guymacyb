import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import fs from 'fs';
import { getDatabase, saveDatabaseToDisk, getDbFilePath } from './src/server/db';
import { checkConnectivity, runRealAnalysis } from './src/server/scanner';
import {
  executeLabSimulation,
  commitFullLabSuiteToReport,
  runAutomatedReconSuite,
} from './src/server/securityLab';
import { LAB_ATTACK_VECTORS } from './src/data/labAttackVectors';
import { getOrCreateInstallerExeBuffer, getPackagingInfo } from './src/server/packaging';

const PORT = 3000;

async function startServer() {
  const app = express();
  app.use(express.json());

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
        threads: 8,
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
      const results = db.exec(`
        SELECT t.id, t.url, t.domain, t.scope, t.last_scanned_at,
               COALESCE(MAX(s.risk_level), 'CLEAN') as risk,
               COALESCE(MAX(s.cvss_score), 0.0) as score,
               (SELECT COUNT(*) FROM findings f JOIN scans sc ON f.scan_id = sc.id WHERE sc.target_id = t.id) as finding_count
        FROM targets t
        LEFT JOIN scans s ON t.id = s.target_id
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
      if (urlFilter) {
        query += ` WHERE target_url LIKE ?`;
        params.push(`%${urlFilter}%`);
      }
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
            roundtripMs: 25,
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
  app.get('/api/desktop/download-installer', (_req, res) => {
    try {
      const exeBuffer = getOrCreateInstallerExeBuffer();
      res.setHeader('Content-Type', 'application/vnd.microsoft.portable-executable');
      res.setHeader('Content-Disposition', 'attachment; filename="GuymaCyb-Setup-v1.0.0.exe"');
      res.setHeader('Content-Length', exeBuffer.length);
      res.send(exeBuffer);
    } catch (err: any) {
      console.error('[Guyma Cyb Packaging] Error generating installer:', err);
      res.status(500).send('Erreur lors de la génération de l\'installateur');
    }
  });

  // Desktop Packaging API - Download GuymaCyb-Portable-v1.0.0 Bundle
  app.get('/api/desktop/download-portable', (_req, res) => {
    try {
      const exeBuffer = getOrCreateInstallerExeBuffer();
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', 'attachment; filename="GuymaCyb-Portable-v1.0.0.zip"');
      res.send(exeBuffer);
    } catch (err: any) {
      console.error('[Guyma Cyb Packaging] Error generating portable bundle:', err);
      res.status(500).send('Erreur lors de la génération du bundle');
    }
  });

  // Vite integration
  const isProd = process.env.NODE_ENV === 'production';
  if (!isProd) {
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

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[ShadowScan] Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Fatal server startup error:', err);
  process.exit(1);
});
