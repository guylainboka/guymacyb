import React, { useState } from 'react';
import { TargetConfig } from '../../types';

interface ReportRemediationViewProps {
  targetConfig: TargetConfig;
}

export const ReportRemediationView: React.FC<ReportRemediationViewProps> = ({
  targetConfig,
}) => {
  const [copyStatus, setCopyStatus] = useState<string | null>(null);
  const [showIssueModal, setShowIssueModal] = useState<boolean>(false);
  const [activeTabRemediation, setActiveTabRemediation] = useState<'idor' | 'sqli' | 'csp'>('idor');

  const handleCopyJson = () => {
    const reportData = {
      reportId: 'REP-20240524-EXM',
      auditEngine: 'ShadowScan v1.0.0',
      target: targetConfig.url,
      timestamp: new Date().toISOString(),
      operator: targetConfig.operatorId,
      overallRisk: 'HIGH',
      cvssBaseScore: 7.4,
      findingsSummary: {
        critical: 0,
        high: 3,
        medium: 7,
        low: 11,
      },
      auditSurface: {
        endpoints: 137,
        apiRoutes: 42,
        technologies: 9,
        testedVectors: 8,
      },
    };
    navigator.clipboard.writeText(JSON.stringify(reportData, null, 2));
    setCopyStatus('Copié !');
    setTimeout(() => setCopyStatus(null), 2000);
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="flex-1 overflow-y-auto p-6 flex flex-col gap-6 font-sans">
      {/* Top Bar Actions & Audit Info */}
      <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-5 flex flex-wrap items-center justify-between gap-4 shadow-sm font-mono text-xs">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded bg-[#4d8eff]/20 border border-[#4d8eff]/40 flex items-center justify-center text-[#4d8eff]">
            <span className="material-symbols-outlined text-[24px]">assessment</span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-[#dfe2f1]">
                Rapport de Sécurité & Plan d'Action Développeurs
              </h2>
              <span className="px-2 py-0.5 rounded bg-[#262a35] text-[#4cd7f6] text-[10px]">
                ID: REP-20240524-EXM
              </span>
            </div>
            <p className="text-xs text-[#8c909f] mt-0.5">
              Cible: <strong className="text-[#dfe2f1]">{targetConfig.url}</strong> • Moteur:{' '}
              <strong className="text-[#dfe2f1]">ShadowScan v1.0.0</strong> • Opérateur:{' '}
              <span className="text-[#3b82f6]">{targetConfig.operatorId}</span>
            </p>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-2 no-print">
          <button
            type="button"
            onClick={handleCopyJson}
            className="px-3 py-1.5 rounded bg-[#262a35] hover:bg-[#313540] text-[#c2c6d6] hover:text-white border border-[#424754] flex items-center gap-1.5 transition-colors"
          >
            <span className="material-symbols-outlined text-[14px]">content_copy</span>
            <span>{copyStatus || 'Copier le JSON'}</span>
          </button>

          <button
            type="button"
            onClick={() => setShowIssueModal(true)}
            className="px-3 py-1.5 rounded bg-[#262a35] hover:bg-[#313540] text-[#c2c6d6] hover:text-white border border-[#424754] flex items-center gap-1.5 transition-colors"
          >
            <span className="material-symbols-outlined text-[14px]">bug_report</span>
            <span>Tickets Jira / GitHub</span>
          </button>

          <button
            type="button"
            onClick={handlePrint}
            className="px-4 py-1.5 rounded bg-[#4d8eff] hover:bg-[#3b82f6] text-white font-bold flex items-center gap-1.5 shadow-sm transition-colors"
          >
            <span className="material-symbols-outlined text-[15px]">print</span>
            <span>Exporter en PDF</span>
          </button>
        </div>
      </div>

      {/* Risk Gauge & High-Level Summary Card */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Overall Risk & Score Gauge */}
        <div className="lg:col-span-5 bg-[#171b26] border border-[#24314c] rounded-lg p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-[#24314c]">
              <span className="font-mono text-xs font-bold text-[#dfe2f1] uppercase tracking-wider">
                Synthèse du Niveau de Menace
              </span>
              <span className="px-2 py-0.5 rounded bg-[#93000a]/30 text-[#ffb4ab] font-mono text-[11px] font-bold border border-[#ffb4ab]/30">
                RISQUE GLOBAL : ÉLEVÉ
              </span>
            </div>

            {/* Circular Gauge and Metrics */}
            <div className="flex items-center justify-center py-6 gap-6">
              <div className="relative w-32 h-32 flex items-center justify-center">
                <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
                  <circle cx="50" cy="50" r="40" stroke="#1c1f2a" strokeWidth="8" fill="none" />
                  <circle
                    cx="50"
                    cy="50"
                    r="40"
                    stroke="#ff5449"
                    strokeWidth="8"
                    strokeDasharray="251.2"
                    strokeDashoffset="65"
                    strokeLinecap="round"
                    fill="none"
                  />
                </svg>
                <div className="absolute flex flex-col items-center justify-center text-center font-mono">
                  <span className="text-3xl font-bold text-white">7.4</span>
                  <span className="text-[10px] text-[#ffb4ab] font-bold">CVSS BASE</span>
                </div>
              </div>

              <div className="flex flex-col gap-2 font-mono text-xs">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded bg-[#93000a]"></span>
                  <span className="text-[#c2c6d6]">3 Faiblesses Élevées (Exploitables)</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded bg-[#f59e0b]"></span>
                  <span className="text-[#c2c6d6]">7 Faiblesses Moyennes (Durcissement)</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded bg-[#3b82f6]"></span>
                  <span className="text-[#c2c6d6]">11 Faiblesses Faibles / Info</span>
                </div>
              </div>
            </div>
          </div>

          <div className="p-3 bg-[#0a0e18] rounded border border-[#24314c] font-mono text-xs text-[#8c909f] flex items-center justify-between">
            <span>Sceau cryptographique :</span>
            <span className="text-[#4cd7f6] font-bold">SHA-256: 8fa09...c1e92</span>
          </div>
        </div>

        {/* Right: Surface Cartography & Statistics */}
        <div className="lg:col-span-7 bg-[#171b26] border border-[#24314c] rounded-lg p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-[#24314c]">
              <span className="font-mono text-xs font-bold text-[#dfe2f1] uppercase tracking-wider">
                Cartographie de la Surface Évaluée
              </span>
              <span className="font-mono text-[11px] text-[#10b981]">100% Non-Destructif</span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4">
              <div className="bg-[#0a0e18] p-3 rounded border border-[#24314c] flex flex-col">
                <span className="font-mono text-[10px] text-[#8c909f]">Endpoints Découverts</span>
                <span className="font-mono text-xl font-bold text-[#dfe2f1] mt-1">137</span>
                <span className="font-mono text-[10px] text-[#4cd7f6]">70% GET • 30% POST</span>
              </div>
              <div className="bg-[#0a0e18] p-3 rounded border border-[#24314c] flex flex-col">
                <span className="font-mono text-[10px] text-[#8c909f]">Routes API V1</span>
                <span className="font-mono text-xl font-bold text-[#dfe2f1] mt-1">42</span>
                <span className="font-mono text-[10px] text-[#ffb4ab]">1 BOLA/IDOR critique</span>
              </div>
              <div className="bg-[#0a0e18] p-3 rounded border border-[#24314c] flex flex-col">
                <span className="font-mono text-[10px] text-[#8c909f]">Technologies</span>
                <span className="font-mono text-xl font-bold text-[#dfe2f1] mt-1">9</span>
                <span className="font-mono text-[10px] text-[#8c909f]">Nginx, Node, PG</span>
              </div>
              <div className="bg-[#0a0e18] p-3 rounded border border-[#24314c] flex flex-col">
                <span className="font-mono text-[10px] text-[#8c909f]">Vecteurs Testés</span>
                <span className="font-mono text-xl font-bold text-[#dfe2f1] mt-1">8</span>
                <span className="font-mono text-[10px] text-[#10b981]">0 Faux-positif</span>
              </div>
            </div>

            <div className="mt-4 p-3 bg-[#0a0e18] rounded border border-[#24314c] font-mono text-xs text-[#c2c6d6] leading-relaxed">
              <strong className="text-[#4cd7f6] block mb-1">Observation générale de l'audit :</strong>
              L'application présente une bonne posture de transport (TLS 1.3, certificats valides), mais souffre d'un défaut critique d'autorisation objet au niveau de l'API REST (/api/user/{'{id}'}) et d'une vulnérabilité d'injection SQL aveugle temporelle sur le paramètre de tri.
            </div>
          </div>

          <div className="pt-3 border-t border-[#24314c] flex items-center justify-between font-mono text-[11px] text-[#8c909f]">
            <span>Méthodologie : OWASP ASVS v4.0.3</span>
            <span>Validateur : ShadowScan Core Engine</span>
          </div>
        </div>
      </div>

      {/* Detailed Action Plan & Developer Remediations */}
      <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-6 shadow-sm flex flex-col gap-5">
        <div className="flex items-center justify-between pb-3 border-b border-[#24314c]">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-[20px] text-[#10b981]">build_circle</span>
            <h3 className="font-mono text-sm font-bold text-[#dfe2f1] uppercase tracking-wider">
              Plan d'Action Développeurs & Patchs de Remédiation
            </h3>
          </div>

          {/* Remediation Selectors */}
          <div className="flex items-center gap-1 font-mono text-xs">
            <button
              type="button"
              onClick={() => setActiveTabRemediation('idor')}
              className={`px-3 py-1 rounded transition-colors ${
                activeTabRemediation === 'idor'
                  ? 'bg-[#93000a]/40 text-[#ffb4ab] border border-[#ffb4ab]/40 font-bold'
                  : 'bg-[#0a0e18] text-[#8c909f] hover:text-[#dfe2f1]'
              }`}
            >
              1. Fix BOLA / IDOR (Express)
            </button>
            <button
              type="button"
              onClick={() => setActiveTabRemediation('sqli')}
              className={`px-3 py-1 rounded transition-colors ${
                activeTabRemediation === 'sqli'
                  ? 'bg-[#93000a]/40 text-[#ffb4ab] border border-[#ffb4ab]/40 font-bold'
                  : 'bg-[#0a0e18] text-[#8c909f] hover:text-[#dfe2f1]'
              }`}
            >
              2. Fix SQL Injection (PostgreSQL)
            </button>
            <button
              type="button"
              onClick={() => setActiveTabRemediation('csp')}
              className={`px-3 py-1 rounded transition-colors ${
                activeTabRemediation === 'csp'
                  ? 'bg-[#f59e0b]/20 text-[#fbbf24] border border-[#fbbf24]/30 font-bold'
                  : 'bg-[#0a0e18] text-[#8c909f] hover:text-[#dfe2f1]'
              }`}
            >
              3. Hardening Headers (Nginx)
            </button>
          </div>
        </div>

        {/* Remediation Code Patch Diff Container */}
        {activeTabRemediation === 'idor' && (
          <div className="flex flex-col gap-4 font-mono text-xs">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-[#ffb4ab] font-bold text-sm">
                  Priorité 1 (Immédiate) : Correction BOLA / IDOR sur GET /api/user/:id
                </span>
                <p className="text-[#8c909f] text-[11px] mt-0.5">
                  Ne jamais faire confiance à l'identifiant extrait des paramètres de route. Valider la session active.
                </p>
              </div>
              <span className="px-2 py-0.5 rounded bg-[#93000a]/40 text-[#ffb4ab] font-bold text-[10px]">
                CVSS 8.5
              </span>
            </div>

            {/* Side-by-side Code Patch Diff */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Avant: Vulnérable */}
              <div className="bg-[#0a0e18] border border-[#ffb4ab]/30 rounded overflow-hidden flex flex-col">
                <div className="bg-[#93000a]/20 px-3 py-1.5 text-[10px] text-[#ffb4ab] font-bold border-b border-[#ffb4ab]/30 flex items-center justify-between">
                  <span>AVANT (VULNÉRABLE - ACCÈS NON FILTRÉ)</span>
                  <span>Node.js / Express</span>
                </div>
                <pre className="p-3 text-[11px] text-[#ffdad6] overflow-x-auto whitespace-pre leading-relaxed select-text font-mono">
{`app.get('/api/user/:id', authenticateToken, async (req, res) => {
  // FAILLE: Utilise directement req.params.id sans vérifier
  // si le sujet authentifié (req.user.id) possède cette ressource.
  const targetId = req.params.id;
  const user = await db.users.findById(targetId);

  if (!user) return res.status(404).send('Non trouvé');
  // Fuite directe des données sensibles du tiers
  res.json(user);
});`}
                </pre>
              </div>

              {/* Après: Sécurisé */}
              <div className="bg-[#0a0e18] border border-[#10b981]/40 rounded overflow-hidden flex flex-col">
                <div className="bg-[#10b981]/20 px-3 py-1.5 text-[10px] text-[#10b981] font-bold border-b border-[#10b981]/40 flex items-center justify-between">
                  <span>APRÈS (SÉCURISÉ - CONTRÔLE D'AUTORISATION STRICT)</span>
                  <span>Node.js / Express</span>
                </div>
                <pre className="p-3 text-[11px] text-[#bbf7d0] overflow-x-auto whitespace-pre leading-relaxed select-text font-mono">
{`app.get('/api/user/:id', authenticateToken, async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  const currentUserId = req.user.id;
  const userRole = req.user.role;

  // CORRECTION: Vérification de possession stricte ou privilège admin
  if (currentUserId !== targetId && userRole !== 'admin') {
    return res.status(403).json({ error: 'Accès non autorisé à cette ressource' });
  }

  const user = await db.users.findById(targetId);
  if (!user) return res.status(404).send('Non trouvé');

  // Filtrage des champs sensibles (suppression api_key)
  const { api_key, password_hash, ...safeUser } = user;
  res.json(safeUser);
});`}
                </pre>
              </div>
            </div>
          </div>
        )}

        {activeTabRemediation === 'sqli' && (
          <div className="flex flex-col gap-4 font-mono text-xs">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-[#ffb4ab] font-bold text-sm">
                  Priorité 2 : Protection contre l'Injection SQL sur le tri (/api/v1/search)
                </span>
                <p className="text-[#8c909f] text-[11px] mt-0.5">
                  Utiliser impérativement une liste blanche (allowlist) pour les noms de colonnes et clauses de tri.
                </p>
              </div>
              <span className="px-2 py-0.5 rounded bg-[#93000a]/40 text-[#ffb4ab] font-bold text-[10px]">
                CVSS 8.2
              </span>
            </div>

            <div className="bg-[#0a0e18] border border-[#10b981]/40 rounded overflow-hidden flex flex-col">
              <div className="bg-[#10b981]/20 px-3 py-1.5 text-[10px] text-[#10b981] font-bold border-b border-[#10b981]/40 flex items-center justify-between">
                <span>SOLUTION RECOMMANDÉE (ALLOWLIST & PARAMÉTRAGE)</span>
                <span>TypeScript / ORM</span>
              </div>
              <pre className="p-3 text-[11px] text-[#bbf7d0] overflow-x-auto whitespace-pre leading-relaxed select-text font-mono">
{`const ALLOWED_SORT_COLUMNS = new Set(['name', 'created_at', 'price', 'popularity']);

app.get('/api/v1/search', async (req, res) => {
  const searchTerm = String(req.query.q || '');
  const requestedSort = String(req.query.sort || 'created_at');

  // Vérification stricte en liste blanche pour empêcher l'injection dans ORDER BY
  const safeSort = ALLOWED_SORT_COLUMNS.has(requestedSort) ? requestedSort : 'created_at';

  // Requête paramétrée (Prepared Statement)
  const results = await db.query(
    \`SELECT id, name, price FROM products WHERE name ILIKE $1 ORDER BY \${safeSort} ASC LIMIT 20\`,
    [\`%\${searchTerm}%\`]
  );
  res.json(results.rows);
});`}
              </pre>
            </div>
          </div>
        )}

        {activeTabRemediation === 'csp' && (
          <div className="flex flex-col gap-4 font-mono text-xs">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-[#fbbf24] font-bold text-sm">
                  Priorité 3 : Configuration des En-têtes HTTP de Sécurité
                </span>
                <p className="text-[#8c909f] text-[11px] mt-0.5">
                  Déploiement de la Content Security Policy et masquage des bannières logicielles.
                </p>
              </div>
              <span className="px-2 py-0.5 rounded bg-[#f59e0b]/20 text-[#fbbf24] font-bold text-[10px]">
                CVSS 5.3
              </span>
            </div>

            <div className="bg-[#0a0e18] border border-[#10b981]/40 rounded overflow-hidden flex flex-col">
              <div className="bg-[#10b981]/20 px-3 py-1.5 text-[10px] text-[#10b981] font-bold border-b border-[#10b981]/40 flex items-center justify-between">
                <span>DIRECTIVES DE SÉCURITÉ NGINX (nginx.conf)</span>
                <span>Configuration Reverse Proxy</span>
              </div>
              <pre className="p-3 text-[11px] text-[#bbf7d0] overflow-x-auto whitespace-pre leading-relaxed select-text font-mono">
{`# Masquer la version exacte du serveur web (Nginx)
server_tokens off;

# Bloquer l'exécution de scripts inline non autorisés
add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none';" always;

# Bloquer le chargement dans un iframe externe
add_header X-Frame-Options "SAMEORIGIN" always;

# Interdire les méthodes HTTP obsolètes ou dangereuses
if ($request_method = TRACE) {
    return 405;
}`}
              </pre>
            </div>
          </div>
        )}
      </div>

      {/* Ticket Modal */}
      {showIssueModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 font-sans">
          <div className="bg-[#171b26] border border-[#24314c] rounded-lg max-w-lg w-full p-5 shadow-2xl flex flex-col gap-4 font-mono text-xs">
            <div className="flex items-center justify-between pb-2 border-b border-[#24314c]">
              <span className="font-bold text-[#dfe2f1]">Générateur d'Issues Jira / GitHub</span>
              <button
                type="button"
                onClick={() => setShowIssueModal(false)}
                className="text-[#8c909f] hover:text-white"
              >
                <span className="material-symbols-outlined text-[16px]">close</span>
              </button>
            </div>
            <div className="bg-[#0a0e18] p-3 rounded border border-[#24314c] text-[11px] text-[#c2c6d6] flex flex-col gap-2">
              <div className="font-bold text-[#4cd7f6]">[SEC-P1] Fix BOLA/IDOR on GET /api/user/:id</div>
              <p>
                Description: Identified by ShadowScan Engine. User ID 104 can access data of User ID 105.
                <br />
                CVSS: 8.5 (HIGH) • CWE-639
                <br />
                Remediation: Validate session ownership before returning database record.
              </p>
            </div>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => {
                  navigator.clipboard.writeText(
                    `[SEC-P1] Fix BOLA/IDOR on GET /api/user/:id\nSeverity: HIGH (CVSS 8.5)\nCWE: CWE-639\nReported by: ShadowScan\nTarget: ${targetConfig.url}`
                  );
                  alert('Template de ticket copié dans le presse-papiers.');
                  setShowIssueModal(false);
                }}
                className="px-3 py-1.5 rounded bg-[#4d8eff] hover:bg-[#3b82f6] text-white font-bold"
              >
                Copier le Ticket
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
