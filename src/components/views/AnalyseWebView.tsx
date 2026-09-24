import React, { useState } from 'react';
import { EndpointItem } from '../../types';

interface AnalyseWebViewProps {
  endpointsTree: EndpointItem[];
  onTransferToAttack: () => void;
  onRescan: () => void;
  targetUrl: string;
}

export const AnalyseWebView: React.FC<AnalyseWebViewProps> = ({
  endpointsTree,
  onTransferToAttack,
  onRescan,
  targetUrl,
}) => {
  const [filterQuery, setFilterQuery] = useState<string>('');
  const [activeTab, setActiveTab] = useState<'headers' | 'tls' | 'cookies' | 'methods' | 'posture'>('headers');
  const [expandedNodes, setExpandedNodes] = useState<Record<string, boolean>>({
    'ep-root': true,
    'ep-api-parent': true,
  });
  const [selectedEndpoint, setSelectedEndpoint] = useState<EndpointItem | null>(null);

  const toggleNode = (id: string) => {
    setExpandedNodes((p) => ({ ...p, [id]: !p[id] }));
  };

  const filteredTree = endpointsTree.filter((item) => {
    if (!filterQuery) return true;
    const q = filterQuery.toLowerCase();
    const matchesSelf =
      item.path.toLowerCase().includes(q) ||
      item.method.toLowerCase().includes(q) ||
      item.statusText.toLowerCase().includes(q) ||
      (item.note && item.note.toLowerCase().includes(q));
    const matchesChild = item.children?.some(
      (c) =>
        c.path.toLowerCase().includes(q) ||
        c.method.toLowerCase().includes(q) ||
        (c.note && c.note.toLowerCase().includes(q))
    );
    return matchesSelf || matchesChild;
  });

  return (
    <div className="flex-1 overflow-y-auto p-5 flex flex-col gap-5 font-sans">
      {/* Operational Status Bar */}
      <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3.5 flex flex-wrap items-center justify-between gap-3 shadow-sm font-mono text-xs">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 px-2.5 py-1 bg-[#10b981]/15 border border-[#10b981]/30 rounded text-[#10b981]">
            <span className="w-2 h-2 rounded-full bg-[#10b981] animate-pulse"></span>
            <span className="font-bold">Terminé en 14.8s</span>
          </div>
          <span className="text-[#8c909f]">Profondeur crawler: 4</span>
          <span className="text-[#424754]">|</span>
          <span className="text-[#dfe2f1]">137 URLs inspectées</span>
          <span className="text-[#424754]">|</span>
          <span className="text-[#c2c6d6]">IP: 192.0.2.42</span>
          <span className="text-[#424754]">|</span>
          <span className="text-[#4cd7f6]">Origin: Nginx/1.24.0 (Ubuntu)</span>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => {
              const exportData = JSON.stringify(endpointsTree, null, 2);
              navigator.clipboard.writeText(exportData);
              alert('Cartographie exportée dans le presse-papiers (format JSON/HAR)');
            }}
            className="px-2.5 py-1 rounded bg-[#262a35] hover:bg-[#313540] text-[#c2c6d6] hover:text-white flex items-center gap-1.5 border border-[#424754] transition-colors"
          >
            <span className="material-symbols-outlined text-[14px]">file_download</span>
            <span>Export JSON / HAR</span>
          </button>
          <button
            type="button"
            onClick={onRescan}
            className="px-2.5 py-1 rounded bg-[#4d8eff] hover:bg-[#3b82f6] text-white flex items-center gap-1.5 shadow-sm transition-colors"
          >
            <span className="material-symbols-outlined text-[14px]">refresh</span>
            <span>Re-scanner</span>
          </button>
        </div>
      </div>

      {/* 4 Metrics KPI Bar Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1 */}
        <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-[#8c909f] font-mono text-xs">
              <span>Endpoints Découverts</span>
              <span className="material-symbols-outlined text-[16px] text-[#4cd7f6]">alt_route</span>
            </div>
            <div className="flex items-baseline gap-2 mt-2">
              <span className="text-2xl font-bold font-mono text-[#dfe2f1]">137</span>
              <span className="text-xs font-mono text-[#10b981]">+12 subpaths</span>
            </div>
          </div>
          <div className="mt-3">
            <div className="h-1.5 w-full bg-[#0a0e18] rounded-full overflow-hidden flex">
              <div style={{ width: '70%' }} className="bg-[#4cd7f6]" title="GET: 98"></div>
              <div style={{ width: '22%' }} className="bg-[#f59e0b]" title="POST: 31"></div>
              <div style={{ width: '8%' }} className="bg-[#ec4899]" title="PUT: 8"></div>
            </div>
            <div className="flex justify-between font-mono text-[10px] text-[#8c909f] mt-1.5">
              <span>GET 98</span>
              <span>POST 31</span>
              <span>PUT 8</span>
            </div>
          </div>
        </div>

        {/* Metric 2 */}
        <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-[#8c909f] font-mono text-xs">
              <span>Routes d'API Visibles</span>
              <span className="material-symbols-outlined text-[16px] text-[#3b82f6]">api</span>
            </div>
            <div className="flex items-baseline gap-2 mt-2">
              <span className="text-2xl font-bold font-mono text-[#dfe2f1]">42</span>
              <span className="text-xs font-mono text-[#8c909f]">/ 3 namespaces</span>
            </div>
          </div>
          <div className="mt-3 flex flex-col gap-1 font-mono text-[10px] text-[#c2c6d6]">
            <div className="flex items-center justify-between">
              <span className="truncate">/api/v1/auth</span>
              <span className="text-[#10b981]">OAUTH2</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="truncate">/api/v1/users/{'{id}'}</span>
              <span className="text-[#ffb4ab]">IDOR SUSP</span>
            </div>
          </div>
        </div>

        {/* Metric 3 */}
        <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-[#8c909f] font-mono text-xs">
              <span>Technologies Détectées</span>
              <span className="material-symbols-outlined text-[16px] text-[#10b981]">layers</span>
            </div>
            <div className="flex items-baseline gap-2 mt-2">
              <span className="text-2xl font-bold font-mono text-[#dfe2f1]">9</span>
              <span className="text-xs font-mono text-[#10b981]">Fingerprinted</span>
            </div>
          </div>
          <div className="mt-2 flex flex-wrap gap-1 font-mono text-[10px]">
            <span className="px-1.5 py-0.5 rounded bg-[#0a0e18] text-[#dfe2f1] border border-[#24314c]">
              Nginx 1.24
            </span>
            <span className="px-1.5 py-0.5 rounded bg-[#0a0e18] text-[#dfe2f1] border border-[#24314c]">
              Express
            </span>
            <span className="px-1.5 py-0.5 rounded bg-[#0a0e18] text-[#dfe2f1] border border-[#24314c]">
              PostgreSQL
            </span>
            <span className="px-1.5 py-0.5 rounded bg-[#0a0e18] text-[#dfe2f1] border border-[#24314c]">
              React 18
            </span>
          </div>
        </div>

        {/* Metric 4 */}
        <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-[#8c909f] font-mono text-xs">
              <span>Anomalies Détectées</span>
              <span className="material-symbols-outlined text-[16px] text-[#ffb4ab]">error_outline</span>
            </div>
            <div className="flex items-baseline gap-2 mt-2">
              <span className="text-2xl font-bold font-mono text-[#ffb4ab]">21</span>
              <span className="text-xs font-mono text-[#ffb4ab]">Alertes actives</span>
            </div>
          </div>
          <div className="mt-3 flex items-center justify-between font-mono text-[10px]">
            <span className="text-[#ffb4ab] font-bold">3 HIGH Exploitable</span>
            <span className="text-[#fbbf24]">7 MED Durcissement</span>
            <span className="text-[#8c909f]">11 LOW Info</span>
          </div>
        </div>
      </div>

      {/* Main Dual-Pane: Left Arborescence / Right Components Audit */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 flex-1 min-h-[480px]">
        {/* Left Column: Arborescence & Cartographie */}
        <div className="lg:col-span-6 bg-[#171b26] border border-[#24314c] rounded-lg flex flex-col overflow-hidden">
          <div className="p-3.5 bg-[#0a0e18] border-b border-[#24314c] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[18px] text-[#4cd7f6]">account_tree</span>
              <h3 className="font-mono text-xs font-bold text-[#dfe2f1] uppercase tracking-wider">
                Arborescence & Cartographie
              </h3>
            </div>
            <span className="font-mono text-[11px] text-[#8c909f]">137 Découvertes</span>
          </div>

          {/* Filter Bar */}
          <div className="p-3 border-b border-[#24314c] bg-[#171b26] flex items-center gap-2">
            <span className="material-symbols-outlined text-[16px] text-[#8c909f]">search</span>
            <input
              type="text"
              value={filterQuery}
              onChange={(e) => setFilterQuery(e.target.value)}
              placeholder="Filtrer endpoints (ex: /api, POST, 401)..."
              className="bg-transparent font-mono text-xs text-[#dfe2f1] focus:outline-none w-full"
            />
            {filterQuery && (
              <button
                type="button"
                onClick={() => setFilterQuery('')}
                className="text-[#8c909f] hover:text-white"
              >
                <span className="material-symbols-outlined text-[14px]">close</span>
              </button>
            )}
          </div>

          {/* Tree View */}
          <div className="flex-1 overflow-y-auto p-3 font-mono text-xs flex flex-col gap-1">
            <div className="text-[11px] text-[#8c909f] pb-1 flex items-center gap-1.5">
              <span className="material-symbols-outlined text-[14px] text-[#4cd7f6]">dns</span>
              <span>{targetUrl}</span>
            </div>

            {filteredTree.map((item) => {
              const isExpanded = expandedNodes[item.id];
              const isSelected = selectedEndpoint?.id === item.id;

              return (
                <div key={item.id} className="flex flex-col">
                  <div
                    onClick={() => {
                      if (item.children) {
                        toggleNode(item.id);
                      }
                      setSelectedEndpoint(item);
                    }}
                    className={`flex items-center justify-between px-2.5 py-1.5 rounded cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-[#262a35] text-white border border-[#4cd7f6]/40'
                        : 'hover:bg-[#1c1f2a] text-[#dfe2f1]'
                    }`}
                  >
                    <div className="flex items-center gap-2 truncate">
                      {item.children ? (
                        <span className="material-symbols-outlined text-[16px] text-[#8c909f]">
                          {isExpanded ? 'expand_more' : 'chevron_right'}
                        </span>
                      ) : (
                        <span className="w-4"></span>
                      )}

                      <span
                        className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                          item.method === 'GET'
                            ? 'bg-[#3b82f6]/20 text-[#60a5fa]'
                            : item.method === 'POST'
                            ? 'bg-[#f59e0b]/20 text-[#fbbf24]'
                            : 'bg-[#8b5cf6]/20 text-[#c084fc]'
                        }`}
                      >
                        {item.method}
                      </span>

                      <span className="font-medium truncate">{item.path}</span>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      {item.hasFinding && (
                        <span className="px-1.5 py-0.2 rounded bg-[#93000a]/40 text-[#ffb4ab] text-[10px] font-bold border border-[#ffb4ab]/30 animate-pulse">
                          {item.note || 'FINDING'}
                        </span>
                      )}
                      <span
                        className={`text-[11px] ${
                          item.status >= 400
                            ? 'text-[#f59e0b]'
                            : item.status === 200
                            ? 'text-[#10b981]'
                            : 'text-[#8c909f]'
                        }`}
                      >
                        {item.statusText}
                      </span>
                    </div>
                  </div>

                  {/* Render Children if folder is expanded */}
                  {item.children && isExpanded && (
                    <div className="pl-6 flex flex-col gap-1 mt-1 border-l border-[#24314c] ml-3">
                      {item.children.map((child) => (
                        <div
                          key={child.id}
                          onClick={() => setSelectedEndpoint(child)}
                          className={`flex items-center justify-between px-2.5 py-1.5 rounded cursor-pointer transition-colors ${
                            selectedEndpoint?.id === child.id
                              ? 'bg-[#262a35] text-white border border-[#4cd7f6]/40'
                              : 'hover:bg-[#1c1f2a] text-[#dfe2f1]'
                          }`}
                        >
                          <div className="flex items-center gap-2 truncate">
                            <span
                              className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                                child.method === 'GET'
                                  ? 'bg-[#3b82f6]/20 text-[#60a5fa]'
                                  : child.method === 'POST'
                                  ? 'bg-[#f59e0b]/20 text-[#fbbf24]'
                                  : 'bg-[#8b5cf6]/20 text-[#c084fc]'
                              }`}
                            >
                              {child.method}
                            </span>
                            <span className="truncate">{child.path}</span>
                          </div>

                          <div className="flex items-center gap-2 shrink-0">
                            {child.hasFinding && (
                              <span className="px-1.5 py-0.2 rounded bg-[#93000a]/40 text-[#ffb4ab] text-[10px] font-bold border border-[#ffb4ab]/30">
                                {child.note || 'FINDING'}
                              </span>
                            )}
                            <span className="text-[11px] text-[#f59e0b]">{child.statusText}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Audit des Composants Web with dynamic tabs */}
        <div className="lg:col-span-6 bg-[#171b26] border border-[#24314c] rounded-lg flex flex-col overflow-hidden">
          {/* Tabs bar */}
          <div className="bg-[#0a0e18] border-b border-[#24314c] flex overflow-x-auto text-xs font-mono">
            <button
              type="button"
              onClick={() => setActiveTab('headers')}
              className={`px-4 py-3 flex items-center gap-1.5 border-b-2 font-medium transition-colors ${
                activeTab === 'headers'
                  ? 'border-[#4cd7f6] text-[#4cd7f6] bg-[#171b26]'
                  : 'border-transparent text-[#8c909f] hover:text-[#dfe2f1]'
              }`}
            >
              <span className="material-symbols-outlined text-[15px]">badge</span>
              <span>Headers HTTP</span>
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('tls')}
              className={`px-4 py-3 flex items-center gap-1.5 border-b-2 font-medium transition-colors ${
                activeTab === 'tls'
                  ? 'border-[#4cd7f6] text-[#4cd7f6] bg-[#171b26]'
                  : 'border-transparent text-[#8c909f] hover:text-[#dfe2f1]'
              }`}
            >
              <span className="material-symbols-outlined text-[15px]">lock</span>
              <span>TLS & Certificats</span>
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('cookies')}
              className={`px-4 py-3 flex items-center gap-1.5 border-b-2 font-medium transition-colors ${
                activeTab === 'cookies'
                  ? 'border-[#4cd7f6] text-[#4cd7f6] bg-[#171b26]'
                  : 'border-transparent text-[#8c909f] hover:text-[#dfe2f1]'
              }`}
            >
              <span className="material-symbols-outlined text-[15px]">cookie</span>
              <span>Cookies</span>
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('methods')}
              className={`px-4 py-3 flex items-center gap-1.5 border-b-2 font-medium transition-colors ${
                activeTab === 'methods'
                  ? 'border-[#4cd7f6] text-[#4cd7f6] bg-[#171b26]'
                  : 'border-transparent text-[#8c909f] hover:text-[#dfe2f1]'
              }`}
            >
              <span className="material-symbols-outlined text-[15px]">code</span>
              <span>Méthodes HTTP</span>
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('posture')}
              className={`px-4 py-3 flex items-center gap-1.5 border-b-2 font-medium transition-colors ${
                activeTab === 'posture'
                  ? 'border-[#4cd7f6] text-[#4cd7f6] bg-[#171b26]'
                  : 'border-transparent text-[#8c909f] hover:text-[#dfe2f1]'
              }`}
            >
              <span className="material-symbols-outlined text-[15px]">security</span>
              <span>Posture Web</span>
            </button>
          </div>

          {/* Tab Contents */}
          <div className="flex-1 p-5 overflow-y-auto font-mono text-xs">
            {activeTab === 'headers' && (
              <div className="flex flex-col gap-3">
                <div className="p-3 bg-[#0a0e18] border border-[#ffb4ab]/30 rounded flex flex-col gap-1.5">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-[#ffb4ab]">Content-Security-Policy (CSP)</span>
                    <span className="px-2 py-0.5 rounded bg-[#93000a]/40 text-[#ffb4ab] text-[10px] font-bold">
                      MANQUANT
                    </span>
                  </div>
                  <p className="text-[11px] text-[#c2c6d6]">
                    Aucune politique CSP détectée. Les navigateurs exécuteront les scripts inline sans sandbox.
                  </p>
                </div>

                <div className="p-3 bg-[#0a0e18] border border-[#10b981]/30 rounded flex flex-col gap-1.5">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-[#10b981]">Strict-Transport-Security (HSTS)</span>
                    <span className="px-2 py-0.5 rounded bg-[#10b981]/20 text-[#10b981] text-[10px] font-bold">
                      VALIDE
                    </span>
                  </div>
                  <p className="text-[11px] text-[#8c909f]">
                    max-age=31536000; includeSubDomains; preload (Excellente configuration)
                  </p>
                </div>

                <div className="p-3 bg-[#0a0e18] border border-[#24314c] rounded flex flex-col gap-1.5">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-[#dfe2f1]">X-Frame-Options</span>
                    <span className="px-2 py-0.5 rounded bg-[#262a35] text-[#4cd7f6] text-[10px]">
                      SAMEORIGIN
                    </span>
                  </div>
                  <p className="text-[11px] text-[#8c909f]">Protection Clickjacking de base active.</p>
                </div>

                <div className="p-3 bg-[#0a0e18] border border-[#f59e0b]/30 rounded flex flex-col gap-1.5">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-[#fbbf24]">Server Header Leaked</span>
                    <span className="px-2 py-0.5 rounded bg-[#f59e0b]/20 text-[#fbbf24] text-[10px]">
                      INFO LEAK
                    </span>
                  </div>
                  <p className="text-[11px] text-[#8c909f]">nginx/1.24.0 (Ubuntu) — Recommandé de masquer</p>
                </div>
              </div>
            )}

            {activeTab === 'tls' && (
              <div className="flex flex-col gap-3">
                <div className="bg-[#0a0e18] p-3 rounded border border-[#24314c] flex flex-col gap-2">
                  <div className="flex items-center justify-between text-[#10b981] font-bold">
                    <span>Certificat X.509 Let's Encrypt Authority X3</span>
                    <span className="text-[11px]">Valide (expire dans 64 jours)</span>
                  </div>
                  <div className="text-[11px] text-[#8c909f] flex flex-col gap-1">
                    <span>Issuer: CN=R3, O=Let's Encrypt, C=US</span>
                    <span>SANs: example.com, *.example.com</span>
                    <span>Clé publique: RSA 2048 bits • SHA256withRSA</span>
                  </div>
                </div>

                <div className="bg-[#0a0e18] p-3 rounded border border-[#24314c] flex flex-col gap-1.5">
                  <span className="font-bold text-[#dfe2f1]">Protocoles supportés :</span>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="px-2 py-0.5 rounded bg-[#10b981]/20 text-[#10b981] text-[10px]">
                      TLS 1.3 (Activé)
                    </span>
                    <span className="px-2 py-0.5 rounded bg-[#10b981]/20 text-[#10b981] text-[10px]">
                      TLS 1.2 (Sécurisé)
                    </span>
                    <span className="px-2 py-0.5 rounded bg-[#262a35] text-[#8c909f] text-[10px] line-through">
                      TLS 1.0/1.1 (Désactivés)
                    </span>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'cookies' && (
              <div className="flex flex-col gap-3">
                <div className="bg-[#0a0e18] p-3 rounded border border-[#f59e0b]/30 flex flex-col gap-2">
                  <div className="flex items-center justify-between font-bold text-[#fbbf24]">
                    <span>Cookie: session_token</span>
                    <span className="px-2 py-0.5 rounded bg-[#f59e0b]/20 text-[10px]">MEDIUM RISK</span>
                  </div>
                  <div className="grid grid-cols-3 gap-2 text-[10px] text-center mt-1">
                    <span className="bg-[#10b981]/20 text-[#10b981] py-1 rounded">Secure: Oui</span>
                    <span className="bg-[#10b981]/20 text-[#10b981] py-1 rounded">HttpOnly: Oui</span>
                    <span className="bg-[#93000a]/30 text-[#ffb4ab] py-1 rounded">SameSite: None (!)</span>
                  </div>
                  <p className="text-[11px] text-[#8c909f] mt-1">
                    Attention : SameSite=None sans token anti-CSRF synchrone permet les requêtes cross-site forcées.
                  </p>
                </div>
              </div>
            )}

            {activeTab === 'methods' && (
              <div className="flex flex-col gap-3">
                <div className="bg-[#0a0e18] p-3 rounded border border-[#ffb4ab]/30 flex flex-col gap-2">
                  <div className="flex items-center justify-between font-bold text-[#ffb4ab]">
                    <span>Méthode HTTP TRACE activée</span>
                    <span className="px-2 py-0.5 rounded bg-[#93000a]/40 text-[10px]">XST VULN</span>
                  </div>
                  <p className="text-[11px] text-[#c2c6d6]">
                    Le serveur répond 200 OK avec le corps de la requête renvoyé. Cela permet des attaques Cross-Site Tracing pour contourner le drapeau HttpOnly.
                  </p>
                </div>
              </div>
            )}

            {activeTab === 'posture' && (
              <div className="flex flex-col gap-4">
                <div className="flex items-center justify-between bg-[#0a0e18] p-4 rounded border border-[#24314c]">
                  <div>
                    <span className="text-[#8c909f] text-[11px] block">Score de posture Web</span>
                    <span className="text-3xl font-bold text-[#f59e0b]">68 / 100</span>
                  </div>
                  <div className="text-right text-[11px] text-[#c2c6d6]">
                    <span className="text-[#ffb4ab] block font-bold">3 Faiblesses Prioritaires</span>
                    <span className="text-[#8c909f]">Tests actifs requis pour confirmation</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Bottom Transition Action Banner */}
      <div className="bg-gradient-to-r from-[#171b26] to-[#0a0e18] border border-[#3b82f6]/40 rounded-lg p-4 flex flex-wrap items-center justify-between gap-4 shadow-md font-mono text-xs">
        <div className="flex items-center gap-3">
          <span className="material-symbols-outlined text-[24px] text-[#4cd7f6]">verified_user</span>
          <div>
            <strong className="text-[#dfe2f1] font-bold block text-sm">
              Prêt pour la phase d'exploitation active — 137 cibles qualifiées
            </strong>
            <span className="text-[#8c909f] text-[11px]">
              Transférez les endpoints et paramètres découverts dans le moteur de validation contrôlée.
            </span>
          </div>
        </div>

        <button
          type="button"
          onClick={onTransferToAttack}
          className="flex items-center gap-2 px-5 py-2.5 rounded bg-[#4d8eff] hover:bg-[#3b82f6] text-white font-bold tracking-wide shadow-md transition-all hover:scale-[1.02]"
        >
          <span>Transférer vers le Module ATTAQUER / TESTER</span>
          <span className="material-symbols-outlined text-[16px]">arrow_forward</span>
        </button>
      </div>
    </div>
  );
};
