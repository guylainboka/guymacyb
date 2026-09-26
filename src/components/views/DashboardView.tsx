import React, { useEffect, useState } from 'react';
import { ModuleView, TargetConfig, Finding } from '../../types';

interface DashboardViewProps {
  targetConfig: TargetConfig;
  findings: Finding[];
  onSelectView: (view: ModuleView) => void;
}

// NOTE: shape must match `/api/core/status` returned by `getCoreStatus()` in
// `src/server/toolbridge.ts`. The API returns:
//   platform, isWindows, wsl{available,distros,defaultDistro},
//   tools{available,missing}, python, node, memoryMb
interface CoreStatus {
  platform: string;
  isWindows: boolean;
  node: string;
  memoryMb?: number;
  python?: string | null;
  wsl?: { distros: any[]; defaultDistro: string | null; available: boolean } | null;
  tools?: { available: string[]; missing: string[] };
  error?: string;
}

// NOTE: shape must match `/api/dashboard/stats` returned by `server.ts`.
// The API returns a FLAT object (not nested under `totals`):
//   targets, scans, findings, bySeverity, recentFindings, recentTargets, engine, platform
interface DashboardStats {
  targets?: number;
  scans?: number;
  findings?: number;
  bySeverity?: Record<string, number>;
  recentFindings?: any[];
  recentTargets?: any[];
  engine?: string;
  platform?: string;
  error?: string;
}

const quickModules: { id: ModuleView; label: string; icon: string; desc: string; color: string }[] = [
  { id: 'scanner-and-recon', label: 'Scanner & Recon', icon: 'radar', desc: 'Reconnaissance cible & cartographie', color: 'text-[#4cd7f6]' },
  { id: 'reseau-local', label: 'Réseau Local', icon: 'lan', desc: 'mDNS / SSDP / NetBIOS / rDNS rootless', color: 'text-[#4cd7f6]' },
  { id: 'arsenal', label: 'Arsenal', icon: 'inventory_2', desc: 'SearchSploit + Hashcat', color: 'text-[#4d8eff]' },
  { id: 'geomac', label: 'GeoMac', icon: 'location_on', desc: 'OUI vendor + géoloc WiGLE/OSM', color: 'text-[#4cd7f6]' },
  { id: 'wifi-and-reseau', label: 'WiFi & Réseau', icon: 'wifi', desc: 'Scan AP, audit WPA, déauth', color: 'text-emerald-400' },
  { id: 'tests-actifs-and-attaque', label: 'Tests Actifs', icon: 'terminal', desc: 'Suite de tests contrôlés', color: 'text-[#ffb4ab]' },
  { id: 'resultats-and-preuves', label: 'Résultats & Preuves', icon: 'fact_check', desc: 'Vulnérabilités confirmées', color: 'text-amber-400' },
  { id: 'core-manager', label: 'Core Manager', icon: 'memory', desc: 'Statut pont WSL + outils', color: 'text-[#4d8eff]' },
  { id: 'terminal-integre', label: 'Terminal Intégré', icon: 'terminal', desc: 'bash / python / wsl / cmd', color: 'text-[#c2c6d6]' },
];

export const DashboardView: React.FC<DashboardViewProps> = ({ targetConfig, findings, onSelectView }) => {
  const [coreStatus, setCoreStatus] = useState<CoreStatus | null>(null);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loadingCore, setLoadingCore] = useState<boolean>(true);
  const [loadingStats, setLoadingStats] = useState<boolean>(true);
  const [coreError, setCoreError] = useState<string | null>(null);
  const [statsError, setStatsError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoadingCore(true);
      try {
        const res = await fetch('/api/core/status');
        const data = await res.json();
        if (!cancelled) setCoreStatus(data);
      } catch (e: any) {
        if (!cancelled) setCoreError(e?.message || 'Échec du chargement du statut du pont');
      } finally {
        if (!cancelled) setLoadingCore(false);
      }
    })();
    (async () => {
      setLoadingStats(true);
      try {
        const res = await fetch('/api/dashboard/stats');
        const data = await res.json();
        if (!cancelled) setStats(data);
      } catch (e: any) {
        if (!cancelled) setStatsError(e?.message || 'Échec du chargement des stats');
      } finally {
        if (!cancelled) setLoadingStats(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const maxCvss = findings.length > 0 ? Math.max(...findings.map((f) => f.cvss || 0)) : 0;
  const validatedCount = findings.filter((f) => f.status === 'VALIDATED').length;
  const highOrAbove = findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH').length;

  const fmtBytes = (mb: number) => {
    if (!Number.isFinite(mb)) return '—';
    if (mb >= 1024) return `${(mb / 1024).toFixed(1)} GB`;
    return `${Math.round(mb)} MB`;
  };

  // Derived helpers — the API does NOT return `bridge`/`tools.total`/`memory.total`/
  // `stats.totals.*`. Compute them locally so the dashboard cards are accurate.
  const toolInstalled = coreStatus?.tools ? coreStatus.tools.available.length : undefined;
  const toolTotal = coreStatus?.tools
    ? coreStatus.tools.available.length + coreStatus.tools.missing.length
    : undefined;
  const memMb = coreStatus?.memoryMb;
  const bridgeLabel = coreStatus
    ? coreStatus.isWindows
      ? (coreStatus.wsl?.available ? 'wsl.exe' : 'wsl (absent)')
      : 'linux-native'
    : 'détection...';

  return (
    <div className="h-full overflow-y-auto bg-[#0a0e18] text-[#dfe2f1] p-6">
      <div className="max-w-7xl mx-auto">
        {/* En-tête */}
        <div className="mb-6">
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <span className="material-symbols-outlined text-[#4d8eff]">dashboard</span>
            Dashboard — Centre d'Opérations
          </h1>
          <p className="text-sm text-[#8c909f] mt-1">
            Vue consolidée de la cible, du moteur, des findings récents et du pont WSL/Linux.
          </p>
        </div>

        {/* 4 Stat Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] text-[#8c909f] font-mono uppercase">Cible active</span>
              <span className="material-symbols-outlined text-[18px] text-[#4cd7f6]">target</span>
            </div>
            <div className="text-sm font-mono text-[#dfe2f1] truncate" title={targetConfig.url}>
              {targetConfig.url}
            </div>
            <div className="text-[11px] text-[#8c909f] font-mono mt-1">
              :{targetConfig.port} • scope {targetConfig.scope} • op {targetConfig.operatorId}
            </div>
          </div>

          <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] text-[#8c909f] font-mono uppercase">Findings</span>
              <span className="material-symbols-outlined text-[18px] text-amber-400">fact_check</span>
            </div>
            <div className="text-2xl font-bold text-[#dfe2f1]">{findings.length}</div>
            <div className="text-[11px] text-[#8c909f] font-mono mt-1">
              {validatedCount} validés • {highOrAbove} haut+critique
            </div>
          </div>

          <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] text-[#8c909f] font-mono uppercase">CVSS Max</span>
              <span className="material-symbols-outlined text-[18px] text-[#ffb4ab]">whatshot</span>
            </div>
            <div className="text-2xl font-bold text-[#ffb4ab]">{maxCvss.toFixed(1)}</div>
            <div className="text-[11px] text-[#8c909f] font-mono mt-1">
              {maxCvss >= 9 ? 'Critique' : maxCvss >= 7 ? 'Élevé' : maxCvss >= 4 ? 'Moyen' : 'Faible'}
            </div>
          </div>

          <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] text-[#8c909f] font-mono uppercase">Moteur</span>
              <span className="material-symbols-outlined text-[18px] text-emerald-400">memory</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="inline-block w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-sm font-medium text-emerald-400">Opérationnel</span>
            </div>
            <div className="text-[11px] text-[#8c909f] font-mono mt-1">
              Pont {bridgeLabel}
            </div>
          </div>
        </div>

        {/* Pont WSL + Tools status */}
        <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4 mb-6">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-[#dfe2f1] flex items-center gap-2">
              <span className="material-symbols-outlined text-[18px] text-[#4d8eff]">dns</span>
              Statut du Pont WSL / Linux natif
            </h2>
            <button
              onClick={() => onSelectView('core-manager')}
              className="text-[11px] text-[#4cd7f6] hover:text-[#dfe2f1] font-mono flex items-center gap-1 transition-colors"
              type="button"
            >
              Détails <span className="material-symbols-outlined text-[14px]">arrow_forward</span>
            </button>
          </div>

          {loadingCore ? (
            <div className="flex items-center gap-2 text-[#8c909f] text-sm">
              <span className="material-symbols-outlined animate-spin text-[18px]">progress_activity</span>
              Interrogation du pont...
            </div>
          ) : coreError ? (
            <div className="px-3 py-2 rounded bg-[#93000a]/20 border border-[#93000a]/40 text-[#ffb4ab] text-xs font-mono">
              {coreError}
            </div>
          ) : coreStatus ? (
            <div className="space-y-3">
              {coreStatus.error && (
                <div className="px-3 py-2 rounded bg-[#93000a]/20 border border-[#93000a]/40 text-[#ffb4ab] text-xs font-mono">
                  {coreStatus.error}
                </div>
              )}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div>
                  <div className="text-[10px] text-[#8c909f] font-mono uppercase">Plateforme</div>
                  <div className="font-mono text-[#dfe2f1]">{coreStatus.platform}{coreStatus.isWindows ? ' • Windows' : ''}</div>
                </div>
                <div>
                  <div className="text-[10px] text-[#8c909f] font-mono uppercase">Node</div>
                  <div className="font-mono text-[#dfe2f1]">{coreStatus.node}</div>
                </div>
                <div>
                  <div className="text-[10px] text-[#8c909f] font-mono uppercase">Outils installés</div>
                  <div className="font-mono text-emerald-400">
                    {toolInstalled !== undefined && toolTotal !== undefined ? `${toolInstalled}/${toolTotal}` : '—'}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-[#8c909f] font-mono uppercase">Mémoire (heap)</div>
                  <div className="font-mono text-[#dfe2f1]">
                    {memMb !== undefined ? fmtBytes(memMb) : '—'}
                  </div>
                </div>
              </div>

              {coreStatus.tools && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <div className="text-[10px] text-[#8c909f] font-mono uppercase mb-1">Disponibles</div>
                    <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto">
                      {coreStatus.tools.available.length > 0 ? coreStatus.tools.available.map((t) => (
                        <span key={t} className="px-1.5 py-0.5 text-[10px] font-mono rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">{t}</span>
                      )) : <span className="text-[10px] text-[#8c909f] font-mono">Aucun</span>}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] text-[#8c909f] font-mono uppercase mb-1">Manquants</div>
                    <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto">
                      {coreStatus.tools.missing.length > 0 ? coreStatus.tools.missing.map((t) => (
                        <span key={t} className="px-1.5 py-0.5 text-[10px] font-mono rounded bg-amber-500/10 border border-amber-500/30 text-amber-400">{t}</span>
                      )) : <span className="text-[10px] text-emerald-400 font-mono">Tous installés</span>}
                    </div>
                  </div>
                </div>
              )}

              {coreStatus.wsl && coreStatus.isWindows && (
                <div className="text-[11px] text-[#8c909f] font-mono">
                  WSL distro par défaut: <span className="text-[#4cd7f6]">{coreStatus.wsl.defaultDistro || '—'}</span>
                  {' • '}{coreStatus.wsl.distros.length} distro(s)
                </div>
              )}
            </div>
          ) : null}
        </div>

        {/* Dashboard stats (recent findings / targets) */}
        <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4 mb-6">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-[#dfe2f1] flex items-center gap-2">
              <span className="material-symbols-outlined text-[18px] text-[#4cd7f6]">insights</span>
              Statistiques SQLite (shadow_core.db)
            </h2>
          </div>

          {loadingStats ? (
            <div className="flex items-center gap-2 text-[#8c909f] text-sm">
              <span className="material-symbols-outlined animate-spin text-[18px]">progress_activity</span>
              Agrégation en cours...
            </div>
          ) : statsError ? (
            <div className="px-3 py-2 rounded bg-[#93000a]/20 border border-[#93000a]/40 text-[#ffb4ab] text-xs font-mono">
              {statsError}
            </div>
          ) : stats?.error ? (
            <div className="px-3 py-2 rounded bg-[#93000a]/20 border border-[#93000a]/40 text-[#ffb4ab] text-xs font-mono">
              {stats.error}
            </div>
          ) : stats ? (
            <div className="space-y-4">
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                <div className="bg-[#0a0e18] border border-[#24314c] rounded p-2">
                  <div className="text-[10px] text-[#8c909f] font-mono uppercase">Cibles</div>
                  <div className="text-lg font-bold text-[#4d8eff]">{stats.targets ?? 0}</div>
                </div>
                <div className="bg-[#0a0e18] border border-[#24314c] rounded p-2">
                  <div className="text-[10px] text-[#8c909f] font-mono uppercase">Findings</div>
                  <div className="text-lg font-bold text-amber-400">{stats.findings ?? 0}</div>
                </div>
                <div className="bg-[#0a0e18] border border-[#24314c] rounded p-2">
                  <div className="text-[10px] text-[#8c909f] font-mono uppercase">Scans</div>
                  <div className="text-lg font-bold text-[#4cd7f6]">{stats.scans ?? 0}</div>
                </div>
                <div className="bg-[#0a0e18] border border-[#24314c] rounded p-2">
                  <div className="text-[10px] text-[#8c909f] font-mono uppercase">Critique</div>
                  <div className="text-lg font-bold text-[#ffb4ab]">{stats.bySeverity?.CRITICAL ?? 0}</div>
                </div>
                <div className="bg-[#0a0e18] border border-[#24314c] rounded p-2">
                  <div className="text-[10px] text-[#8c909f] font-mono uppercase">High+</div>
                  <div className="text-lg font-bold text-red-400">{(stats.bySeverity?.HIGH ?? 0) + (stats.bySeverity?.CRITICAL ?? 0)}</div>
                </div>
              </div>

              {(stats.recentFindings && stats.recentFindings.length > 0) && (
                <div>
                  <div className="text-[10px] text-[#8c909f] font-mono uppercase mb-2">Findings récents</div>
                  <div className="max-h-48 overflow-y-auto space-y-1">
                    {stats.recentFindings.slice(0, 8).map((f, i) => (
                      <div key={f.id || i} className="flex items-center justify-between px-2 py-1.5 rounded bg-[#0a0e18] border border-[#24314c] text-xs">
                        <div className="truncate">
                          <span className={`font-mono px-1.5 py-0.5 rounded text-[10px] mr-2 ${
                            f.severity === 'CRITICAL' ? 'bg-[#93000a]/40 text-[#ffb4ab]' :
                            f.severity === 'HIGH' ? 'bg-red-500/10 border border-red-500/30 text-red-400' :
                            f.severity === 'MEDIUM' ? 'bg-amber-500/10 border border-amber-500/30 text-amber-400' :
                            'bg-sky-500/10 border border-sky-500/30 text-sky-400'
                          }`}>{f.severity}</span>
                          <span className="text-[#dfe2f1]">{f.title}</span>
                        </div>
                        <span className="text-[10px] text-[#8c909f] font-mono ml-2">CVSS {f.cvss}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {(stats.recentTargets && stats.recentTargets.length > 0) && (
                <div>
                  <div className="text-[10px] text-[#8c909f] font-mono uppercase mb-2">Cibles récentes</div>
                  <div className="max-h-40 overflow-y-auto space-y-1">
                    {stats.recentTargets.slice(0, 6).map((t, i) => (
                      <div key={t.id || i} className="flex items-center justify-between px-2 py-1.5 rounded bg-[#0a0e18] border border-[#24314c] text-xs">
                        <span className="font-mono text-[#4cd7f6] truncate">{t.url || t.domain}</span>
                        <span className="text-[10px] text-[#8c909f] font-mono ml-2">{(t as any).status || '—'}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {stats.engine && (
                <div className="text-[10px] text-[#8c909f] font-mono">Moteur: {stats.engine} • Plateforme: {stats.platform || '—'}</div>
              )}
            </div>
          ) : null}
        </div>

        {/* Modules grid — navigation rapide */}
        <div>
          <h2 className="text-sm font-semibold text-[#dfe2f1] flex items-center gap-2 mb-3">
            <span className="material-symbols-outlined text-[18px] text-[#4cd7f6]">apps</span>
            Modules — Navigation rapide
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {quickModules.map((m) => (
              <button
                key={m.id}
                onClick={() => onSelectView(m.id)}
                className="text-left bg-[#171b26] border border-[#24314c] rounded-lg p-4 hover:border-[#4cd7f6]/50 hover:bg-[#1b2030] transition-all group"
                type="button"
              >
                <div className="flex items-start gap-3">
                  <span className={`material-symbols-outlined text-[24px] ${m.color} group-hover:scale-110 transition-transform`}>
                    {m.icon}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-semibold text-[#dfe2f1]">{m.label}</div>
                    <div className="text-[11px] text-[#8c909f] mt-0.5">{m.desc}</div>
                  </div>
                  <span className="material-symbols-outlined text-[16px] text-[#8c909f] opacity-0 group-hover:opacity-100 transition-opacity">arrow_forward</span>
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
