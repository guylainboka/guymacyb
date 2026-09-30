import React, { useEffect, useState, useCallback } from 'react';
import { ModuleView } from '../../types';

// ACCUEIL — remplace l'ancien dashboard. Doctrine :
//  - AUCUNE donnée inventée : tout vient de /api/system/status (droits admin +
//    matériel réel via CIM/WMI) et /api/core/status (WSL + outils réels).
//  - Pas d'historique, pas de suggestions, pas de compteurs fantômes.
//  - Hub de SERVICES : chaque carte = un module réel, avec son vrai prérequis.

interface SystemStatus {
  platform: string;
  admin?: { elevated: boolean; method: string; detail: string };
  hardware?: {
    os: string;
    cpu: { model: string; cores: number; loadPercent: number | null };
    ram: { totalMb: number; freeMb: number | null };
    hostname: string;
    error?: string;
  };
  error?: string;
}

interface CoreStatus {
  platform: string;
  isWindows: boolean;
  node: string;
  memoryMb?: number;
  python?: string | null;
  wsl?: {
    available: boolean;
    installed?: boolean;
    version?: string;
    reason?: string;
    distros: any[];
    defaultDistro: string | null;
  } | null;
  tools?: { available: string[]; missing: string[] };
  error?: string;
}

// Doit correspondre à DistroInstallStatus dans src/server/wsl.ts (API
// /api/core/install-distro/status) : état du job d'installation de la distro.
interface DistroJob {
  running: boolean;
  done: boolean;
  success: boolean;
  error: string;
  log: string[];
  distroName: string;
  startedAt: number | null;
  finishedAt: number | null;
}

const SERVICES: { id: ModuleView; label: string; icon: string; desc: string; req: 'none' | 'tools' | 'wsl' | 'wifi' }[] = [
  { id: 'scanner-and-recon', label: 'Scanner & Recon', icon: 'radar', desc: 'Reconnaissance cible, ports, DNS, TLS', req: 'none' },
  { id: 'analyse-web', label: 'Analyse Web', icon: 'language', desc: 'En-têtes de sécurité, endpoints, findings', req: 'none' },
  { id: 'reseau-local', label: 'Réseau Local', icon: 'lan', desc: 'Découverte mDNS / SSDP / NetBIOS / rDNS', req: 'none' },
  { id: 'tests-actifs-and-attaque', label: 'Tests Actifs', icon: 'bolt', desc: 'Suite active réelle (8 familles + fuzzing)', req: 'none' },
  { id: 'laboratoire-attaques', label: 'Lab Attaques Web', icon: 'science', desc: 'SQLi, XSS, SSRF, IDOR, JWT — sondes réelles', req: 'none' },
  { id: 'wifi-and-reseau', label: 'WiFi & Réseau', icon: 'wifi', desc: 'Scan AP, audit WPA, outils airmon', req: 'wifi' },
  { id: 'laboratoire-wifi', label: 'Lab Attaques WiFi', icon: 'settings_input_antenna', desc: 'Handshake, WPS, Evil Twin réel', req: 'wifi' },
  { id: 'arsenal', label: 'Arsenal', icon: 'inventory_2', desc: 'SearchSploit + Hashcat', req: 'tools' },
  { id: 'geomac', label: 'GeoMac', icon: 'location_on', desc: 'OUI vendor + géoloc WiGLE/OSM', req: 'none' },
  { id: 'hid-attacks', label: 'HID Attacks', icon: 'keyboard', desc: 'Payloads DuckyScript réels', req: 'none' },
  { id: 'usb-arsenal', label: 'USB Arsenal', icon: 'usb', desc: 'HID / storage / RNDIS / ECM / ACM', req: 'none' },
  { id: 'cameradar', label: 'Cameradar', icon: 'videocam', desc: 'RTSP + credentials par défaut', req: 'tools' },
  { id: 'terminal-integre', label: 'Terminal Intégré', icon: 'terminal', desc: 'PowerShell / CMD natifs, bash / python WSL', req: 'none' },
  { id: 'cours-and-notions', label: 'Cours & Notions', icon: 'school', desc: '14 notions cybersécurité', req: 'none' },
  { id: 'resultats-and-preuves', label: 'Résultats & Preuves', icon: 'fact_check', desc: 'Findings, CVSS v3.1, re-test réel', req: 'none' },
  { id: 'rapport-and-remediation', label: 'Rapport & Remédiation', icon: 'summarize', desc: 'Rapport consolidé, export SQLite/JSON', req: 'none' },
  { id: 'core-manager', label: 'Core Manager', icon: 'memory', desc: 'WSL, outils, assistant de configuration', req: 'none' },
];

const REQ_LABEL: Record<string, string> = {
  none: 'Prêt',
  tools: 'Outils Linux requis',
  wsl: 'WSL requis',
  wifi: 'WSL + clé WiFi monitor',
};

interface HomeViewProps {
  onSelectView: (view: ModuleView) => void;
}

export const HomeView: React.FC<HomeViewProps> = ({ onSelectView }) => {
  const [sys, setSys] = useState<SystemStatus | null>(null);
  const [core, setCore] = useState<CoreStatus | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [busy, setBusy] = useState<'' | 'install' | 'refresh' | 'distro'>('');
  const [actionOutput, setActionOutput] = useState<string>('');
  const [actionError, setActionError] = useState<string>('');
  const [distroJob, setDistroJob] = useState<DistroJob | null>(null);
  const mountedRef = React.useRef<boolean>(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [s, c] = await Promise.all([
        fetch('/api/system/status').then((r) => r.json()).catch(() => ({ error: 'injoignable' })),
        fetch('/api/core/status').then((r) => r.json()).catch(() => ({ error: 'injoignable' })),
      ]);
      setSys(s?.error ? null : s);
      setCore(c?.error ? null : c);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const refreshWsl = async () => {
    setBusy('refresh');
    setActionError('');
    setActionOutput('Re-détection WSL en cours…');
    try {
      const r = await fetch('/api/core/refresh-wsl', { method: 'POST' });
      const data = await r.json();
      if (data?.wsl) {
        setActionOutput(
          data.wsl.available
            ? `WSL opérationnel — distro : ${data.wsl.defaultDistro}${data.wsl.version ? ` (${data.wsl.version})` : ''}`
            : `WSL indisponible : ${data.wsl.reason || 'raison inconnue'}`
        );
      } else {
        setActionError(data?.error || 'Réponse inattendue du serveur');
      }
      await load();
    } catch (e: any) {
      setActionError(e?.message || 'API injoignable');
    } finally {
      setBusy('');
    }
  };

  const installTools = async () => {
    setBusy('install');
    setActionError('');
    setActionOutput('Installation apt en cours dans le distro WSL (peut prendre plusieurs minutes)…');
    try {
      const r = await fetch('/api/core/install-tools', { method: 'POST' });
      const data = await r.json();
      if (data?.verification) {
        const v = data.verification;
        setActionOutput(
          `Installation terminée (exit ${data.exitCode}). Outils vérifiés : ${v.verified.length} — absents : ${v.absent.length ? v.absent.join(', ') : 'aucun'}` +
            `\nRegistre : ${v.registryDir}`
        );
      } else if (data?.output) {
        setActionOutput(String(data.output).slice(-2000));
      } else {
        setActionError(data?.error || 'Réponse inattendue du serveur');
      }
      await load();
    } catch (e: any) {
      setActionError(e?.message || 'API injoignable');
    } finally {
      setBusy('');
    }
  };

  // État « WSL installé mais AUCUN distro Linux » : le cas signalé par
  // l'opérateur (wsl.exe répond, `wsl -l -v` vide) — bouton dédié requis.
  const toolsAvail = core?.tools?.available?.length ?? 0;
  const toolsTotal = toolsAvail + (core?.tools?.missing?.length ?? 0);
  const wslOk = core?.wsl?.available ?? false;
  const noDistro = Boolean(
    core?.isWindows && !wslOk && core?.wsl?.installed && (core?.wsl?.distros?.length ?? 0) === 0
  );

  const pollDistroStatus = async (): Promise<DistroJob | null> => {
    try {
      const r = await fetch('/api/core/install-distro/status');
      const data = await r.json();
      if (mountedRef.current) setDistroJob(data);
      return data as DistroJob;
    } catch {
      return null;
    }
  };

  const installDistro = async () => {
    setBusy('distro');
    setActionError('');
    setActionOutput('');
    try {
      const r = await fetch('/api/core/install-distro', { method: 'POST' });
      const data = await r.json();
      if (!r.ok) {
        setActionError(data?.error || 'Démarrage de l\'installation impossible');
        setBusy('');
        return;
      }
      // Polling du journal jusqu'à la fin du job (téléchargement + enregistrement).
      // Le boucle continue même si le composant est démonté/remonté : le job
      // vit côté serveur ; au remontage, useEffect relance le polling si besoin.
      for (;;) {
        await new Promise((s) => setTimeout(s, 2500));
        const st = await pollDistroStatus();
        if (!mountedRef.current) return;
        if (st?.done) break;
      }
      await load();
    } catch (e: any) {
      if (mountedRef.current) setActionError(e?.message || 'API injoignable');
    } finally {
      if (mountedRef.current) setBusy('');
    }
  };

  // Si un job est déjà en cours (page rafraîchie pendant l'installation),
  // on reprend le polling au montage.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const st = await pollDistroStatus();
      if (cancelled || !st?.running) return;
      setBusy('distro');
      for (;;) {
        await new Promise((s) => setTimeout(s, 2500));
        const cur = await pollDistroStatus();
        if (cancelled || !mountedRef.current) return;
        if (cur?.done) break;
      }
      if (!cancelled && mountedRef.current) {
        setBusy('');
        void load();
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const availabilityOf = (req: string): { ok: boolean; label: string } => {
    if (req === 'none') return { ok: true, label: 'Prêt' };
    if (req === 'tools') return { ok: toolsAvail > 0, label: REQ_LABEL.tools };
    if (req === 'wsl') return { ok: wslOk, label: REQ_LABEL.wsl };
    if (req === 'wifi') return { ok: wslOk && toolsAvail > 0, label: REQ_LABEL.wifi };
    return { ok: true, label: '' };
  };

  return (
    <div className="space-y-6">
      {/* ——— HERO ——— */}
      <section className="rounded-xl border border-[#232838] bg-gradient-to-br from-[#12151c] to-[#0d1017] p-6">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white md:text-3xl">Accueil — Guyma Cyb</h1>
            <p className="mt-1 text-sm text-[#8c909f]">
              Plateforme d'audit de sécurité — outils réels, matériels réels, autorisations réelles.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <StatusPill
              icon="dns"
              label="Backend"
              value={loading ? '…' : sys || core ? 'OPÉRATIONNEL' : 'INJOIGNABLE'}
              ok={!loading && (Boolean(sys) || Boolean(core))}
            />
            <StatusPill
              icon="admin_panel_settings"
              label="Droits admin"
              value={loading ? '…' : sys?.admin ? (sys.admin.elevated ? 'ÉLEVÉS' : 'NON ÉLEVÉS') : '—'}
              ok={Boolean(sys?.admin?.elevated)}
              title={sys?.admin?.detail}
            />
            <StatusPill
              icon="terminal"
              label="WSL"
              value={loading ? '…' : core?.isWindows ? (wslOk ? `OK · ${core.wsl?.defaultDistro}` : 'INDISPONIBLE') : 'Linux natif'}
              ok={core?.isWindows ? wslOk : Boolean(core)}
              title={core?.wsl?.reason}
            />
            <StatusPill
              icon="construction"
              label="Outils"
              value={loading ? '…' : `${toolsAvail}/${toolsTotal}`}
              ok={toolsAvail > 0}
            />
          </div>
        </div>

        {/* WSL installé mais AUCUN distro : panneau de correction en un clic */}
        {noDistro && (
          <div className="mt-4 rounded-lg border border-amber-500/30 bg-amber-500/10 p-4">
            <div className="flex items-start gap-3">
              <span className="material-symbols-outlined text-amber-400">dns</span>
              <div className="flex-1 text-sm text-amber-200">
                <strong>WSL est installé mais aucune distribution Linux n'est enregistrée.</strong>
                <div className="mt-1 text-xs text-amber-300/80">
                  C'est pour cela que les outils ne peuvent pas s'installer et que les terminaux restent inactifs.
                  Cliquez ci-dessous : le logiciel télécharge et enregistre Ubuntu tout seul (5 à 15 min selon la
                  connexion), sans aucune commande à taper. Si Windows demande une confirmation (UAC), acceptez-la.
                </div>
                <button
                  onClick={installDistro}
                  disabled={busy !== ''}
                  className="mt-3 flex min-h-[44px] items-center gap-2 rounded-lg border border-amber-400/40 bg-amber-500/20 px-4 py-2 text-sm font-semibold text-amber-100 transition hover:bg-amber-500/30 disabled:opacity-50"
                >
                  <span className="material-symbols-outlined text-base">download</span>
                  {busy === 'distro' ? 'Installation d\'Ubuntu en cours…' : 'Installer Ubuntu maintenant (un clic)'}
                </button>
              </div>
            </div>
            {distroJob && (distroJob.log.length > 0 || distroJob.running) && (
              <pre className="mt-3 max-h-56 overflow-y-auto whitespace-pre-wrap rounded-lg border border-amber-500/20 bg-[#0a0d13] p-3 text-xs text-amber-100/90 scrollbar-thin">
                {distroJob.log.join('\n')}
              </pre>
            )}
            {distroJob?.done && distroJob.error && (
              <div className="mt-2 text-xs text-red-300">✗ {distroJob.error}</div>
            )}
          </div>
        )}

        {/* Raison honnête si WSL indisponible (autres cas) */}
        {core?.isWindows && !wslOk && core?.wsl?.reason && !noDistro && (
          <div className="mt-4 flex items-start gap-3 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3">
            <span className="material-symbols-outlined text-amber-400">warning</span>
            <div className="text-sm text-amber-200">
              <strong>WSL indisponible —</strong> {core.wsl.reason}
              <div className="mt-1 text-xs text-amber-300/70">
                Les scans de base (HTTP, ports, DNS, TLS, réseau local) restent opérationnels sans WSL.
              </div>
            </div>
          </div>
        )}

        {/* Panneau système réel */}
        {sys?.hardware && (
          <div className="mt-4 grid grid-cols-1 gap-3 text-xs text-[#8c909f] sm:grid-cols-2 lg:grid-cols-4">
            <InfoChip icon="computer" label="Machine" value={`${sys.hardware.hostname || '—'}`} />
            <InfoChip icon="desktop_windows" label="OS" value={sys.hardware.os || sys.platform} />
            <InfoChip icon="memory" label="CPU" value={`${sys.hardware.cpu?.model?.slice(0, 40) || '—'} (${sys.hardware.cpu?.cores ?? '—'} cœurs)`} />
            <InfoChip
              icon="savings"
              label="RAM"
              value={sys.hardware.ram?.totalMb ? `${(sys.hardware.ram.totalMb / 1024).toFixed(1)} Go tot. · ${((sys.hardware.ram.freeMb ?? 0) / 1024).toFixed(1)} Go libres` : '—'}
            />
          </div>
        )}
        {sys?.hardware?.error && (
          <div className="mt-2 text-xs text-[#8c909f]">Inventaire matériel : {sys.hardware.error}</div>
        )}
      </section>

      {/* ——— ACTIONS DE MAINTENANCE ——— */}
      <section className="rounded-xl border border-[#232838] bg-[#12151c] p-5">
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-[#8c909f]">
          <span className="material-symbols-outlined text-base">build</span> Configuration système
        </h2>
        <div className="flex flex-wrap gap-3">
          <button
            onClick={refreshWsl}
            disabled={busy !== ''}
            className="flex min-h-[44px] items-center gap-2 rounded-lg border border-[#2c3245] bg-[#1a1f2b] px-4 py-2 text-sm font-medium text-white transition hover:border-[#4cd7f6]/50 hover:bg-[#1e2433] disabled:opacity-50"
          >
            <span className="material-symbols-outlined text-base">refresh</span>
            {busy === 'refresh' ? 'Détection…' : 'Re-détecter WSL'}
          </button>
          <button
            onClick={installTools}
            disabled={busy !== '' || (core?.isWindows && !wslOk)}
            className="flex min-h-[44px] items-center gap-2 rounded-lg border border-[#2c3245] bg-[#1a1f2b] px-4 py-2 text-sm font-medium text-white transition hover:border-[#4cd7f6]/50 hover:bg-[#1e2433] disabled:cursor-not-allowed disabled:opacity-50"
            title={
              core?.isWindows && !wslOk
                ? 'Nécessite une distribution WSL opérationnelle — installez d\'abord Ubuntu (bouton dédié ci-dessus)'
                : 'Installe nmap, nikto, aircrack-ng, hashcat… dans le distro WSL détecté, puis vérifie chaque outil et consigne le résultat dans tools-registry'
            }
          >
            <span className="material-symbols-outlined text-base">download</span>
            {busy === 'install' ? 'Installation…' : `Installer les outils Linux (${toolsTotal - toolsAvail} manquants)`}
          </button>
        </div>
        {(actionOutput || actionError) && (
          <pre className="mt-3 max-h-48 overflow-y-auto whitespace-pre-wrap rounded-lg border border-[#232838] bg-[#0a0d13] p-3 text-xs text-[#c2c6d6] scrollbar-thin">
{actionError ? `✗ ${actionError}` : actionOutput}
          </pre>
        )}
      </section>

      {/* ——— GRILLE DE SERVICES ——— */}
      <section>
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-[#8c909f]">
          <span className="material-symbols-outlined text-base">grid_view</span> Services ({SERVICES.length})
        </h2>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {SERVICES.map((s) => {
            const avail = availabilityOf(s.req);
            return (
              <button
                key={s.id}
                onClick={() => onSelectView(s.id)}
                className="group flex flex-col items-start gap-2 rounded-xl border border-[#232838] bg-[#12151c] p-4 text-left transition hover:border-[#4cd7f6]/50 hover:bg-[#161a24] focus:outline-none focus:ring-2 focus:ring-[#4cd7f6]/40"
              >
                <div className="flex w-full items-center justify-between">
                  <span className="material-symbols-outlined text-2xl text-[#4cd7f6] transition group-hover:text-white">
                    {s.icon}
                  </span>
                  <span
                    className={`rounded-full border px-2 py-0.5 text-[10px] font-medium ${
                      avail.ok
                        ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
                        : 'border-amber-500/30 bg-amber-500/10 text-amber-400'
                    }`}
                  >
                    {avail.ok ? 'Disponible' : avail.label}
                  </span>
                </div>
                <strong className="text-sm font-semibold text-white">{s.label}</strong>
                <span className="text-xs leading-relaxed text-[#8c909f]">{s.desc}</span>
              </button>
            );
          })}
        </div>
      </section>
    </div>
  );
};

// ---------------------------------------------------------------------------
//  Petits composants locaux
// ---------------------------------------------------------------------------

const StatusPill: React.FC<{ icon: string; label: string; value: string; ok: boolean; title?: string }> = ({
  icon,
  label,
  value,
  ok,
  title,
}) => (
  <div
    title={title}
    className={`flex items-center gap-2 rounded-lg border px-3 py-2 ${
      ok ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-[#232838] bg-[#0d1017]'
    }`}
  >
    <span className={`material-symbols-outlined text-lg ${ok ? 'text-emerald-400' : 'text-[#8c909f]'}`}>{icon}</span>
    <div className="leading-tight">
      <div className="text-[10px] uppercase tracking-wide text-[#8c909f]">{label}</div>
      <div className={`text-xs font-semibold ${ok ? 'text-emerald-300' : 'text-white'}`}>{value}</div>
    </div>
  </div>
);

const InfoChip: React.FC<{ icon: string; label: string; value: string }> = ({ icon, label, value }) => (
  <div className="flex items-center gap-2 rounded-lg border border-[#1d2230] bg-[#0d1017] px-3 py-2">
    <span className="material-symbols-outlined text-base text-[#4cd7f6]">{icon}</span>
    <div className="min-w-0 leading-tight">
      <div className="text-[10px] uppercase tracking-wide text-[#8c909f]">{label}</div>
      <div className="truncate text-xs text-[#c2c6d6]" title={value}>{value}</div>
    </div>
  </div>
);
