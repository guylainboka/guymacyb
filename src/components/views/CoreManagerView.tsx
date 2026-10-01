import React, { useCallback, useEffect, useState } from 'react';
import { ConfirmActionModal } from '../common/ConfirmActionModal';

interface WslDistro {
  name: string;
  state: string;
  version: string;
  default?: boolean;
}

// NOTE: shape must match `/api/core/status` returned by `getCoreStatus()` in
// `src/server/toolbridge.ts`. The API returns:
//   platform, isWindows, wsl{available,installed,reason,distros,defaultDistro},
//   tools{available,missing}, python, node, memoryMb
// There is NO `bridge`, `memory.total/free`, `tools.installed/total`, or
// `timestamp` field — these are derived locally from the real API fields.
interface CoreStatus {
  platform: string;
  isWindows: boolean;
  node: string;
  memoryMb?: number;
  python?: string | null;
  wsl?: { distros: WslDistro[]; defaultDistro: string | null; available: boolean; installed?: boolean; reason?: string } | null;
  tools?: { available: string[]; missing: string[] };
  error?: string;
}

// Doit correspondre à DistroInstallStatus dans src/server/wsl.ts
// (API /api/core/install-distro/status).
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

// NOTE: shape must match `/api/core/install-tools` returned by
// `installToolsViaApt()` in `src/server/toolbridge.ts`. The API returns:
//   { output: string, exitCode: number }
// There is NO `tool`/`installed`/`durationMs`/`error` field — derive locally.
interface InstallResult {
  output?: string;
  exitCode?: number;
  error?: string;
}

const fmtMb = (mb: number) => {
  if (!Number.isFinite(mb)) return '—';
  if (mb >= 1024) return `${(mb / 1024).toFixed(1)} GB`;
  return `${Math.round(mb)} MB`;
};

/* ============================================================================
 * Centre de mises à jour (V2) — détection 100 % RÉELLE, zéro simulation.
 * Doit correspondre à src/server/updates.ts (GET /api/updates/check).
 * ==========================================================================*/
interface AppUpdateInfo {
  current: string;
  latest: string | null;
  updateAvailable: boolean;
  releaseUrl: string | null;
  releaseName: string | null;
  publishedAt: string | null;
  notes: string | null;
  asset: { name: string; size: number; downloadUrl: string } | null;
  checkedAt: string;
  error: string | null;
}

interface ToolPackageStatus {
  package: string;
  installed: string | null;
  candidate: string | null;
  action: 'none' | 'upgrade' | 'install';
}

interface ToolsUpdateInfo {
  platform: string;
  isWindows: boolean;
  distro: string | null;
  packages: ToolPackageStatus[];
  upgradable: string[];
  missing: string[];
  checkedAt: string;
  error: string | null;
}

interface UpdatesPayload {
  app?: AppUpdateInfo;
  tools?: ToolsUpdateInfo;
  error?: string;
}

const fmtSize = (bytes: number) => {
  if (!Number.isFinite(bytes) || bytes <= 0) return '—';
  return `${(bytes / (1024 * 1024)).toFixed(1)} Mo`;
};

/**
 * UNE seule action d'application, précédée d'UN seul avertissement (accord).
 * Pas de choix successifs : Confirmer → tout s'exécute d'un bloc.
 */
const UpdatesCenter: React.FC<{ onRefreshCore: () => void }> = ({ onRefreshCore }) => {
  const [data, setData] = useState<UpdatesPayload | null>(null);
  const [checking, setChecking] = useState<boolean>(false);
  const [applying, setApplying] = useState<boolean>(false);
  const [confirmOpen, setConfirmOpen] = useState<boolean>(false);
  const [applyOutput, setApplyOutput] = useState<string>('');
  const [applyError, setApplyError] = useState<string>('');
  const [applySummary, setApplySummary] = useState<string>('');

  const check = useCallback(async () => {
    setChecking(true);
    try {
      const r = await fetch('/api/updates/check');
      const d: UpdatesPayload = await r.json();
      setData(d);
    } catch (e: any) {
      setData({ error: e?.message || 'API injoignable' });
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => { void check(); }, [check]);

  const app = data?.app;
  const tools = data?.tools;
  const upgradable = tools?.upgradable ?? [];
  const missing = tools?.missing ?? [];
  const todoCount = upgradable.length + missing.length;
  const nothingToDo = Boolean(tools && !tools.error && todoCount === 0);

  // UNE seule action : le POST applique périmés + manquants d'un bloc.
  const apply = async () => {
    setConfirmOpen(false);
    setApplying(true);
    setApplyError('');
    setApplySummary('');
    setApplyOutput('Application de la mise à jour en cours (apt-get dans la distribution — peut prendre plusieurs minutes)…');
    try {
      const r = await fetch('/api/updates/apply-tools', { method: 'POST' });
      const d = await r.json();
      if (!r.ok) {
        setApplyOutput('');
        setApplyError(d?.error || `Échec HTTP ${r.status}`);
      } else if (d.skipped === 'nothing-to-do') {
        setApplyOutput(d.output || 'Rien à mettre à jour.');
      } else {
        setApplyOutput(d.output || '(aucune sortie)');
        const v = d.verification;
        if (v) {
          setApplySummary(
            `Vérification réelle post-application : ${v.verified.length} outil(s) vérifié(s)` +
            (v.absent.length ? ` — absents : ${v.absent.join(', ')}` : ' — aucun absent')
          );
        }
        onRefreshCore();
        void check();
      }
    } catch (e: any) {
      setApplyOutput('');
      setApplyError(e?.message || 'API injoignable');
    } finally {
      setApplying(false);
    }
  };

  return (
    <div className="mb-6 rounded-lg border border-[#24314c] bg-[#171b26] p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-[18px] text-[#4d8eff]">system_update_alt</span>
          <h2 className="text-sm font-semibold text-[#dfe2f1]">Centre de mises à jour — logiciel &amp; outils</h2>
        </div>
        <button
          onClick={check}
          disabled={checking || applying}
          className="flex items-center gap-1.5 rounded border border-[#24314c] bg-[#0a0e18] px-3 py-1.5 text-xs text-[#c2c6d6] transition-colors hover:border-[#4d8eff]/50 disabled:opacity-50"
          type="button"
        >
          <span className={`material-symbols-outlined text-[16px] ${checking ? 'animate-spin' : ''}`}>refresh</span>
          {checking ? 'Vérification réelle…' : 'Vérifier les mises à jour'}
        </button>
      </div>

      {data?.error && (
        <div className="mb-3 rounded border border-[#93000a]/40 bg-[#93000a]/20 px-3 py-2 font-mono text-xs text-[#ffb4ab]">
          {data.error}
        </div>
      )}

      {/* — Logiciel : version réelle vs dernière release GitHub — */}
      <div className="mb-4 rounded border border-[#24314c] bg-[#0a0e18] p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-[18px] text-[#4cd7f6]">desktop_windows</span>
            <div>
              <div className="text-xs font-semibold text-[#dfe2f1]">Logiciel Guyma Cyb</div>
              <div className="font-mono text-[11px] text-[#8c909f]">
                Version installée : <span className="text-[#c2c6d6]">{app?.current ?? 'détection…'}</span>
                {app?.latest ? <> · Dernière release : <span className="text-[#c2c6d6]">v{app.latest}</span></> : null}
              </div>
            </div>
          </div>
          {app?.error ? (
            <span className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 font-mono text-[10px] text-amber-400" title={app.error}>
              Vérification indisponible
            </span>
          ) : app?.updateAvailable ? (
            <span className="flex items-center gap-1.5 rounded border border-[#4d8eff]/40 bg-[#4d8eff]/15 px-2 py-0.5 text-[10px] font-semibold text-[#4d8eff]">
              <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-[#4d8eff]" />
              Mise à jour v{app.latest} disponible
            </span>
          ) : app ? (
            <span className="flex items-center gap-1.5 rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-400">
              <span className="material-symbols-outlined text-[12px]">check_circle</span>
              À jour
            </span>
          ) : null}
        </div>
        {app?.updateAvailable && (
          <div className="mt-2 flex flex-wrap items-center gap-3">
            <button
              onClick={() => { if (app.releaseUrl) window.open(app.releaseUrl, '_blank', 'noopener'); }}
              className="flex items-center gap-1.5 rounded border border-[#4d8eff]/40 bg-[#4d8eff]/15 px-3 py-1.5 text-xs font-medium text-[#4d8eff] transition-colors hover:bg-[#4d8eff]/25"
              type="button"
            >
              <span className="material-symbols-outlined text-[16px]">open_in_new</span>
              Télécharger la v{app.latest}
            </button>
            {app.asset && (
              <span className="font-mono text-[10px] text-[#8c909f]" title={app.asset.downloadUrl}>
                {app.asset.name} · {fmtSize(app.asset.size)}
              </span>
            )}
          </div>
        )}
        {app?.error && <div className="mt-2 font-mono text-[11px] text-amber-400/80">{app.error}</div>}
      </div>

      {/* — Outils : versions réelles Installed/Candidate — */}
      <div className="rounded border border-[#24314c] bg-[#0a0e18] p-3">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-[18px] text-[#4cd7f6]">build</span>
            <div className="text-xs font-semibold text-[#dfe2f1]">Outils Linux (apt — versions réelles)</div>
          </div>
          {tools && !tools.error && (
            <div className="font-mono text-[10px] text-[#8c909f]">
              <span className="text-amber-400">{upgradable.length} périmé(s)</span> · <span className="text-amber-300">{missing.length} absent(s)</span> · distro : {tools.distro ?? '—'}
            </div>
          )}
        </div>

        {tools?.error ? (
          <div className="rounded border border-amber-500/30 bg-amber-500/10 px-3 py-2 font-mono text-xs text-amber-400">
            {tools.error}
          </div>
        ) : tools ? (
          <>
            <div className="max-h-64 overflow-y-auto rounded border border-[#24314c]">
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-[#0a0e18]">
                  <tr className="font-mono text-[10px] uppercase text-[#8c909f]">
                    <th className="px-2 py-1 text-left">Paquet</th>
                    <th className="px-2 py-1 text-left">Installée</th>
                    <th className="px-2 py-1 text-left">Candidate</th>
                    <th className="px-2 py-1 text-left">État</th>
                  </tr>
                </thead>
                <tbody>
                  {tools.packages.map((p) => (
                    <tr key={p.package} className="border-t border-[#24314c] font-mono text-[11px]">
                      <td className="px-2 py-1 text-[#dfe2f1]">{p.package}</td>
                      <td className="px-2 py-1 text-[#c2c6d6]">{p.installed ?? <span className="text-[#8c909f]">(absent)</span>}</td>
                      <td className="px-2 py-1 text-[#c2c6d6]">{p.candidate ?? '—'}</td>
                      <td className="px-2 py-1">
                        {p.action === 'upgrade' ? (
                          <span className="rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 text-[10px] text-amber-400">périmé</span>
                        ) : p.action === 'install' ? (
                          <span className="rounded border border-amber-400/30 bg-amber-400/10 px-1.5 py-0.5 text-[10px] text-amber-300">absent</span>
                        ) : !p.installed ? (
                          <span className="rounded border border-[#434655] bg-[#201f22] px-1.5 py-0.5 text-[10px] text-[#8c909f]" title="Absent et sans candidate dans les dépôts apt de cette distribution">
                            indisponible
                          </span>
                        ) : (
                          <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-1.5 py-0.5 text-[10px] text-emerald-400">à jour</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* UNE seule action + UNE confirmation (accord) — pas de choix successifs */}
            <div className="mt-3 flex flex-wrap items-center gap-3">
              <button
                onClick={() => setConfirmOpen(true)}
                disabled={applying || checking || nothingToDo || Boolean(tools.error)}
                title={
                  nothingToDo
                    ? 'Tous les paquets sont à jour et aucun n\'est manquant'
                    : `Met à jour ${upgradable.length} paquet(s) périmé(s) et installe ${missing.length} manquant(s) en UNE commande apt`
                }
                className="flex items-center gap-2 rounded border border-[#4d8eff]/40 bg-[#4d8eff]/15 px-4 py-2 text-sm font-medium text-[#4d8eff] transition-colors hover:bg-[#4d8eff]/25 disabled:cursor-not-allowed disabled:opacity-50"
                type="button"
              >
                <span className={`material-symbols-outlined text-[18px] ${applying ? 'animate-spin' : ''}`}>
                  {applying ? 'progress_activity' : 'download_for_offline'}
                </span>
                {applying ? 'Mise à jour en cours…' : 'Tout mettre à jour maintenant'}
              </button>
              <span className="font-mono text-[11px] text-[#8c909f]">
                UNE confirmation, puis tout s'applique d'un bloc via <code>apt-get install</code>.
              </span>
            </div>
          </>
        ) : (
          <div className="font-mono text-xs text-[#8c909f]">Interrogation d'apt en cours (les dépôts sont rafraîchis réellement)…</div>
        )}
      </div>

      {(applyOutput || applyError || applySummary) && (
        <div className="mt-3">
          {applyError && (
            <div className="mb-2 rounded border border-[#93000a]/40 bg-[#93000a]/20 px-3 py-2 font-mono text-xs text-[#ffb4ab]">✗ {applyError}</div>
          )}
          {applySummary && (
            <div className="mb-2 rounded border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 font-mono text-xs text-emerald-300">{applySummary}</div>
          )}
          {applyOutput && (
            <pre className="max-h-64 overflow-y-auto whitespace-pre-wrap break-all rounded border border-[#24314c] bg-[#0a0e18] p-3 font-mono text-[11px] text-[#c2c6d6]">
{applyOutput}
            </pre>
          )}
        </div>
      )}

      {/* Avertissement unique (accord) avant l'action — UN seul écran, puis exécution directe */}
      <ConfirmActionModal
        open={confirmOpen}
        title="Avertissement — action unique"
        busy={applying}
        confirmLabel="Confirmer et appliquer"
        onConfirm={apply}
        onCancel={() => setConfirmOpen(false)}
      >
        <p className="text-sm leading-relaxed text-[#c2c6d6]">
          Le logiciel va appliquer <strong className="text-white">tout d'un bloc</strong> via{' '}
          <code className="font-mono text-[#4cd7f6]">apt-get install</code> dans la distribution{' '}
          <strong className="text-white">{tools?.distro ?? 'WSL'}</strong> :
        </p>
        <ul className="mt-2 space-y-1 font-mono text-xs text-[#c2c6d6]">
          <li>• Mettre à jour <span className="text-amber-400">{upgradable.length}</span> paquet(s) périmé(s)</li>
          <li>• Installer <span className="text-amber-300">{missing.length}</span> paquet(s) absent(s)</li>
        </ul>
        <p className="mt-3 text-xs text-[#8c909f]">
          L'opération peut prendre plusieurs minutes (téléchargement des dépôts et des paquets).
          La sortie réelle d'apt sera affichée ensuite. Aucune donnée n'est détruite : il s'agit
          d'installation/mise à jour de paquets.
        </p>
      </ConfirmActionModal>
    </div>
  );
};

interface CoreManagerViewProps {
  /** V2 : ouvre l'assistant d'installation in-app (overlay) hors Electron. */
  onOpenAssistant?: () => void;
}

export const CoreManagerView: React.FC<CoreManagerViewProps> = ({ onOpenAssistant }) => {
  const [status, setStatus] = useState<CoreStatus | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [installing, setInstalling] = useState<boolean>(false);
  const [installResult, setInstallResult] = useState<InstallResult | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/core/status');
      const data = await res.json();
      setStatus(data);
    } catch (e: any) {
      setError(e?.message || 'Échec du chargement du statut du pont');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const handleInstall = async () => {
    setInstalling(true);
    setInstallResult(null);
    try {
      const res = await fetch('/api/core/install-tools', { method: 'POST' });
      const data = await res.json();
      // The API returns { output, exitCode } on success (200) or { error } on 500.
      // We normalise the shape so the renderer can read `installed`/`error` cleanly.
      if (!res.ok) {
        setInstallResult({ error: data?.error || `Échec HTTP ${res.status}` });
      } else {
        setInstallResult({
          output: data.output,
          exitCode: data.exitCode,
          error: data.error,
        });
      }
      // Recharger le statut après installation
      void refresh();
    } catch (e: any) {
      setInstallResult({ error: e?.message || 'Échec de l\'installation' });
    } finally {
      setInstalling(false);
    }
  };

  // Ouvre l'assistant de configuration (wizard) à la demande : installe WSL
  // (avec élévation UAC) et les outils Linux manquants. Le wizard tourne dans
  // une fenêtre séparée — l'app continue de fonctionner. Une fois le wizard
  // terminé, on rafraîchit le statut pour refléter WSL + outils installés.
  const openSetupWizard = async () => {
    try {
      const w = (window as any).guymacybWindow;
      if (w && typeof w.openSetupWizard === 'function') {
        await w.openSetupWizard();
        // Petit délai puis rafraîchissement (le wizard peut prendre du temps).
        // On rafraîchit aussi à chaque focus de fenêtre principale ci-dessous.
        setTimeout(() => void refresh(), 2000);
      } else if (typeof onOpenAssistant === 'function') {
        // V2 : hors Electron, on ouvre l'assistant d'installation in-app
        // (même design, mêmes APIs HTTP réelles) au lieu d'une erreur.
        onOpenAssistant();
      } else {
        setError('Assistant indisponible hors du logiciel desktop. Lancez « wsl --install » dans PowerShell (admin) puis réessayez.');
      }
    } catch (e: any) {
      setError(e?.message || 'Impossible d\'ouvrir l\'assistant de configuration');
    }
  };

  // État « WSL installé mais AUCUN distro » : installation d'Ubuntu en un clic
  // via l'API HTTP (marche aussi hors Electron), avec journal en direct.
  const [distroJob, setDistroJob] = useState<DistroJob | null>(null);
  const [distroBusy, setDistroBusy] = useState<boolean>(false);
  const mountedRef = React.useRef<boolean>(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

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

  const handleInstallDistro = async () => {
    setDistroBusy(true);
    setError(null);
    try {
      const r = await fetch('/api/core/install-distro', { method: 'POST' });
      const data = await r.json();
      if (!r.ok) {
        setError(data?.error || 'Démarrage de l\'installation impossible');
        setDistroBusy(false);
        return;
      }
      for (;;) {
        await new Promise((s) => setTimeout(s, 2500));
        const st = await pollDistroStatus();
        if (!mountedRef.current) return;
        if (st?.done) break;
      }
      if (mountedRef.current) await refresh();
    } catch (e: any) {
      if (mountedRef.current) setError(e?.message || 'API injoignable');
    } finally {
      if (mountedRef.current) setDistroBusy(false);
    }
  };

  // Reprend le polling si un job tourne déjà (page rafraîchie pendant l'install).
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const st = await pollDistroStatus();
      if (cancelled || !st?.running) return;
      setDistroBusy(true);
      for (;;) {
        await new Promise((s) => setTimeout(s, 2500));
        const cur = await pollDistroStatus();
        if (cancelled || !mountedRef.current) return;
        if (cur?.done) break;
      }
      if (!cancelled && mountedRef.current) {
        setDistroBusy(false);
        void refresh();
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Rafraîchit automatiquement le statut quand la fenêtre principale regagne
  // le focus (l'utilisateur a peut-être installé WSL/outils via le wizard).
  useEffect(() => {
    const onFocus = () => void refresh();
    window.addEventListener('focus', onFocus);
    return () => window.removeEventListener('focus', onFocus);
  }, [refresh]);

  const tools = status?.tools;
  const wsl = status?.wsl;
  // Derived — the API does NOT return `tools.installed`/`tools.total`/`memory.total`/
  // `bridge`/`timestamp`. Compute them locally from the real fields.
  const toolInstalled = tools ? tools.available.length : undefined;
  const toolTotal = tools ? tools.available.length + tools.missing.length : undefined;
  const memMb = status?.memoryMb;
  const bridgeLabel = status
    ? status.isWindows
      ? (status.wsl?.available ? 'wsl.exe' : 'wsl (absent)')
      : 'linux-native'
    : 'détection...';

  return (
    <div className="h-full overflow-y-auto bg-[#0a0e18] text-[#dfe2f1] p-6">
      <div className="max-w-7xl mx-auto">
        {/* En-tête */}
        <div className="mb-6 flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <span className="material-symbols-outlined text-[#4d8eff]">memory</span>
              Core Manager — Pont WSL & Outillage Linux
            </h1>
            <p className="text-sm text-[#8c909f] mt-1">
              Statut réel du pont d'exécution Linux, des outils installés et de la stratégie 3-étapes.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={refresh}
              disabled={loading}
              className="px-3 py-1.5 text-xs rounded bg-[#171b26] border border-[#24314c] hover:border-[#4d8eff]/50 text-[#c2c6d6] flex items-center gap-1.5 transition-colors disabled:opacity-50"
              type="button"
            >
              <span className={`material-symbols-outlined text-[16px] ${loading ? 'animate-spin' : ''}`}>refresh</span>
              Vérifier l'état
            </button>
            <button
              onClick={openSetupWizard}
              className="px-3 py-1.5 text-xs rounded bg-[#4d8eff]/15 border border-[#4d8eff]/40 hover:bg-[#4d8eff]/25 text-[#4d8eff] flex items-center gap-1.5 transition-colors"
              type="button"
              title="Ouvre l'assistant de configuration : installe WSL (avec élévation UAC) et les outils Linux manquants"
            >
              <span className="material-symbols-outlined text-[16px]">tune</span>
              Assistant de configuration
            </button>
          </div>
        </div>

        {/* Info card — stratégie 3 étapes */}
        <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4 mb-6">
          <div className="flex items-center gap-2 mb-3">
            <span className="material-symbols-outlined text-[18px] text-[#4cd7f6]">schema</span>
            <h2 className="text-sm font-semibold text-[#dfe2f1]">Stratégie du pont d'exécution (3 étapes)</h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="bg-[#0a0e18] border border-[#24314c] rounded p-3">
              <div className="flex items-center gap-2 mb-1">
                <span className="w-5 h-5 rounded-full bg-[#4d8eff]/20 border border-[#4d8eff]/40 text-[#4d8eff] font-mono text-[10px] flex items-center justify-center">1</span>
                <span className="text-xs font-semibold text-[#dfe2f1]">Sélection hôte</span>
              </div>
              <p className="text-[11px] text-[#8c909f] font-mono leading-relaxed">
                Détection OS: Windows → pont WSL ; Linux natif → exécution directe.
              </p>
            </div>
            <div className="bg-[#0a0e18] border border-[#24314c] rounded p-3">
              <div className="flex items-center gap-2 mb-1">
                <span className="w-5 h-5 rounded-full bg-[#4cd7f6]/20 border border-[#4cd7f6]/40 text-[#4cd7f6] font-mono text-[10px] flex items-center justify-center">2</span>
                <span className="text-xs font-semibold text-[#dfe2f1]">Wrap & exec</span>
              </div>
              <p className="text-[11px] text-[#8c909f] font-mono leading-relaxed">
                Script bash wrappé puis exécuté via <code>wsl.exe -d Ubuntu</code> (Windows) ou <code>bash</code> direct (Linux).
              </p>
            </div>
            <div className="bg-[#0a0e18] border border-[#24314c] rounded p-3">
              <div className="flex items-center gap-2 mb-1">
                <span className="w-5 h-5 rounded-full bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 font-mono text-[10px] flex items-center justify-center">3</span>
                <span className="text-xs font-semibold text-[#dfe2f1]">JSON parsing</span>
              </div>
              <p className="text-[11px] text-[#8c909f] font-mono leading-relaxed">
                Sortie JSON parsée côté Node, renvoyée au front. Exécution 100% réelle.
              </p>
            </div>
          </div>
        </div>

        {/* ——— V2 : Centre de mises à jour (logiciel + outils, données réelles) ——— */}
        <UpdatesCenter onRefreshCore={refresh} />

        {loading ? (
          <div className="flex items-center gap-2 text-[#8c909f] text-sm py-8">
            <span className="material-symbols-outlined animate-spin text-[18px]">progress_activity</span>
            Interrogation du pont...
          </div>
        ) : error ? (
          <div className="px-4 py-3 mb-4 rounded bg-[#93000a]/20 border border-[#93000a]/40 text-[#ffb4ab] text-sm font-mono flex items-start gap-2">
            <span className="material-symbols-outlined text-[18px]">error</span>
            <div>
              <div className="font-semibold mb-0.5">Pont injoignable</div>
              <div className="text-[12px]">{error}</div>
            </div>
          </div>
        ) : status ? (
          <>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
              {/* Platform card */}
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4">
                <div className="flex items-center gap-2 mb-3">
                  <span className="material-symbols-outlined text-[18px] text-[#4d8eff]">computer</span>
                  <h2 className="text-sm font-semibold text-[#dfe2f1]">Plateforme hôte</h2>
                </div>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-[#8c909f] font-mono text-xs">OS</span>
                    <span className="font-mono text-[#dfe2f1]">{status.platform}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#8c909f] font-mono text-xs">Windows ?</span>
                    <span className={`font-mono ${status.isWindows ? 'text-[#4d8eff]' : 'text-emerald-400'}`}>
                      {status.isWindows ? 'Oui (pont WSL requis)' : 'Non'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#8c909f] font-mono text-xs">Node</span>
                    <span className="font-mono text-[#dfe2f1]">{status.node}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#8c909f] font-mono text-xs">Mémoire (heap)</span>
                    <span className="font-mono text-[#dfe2f1]">
                      {memMb !== undefined ? fmtMb(memMb) : '—'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#8c909f] font-mono text-xs">Mode pont</span>
                    <span className="font-mono text-[#4cd7f6]">{bridgeLabel}</span>
                  </div>
                </div>
              </div>

              {/* WSL card */}
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4">
                <div className="flex items-center gap-2 mb-3">
                  <span className="material-symbols-outlined text-[18px] text-[#4cd7f6]">dns</span>
                  <h2 className="text-sm font-semibold text-[#dfe2f1]">WSL / Linux</h2>
                </div>
                {status.isWindows ? (
                  wsl && wsl.available ? (
                    <div className="space-y-2">
                      <div className="text-[11px] text-[#8c909f] font-mono">
                        Distro par défaut: <span className="text-[#4cd7f6]">{wsl.defaultDistro || '—'}</span>
                      </div>
                      <div className="max-h-48 overflow-y-auto rounded border border-[#24314c]">
                        <table className="w-full text-sm">
                          <thead className="bg-[#0a0e18] sticky top-0">
                            <tr className="text-[10px] text-[#8c909f] font-mono uppercase">
                              <th className="text-left px-2 py-1">Distro</th>
                              <th className="text-left px-2 py-1">État</th>
                              <th className="text-left px-2 py-1">Version</th>
                            </tr>
                          </thead>
                          <tbody>
                            {wsl.distros.map((d) => (
                              <tr key={d.name} className="border-t border-[#24314c]">
                                <td className="px-2 py-1 font-mono text-[11px] text-[#dfe2f1]">
                                  {d.name}{d.default ? <span className="ml-1 text-[#4cd7f6]">★</span> : null}
                                </td>
                                <td className="px-2 py-1">
                                  <span className={`px-1.5 py-0.5 text-[10px] font-mono rounded border ${
                                    (d.state || '').toLowerCase().includes('running')
                                      ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                                      : 'bg-[#262a35] border-[#24314c] text-[#8c909f]'
                                  }`}>{d.state}</span>
                                </td>
                                <td className="px-2 py-1 font-mono text-[11px] text-[#c2c6d6]">{d.version}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {wsl?.installed && (wsl.distros?.length ?? 0) === 0 ? (
                        <>
                          <div className="px-3 py-2 rounded bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs font-mono">
                            WSL est installé mais AUCUN distro Linux n'est enregistré — c'est pourquoi les outils et terminaux sont inopérants.
                          </div>
                          <button
                            onClick={handleInstallDistro}
                            disabled={distroBusy}
                            className="px-3 py-1.5 text-xs rounded bg-amber-500/15 border border-amber-400/40 hover:bg-amber-500/25 text-amber-300 flex items-center gap-1.5 transition-colors font-medium disabled:opacity-50"
                            type="button"
                          >
                            <span className="material-symbols-outlined text-[16px]">download</span>
                            {distroBusy ? 'Installation d\'Ubuntu en cours…' : 'Installer la distribution Ubuntu (un clic)'}
                          </button>
                          {distroJob && distroJob.log.length > 0 && (
                            <pre className="max-h-48 overflow-y-auto whitespace-pre-wrap rounded border border-[#24314c] bg-[#0a0e18] p-2 text-[10px] font-mono text-amber-100/80 scrollbar-thin">
                              {distroJob.log.join('\n')}
                            </pre>
                          )}
                        </>
                      ) : (
                        <>
                          <div className="px-3 py-2 rounded bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs font-mono">
                            {wsl?.reason || 'WSL non détecté. Installation conseillée pour activer les modules WiFi / Arsenal / Terminal avancé.'}
                          </div>
                          <button
                            onClick={openSetupWizard}
                            className="px-3 py-1.5 text-xs rounded bg-[#4d8eff]/15 border border-[#4d8eff]/40 hover:bg-[#4d8eff]/25 text-[#4d8eff] flex items-center gap-1.5 transition-colors font-medium"
                            type="button"
                          >
                            <span className="material-symbols-outlined text-[16px]">download</span>
                            Installer WSL (assistant UAC)
                          </button>
                          <div className="text-[11px] text-[#8c909f] font-mono">
                            Ou manuellement : <code>wsl --install</code> dans PowerShell (admin).
                          </div>
                        </>
                      )}
                    </div>
                  )
                ) : (
                  <div className="px-3 py-2 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono">
                    Mode Linux natif — outils exécutés directement (équivalent WSL).
                  </div>
                )}
              </div>
            </div>

            {/* Tools status grid */}
            <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4 mb-6">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-[18px] text-[#4d8eff]">build</span>
                  <h2 className="text-sm font-semibold text-[#dfe2f1]">Statut des outils Linux</h2>
                </div>
                {tools && toolInstalled !== undefined && toolTotal !== undefined && (
                  <div className="text-[11px] font-mono text-[#8c909f]">
                    <span className="text-emerald-400">{toolInstalled}</span> / {toolTotal} installés
                  </div>
                )}
              </div>

              {tools ? (
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2 max-h-96 overflow-y-auto pr-1">
                  {[...tools.available.sort(), ...tools.missing.sort()].map((t) => {
                    const ok = tools.available.includes(t);
                    return (
                      <div
                        key={t}
                        className={`flex items-center gap-2 px-2 py-1.5 rounded border text-xs font-mono ${
                          ok
                            ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                            : 'bg-amber-500/10 border-amber-500/30 text-amber-400'
                        }`}
                        title={ok ? `${t} installé` : `${t} manquant`}
                      >
                        <span className="material-symbols-outlined text-[14px]">
                          {ok ? 'check_circle' : 'warning'}
                        </span>
                        <span className="truncate">{t}</span>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="text-xs text-[#8c909f]">Impossible de détecter les outils.</div>
              )}

              {tools && tools.missing.length > 0 && (
                <div className="mt-4 flex flex-wrap items-center gap-3">
                  <button
                    onClick={handleInstall}
                    disabled={installing}
                    className="px-4 py-2 bg-[#4d8eff]/15 border border-[#4d8eff]/40 text-[#4d8eff] rounded text-sm font-medium hover:bg-[#4d8eff]/25 disabled:opacity-50 flex items-center gap-2 transition-colors"
                    type="button"
                  >
                    {installing ? (
                      <><span className="material-symbols-outlined animate-spin text-[18px]">progress_activity</span> Installation...</>
                    ) : (
                      <><span className="material-symbols-outlined text-[18px]">download</span> Installer les outils manquants</>
                    )}
                  </button>
                  <span className="text-[11px] text-[#8c909f] font-mono">
                    Lance <code>sudo apt install ...</code> via le pont. Peut nécessiter sudo sans mot de passe ou interaction.
                  </span>
                </div>
              )}
            </div>

            {/* Install output */}
            {installResult && (
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg overflow-hidden">
                <div className="px-4 py-2 border-b border-[#24314c] flex items-center justify-between">
                  <div className="text-xs font-mono text-[#8c909f]">
                    Installation — apt •{' '}
                    {installResult.exitCode === 0 && !installResult.error
                      ? <span className="text-emerald-400">succès</span>
                      : <span className="text-[#ffb4ab]">échec</span>
                    }
                  </div>
                  <div className="text-[10px] text-[#8c909f]">exit={installResult.exitCode ?? '—'}</div>
                </div>
                {installResult.error && (
                  <div className="px-4 py-2 bg-[#93000a]/20 border-b border-[#93000a]/40 text-[#ffb4ab] text-xs font-mono">
                    {installResult.error}
                  </div>
                )}
                <div className="p-3">
                  <pre className="bg-[#0a0e18] border border-[#24314c] rounded p-3 text-[11px] font-mono text-[#c2c6d6] max-h-80 overflow-y-auto whitespace-pre-wrap break-all">
{installResult.output || '(aucune sortie)'}
                  </pre>
                </div>
              </div>
            )}
          </>
        ) : null}
      </div>
    </div>
  );
};
