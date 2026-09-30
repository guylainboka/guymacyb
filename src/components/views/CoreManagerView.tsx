import React, { useCallback, useEffect, useState } from 'react';

interface WslDistro {
  name: string;
  state: string;
  version: string;
  default?: boolean;
}

// NOTE: shape must match `/api/core/status` returned by `getCoreStatus()` in
// `src/server/toolbridge.ts`. The API returns:
//   platform, isWindows, wsl{available,distros,defaultDistro},
//   tools{available,missing}, python, node, memoryMb
// There is NO `bridge`, `memory.total/free`, `tools.installed/total`, or
// `timestamp` field — these are derived locally from the real API fields.
interface CoreStatus {
  platform: string;
  isWindows: boolean;
  node: string;
  memoryMb?: number;
  python?: string | null;
  wsl?: { distros: WslDistro[]; defaultDistro: string | null; available: boolean } | null;
  tools?: { available: string[]; missing: string[] };
  error?: string;
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

export const CoreManagerView: React.FC = () => {
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
      } else {
        setError('Assistant indisponible hors du logiciel desktop. Lancez « wsl --install » dans PowerShell (admin) puis réessayez.');
      }
    } catch (e: any) {
      setError(e?.message || 'Impossible d\'ouvrir l\'assistant de configuration');
    }
  };

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
                      <div className="px-3 py-2 rounded bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs font-mono">
                        WSL non détecté. Installation conseillée pour activer les modules WiFi / Arsenal / Terminal avancé.
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
