import React, { useState, useEffect, useRef } from 'react';
import { ActiveRunResult, TerminalLog } from '../../types';

interface ActiveTestsViewProps {
  targetUrl: string;
  runResult: ActiveRunResult | null;
  terminalLogs: TerminalLog[];
  isTesting: boolean;
  onStopTest: () => void;
  onStartTest: () => void;
  onGoToResults: () => void;
  onGoToLab?: () => void;
  safeMode: boolean;
  setSafeMode: React.Dispatch<React.SetStateAction<boolean>>;
}

/**
 * Vue TESTS ACTIFS RÉELS — affiche les résultats RÉELS de la suite exécutée
 * par /api/tests/active/run (vraies requêtes réseau, vrais findings persistés).
 * Aucune barre de progression artificielle : tant que la suite n'a pas tourné,
 * la vue l'affiche honnêtement.
 */
export const ActiveTestsView: React.FC<ActiveTestsViewProps> = ({
  targetUrl,
  runResult,
  terminalLogs,
  isTesting,
  onStopTest,
  onStartTest,
  onGoToResults,
  onGoToLab,
  safeMode,
  setSafeMode,
}) => {
  const [selectedFamilyId, setSelectedFamilyId] = useState<string | null>(null);
  const [logFilter, setLogFilter] = useState<string>('');
  const [autoScroll, setAutoScroll] = useState<boolean>(true);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (autoScroll && terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [terminalLogs, autoScroll]);

  // Sélection automatique de la première famille au résultat
  useEffect(() => {
    if (runResult?.families?.length && !selectedFamilyId) {
      setSelectedFamilyId(runResult.families[0].id);
    }
  }, [runResult, selectedFamilyId]);

  const filteredLogs = terminalLogs.filter((l) => {
    if (!logFilter) return true;
    const q = logFilter.toLowerCase();
    return l.text.toLowerCase().includes(q) || l.tag.toLowerCase().includes(q);
  });

  const selectedFamily = runResult?.families.find((f) => f.id === selectedFamilyId) ?? null;

  const statusBadge = (status: 'PASS' | 'FAIL' | 'SKIP' | 'ERROR') =>
    status === 'PASS'
      ? 'bg-[#10b981]/20 text-[#10b981]'
      : status === 'FAIL'
      ? 'bg-[#93000a]/40 text-[#ffb4ab] border border-[#ffb4ab]/30'
      : status === 'ERROR'
      ? 'bg-[#f59e0b]/20 text-[#fbbf24]'
      : 'bg-[#262a35] text-[#8c909f]';

  return (
    <div className="flex-1 overflow-y-auto p-5 flex flex-col gap-5 font-sans">
      {/* Header Strip & Emergency Stop */}
      <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4 flex flex-wrap items-center justify-between gap-4 shadow-sm font-mono text-xs">
        <div className="flex items-center gap-3">
          <div
            className={`flex items-center gap-2 px-3 py-1.5 rounded font-bold ${
              isTesting
                ? 'bg-[#93000a]/30 border border-[#ffb4ab]/40 text-[#ffb4ab]'
                : 'bg-[#10b981]/20 border border-[#10b981]/40 text-[#10b981]'
            }`}
          >
            <span className={`w-2.5 h-2.5 rounded-full ${isTesting ? 'bg-[#ffb4ab] animate-ping' : 'bg-[#10b981]'}`}></span>
            <span>{isTesting ? 'SONDES RÉELLES EN COURS' : 'EN ATTENTE / TERMINÉ'}</span>
          </div>

          <div className="flex items-center gap-3 text-[#c2c6d6]">
            <span>
              Cible : <strong className="text-[#4cd7f6]">{targetUrl}</strong>
            </span>
            {runResult && (
              <>
                <span className="text-[#424754]">|</span>
                <span>
                  Requêtes réelles : <strong className="text-white">{runResult.totalRequests}</strong>
                </span>
                <span className="text-[#424754]">|</span>
                <span>
                  Findings réels : <strong className="text-white">{runResult.findingsCreated}</strong>
                </span>
                <span className="text-[#424754]">|</span>
                <span>
                  Durée : <strong className="text-white">{runResult.durationMs} ms</strong>
                </span>
                <span className="text-[#424754]">|</span>
                <span>
                  Attestation : <strong className="text-[#4cd7f6]">{runResult.authorizationLevel}</strong>
                </span>
              </>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => setSafeMode(!safeMode)}
            className={`px-3 py-1.5 rounded border transition-colors ${
              safeMode
                ? 'bg-[#10b981]/15 border-[#10b981]/40 text-[#10b981]'
                : 'bg-[#93000a]/20 border-[#ffb4ab]/30 text-[#ffb4ab]'
            }`}
            title="Safe Mode ON : la famille déstructrice (nikto) est sautée"
          >
            Safe Mode [{safeMode ? 'ACTIF' : 'OFF'}]
          </button>

          {onGoToLab && (
            <button
              type="button"
              onClick={onGoToLab}
              className="px-3 py-1.5 rounded bg-[#262a35] hover:bg-[#323746] text-[#4cd7f6] border border-[#4cd7f6]/40 font-bold tracking-wide flex items-center gap-1.5 shadow-sm"
            >
              <span className="material-symbols-outlined text-[16px]">science</span>
              <span>LABORATOIRE RÉEL</span>
            </button>
          )}

          {isTesting ? (
            <button
              type="button"
              onClick={onStopTest}
              className="px-4 py-1.5 rounded bg-[#93000a] hover:bg-[#ba1a1a] text-white font-bold tracking-wide flex items-center gap-2 shadow-lg shadow-red-950/40"
            >
              <span className="material-symbols-outlined text-[16px]">stop</span>
              <span>STOP D'URGENCE</span>
            </button>
          ) : (
            <button
              type="button"
              onClick={onStartTest}
              className="px-4 py-1.5 rounded bg-[#4d8eff] hover:bg-[#3b82f6] text-white font-bold tracking-wide flex items-center gap-2 shadow-sm"
            >
              <span className="material-symbols-outlined text-[16px]">play_arrow</span>
              <span>LANCER LA SUITE RÉELLE</span>
            </button>
          )}
        </div>
      </div>

      {/* Empty state honnête avant première exécution */}
      {!runResult && !isTesting && (
        <div className="flex flex-col items-center justify-center p-10 text-center bg-[#0a0e18] rounded-lg border border-dashed border-[#24314c] font-mono text-xs">
          <span className="material-symbols-outlined text-[40px] text-[#8c909f] mb-2">power_settings_new</span>
          <p className="text-sm text-[#c2c6d6] font-semibold">Aucune suite active exécutée sur cette cible.</p>
          <p className="text-[11px] text-[#8c909f] mt-1 max-w-md">
            Cliquez sur « LANCER LA SUITE RÉELLE » : après attestation légale, 7 familles de sondes actives réelles
            (en-têtes, verbes HTTP, TLS, fuzzing, injections, CORS, débit) seront exécutées contre {targetUrl}.
            La famille déstructrice (nikto) nécessite l'attestation AGRESSIVE + Safe Mode OFF.
          </p>
        </div>
      )}

      {/* Main Split View: Left familles réelles / Right terminal */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 flex-1 min-h-[520px]">
        {/* Left: familles réelles */}
        <div className="lg:col-span-6 bg-[#171b26] border border-[#24314c] rounded-lg flex flex-col overflow-hidden">
          <div className="p-3.5 bg-[#0a0e18] border-b border-[#24314c] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[18px] text-[#4cd7f6]">grid_view</span>
              <h3 className="font-mono text-xs font-bold text-[#dfe2f1] uppercase tracking-wider">
                Familles de sondes actives réelles
              </h3>
            </div>
            {runResult && (
              <span className="font-mono text-[11px] text-[#8c909f]">
                {runResult.scanId} • démarré {new Date(runResult.startedAt).toLocaleTimeString()}
              </span>
            )}
          </div>

          <div className="flex-1 overflow-y-auto p-3 flex flex-col gap-2 font-mono text-xs">
            {runResult ? (
              runResult.families.map((family) => {
                const isSelected = selectedFamilyId === family.id;
                return (
                  <div
                    key={family.id}
                    onClick={() => setSelectedFamilyId(family.id)}
                    className={`p-3 rounded border transition-all cursor-pointer flex flex-col gap-1.5 ${
                      isSelected
                        ? 'bg-[#262a35] border-[#4cd7f6] shadow-sm'
                        : 'bg-[#0a0e18] border-[#24314c] hover:bg-[#1c1f2a]'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <strong className="text-[#dfe2f1] font-semibold truncate">{family.name}</strong>
                        <span
                          className={`px-1.5 py-0.2 rounded text-[9px] font-bold shrink-0 ${
                            family.level === 'DESTRUCTIVE'
                              ? 'bg-[#93000a]/30 text-[#ffb4ab]'
                              : 'bg-[#4d8eff]/20 text-[#60a5fa]'
                          }`}
                        >
                          {family.level}
                        </span>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold shrink-0 ${statusBadge(family.status)}`}>
                        {family.status}
                      </span>
                    </div>
                    <p className="text-[11px] text-[#8c909f] leading-snug">{family.summary}</p>
                    <span className="text-[10px] text-[#64748b]">
                      {family.requests} requête(s) réelle(s) • {family.durationMs} ms • {family.findings.length} finding(s)
                    </span>
                  </div>
                );
              })
            ) : (
              <div className="text-[#8c909f] text-[11px] p-4">Les familles apparaîtront ici avec leurs métriques réelles après exécution.</div>
            )}
          </div>

          {/* Détail de la famille sélectionnée : logs réels + findings */}
          {selectedFamily && (
            <div className="p-3 bg-[#0a0e18] border-t border-[#24314c] font-mono text-[11px] flex flex-col gap-2 max-h-64 overflow-y-auto">
              <div className="flex items-center justify-between text-[#4cd7f6] font-bold">
                <span>Détail réel : {selectedFamily.name}</span>
                <span className="text-[10px] text-[#8c909f]">{selectedFamily.summary}</span>
              </div>
              {selectedFamily.logs.map((log, i) => (
                <div key={i} className="text-[#c2c6d6] leading-snug select-text">{log}</div>
              ))}
              {selectedFamily.findings.length > 0 && (
                <div className="flex flex-col gap-1 pt-1 border-t border-[#24314c]">
                  {selectedFamily.findings.map((f) => (
                    <div key={f.id} className="text-[#ffb4ab]">
                      [FINDING] {f.title} — CVSS {f.cvss} ({f.severity})
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right: terminal live */}
        <div className="lg:col-span-6 bg-[#0a0e18] border border-[#24314c] rounded-lg flex flex-col overflow-hidden shadow-inner">
          <div className="p-3 bg-[#171b26] border-b border-[#24314c] flex items-center justify-between font-mono text-xs">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[16px] text-[#10b981]">terminal</span>
              <span className="text-[#dfe2f1] font-bold">Journal d'audit en direct</span>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={logFilter}
                onChange={(e) => setLogFilter(e.target.value)}
                placeholder="Filtrer logs..."
                className="bg-[#0a0e18] border border-[#24314c] rounded px-2 py-0.5 text-[11px] text-[#dfe2f1] focus:outline-none w-28"
              />
              <button
                type="button"
                onClick={() => setAutoScroll(!autoScroll)}
                className={`px-2 py-0.5 rounded text-[10px] border ${
                  autoScroll
                    ? 'bg-[#10b981]/20 text-[#10b981] border-[#10b981]/30'
                    : 'bg-[#262a35] text-[#8c909f] border-[#424754]'
                }`}
              >
                Auto-scroll
              </button>
            </div>
          </div>

          <div className="flex-1 p-4 overflow-y-auto font-mono text-[11px] leading-relaxed flex flex-col gap-1.5 select-text">
            {filteredLogs.map((log) => (
              <div key={log.id} className="flex items-start gap-2 hover:bg-[#171b26]/50 p-0.5 rounded">
                <span className="text-[#424754] shrink-0 font-light">[{log.timestamp}]</span>
                <span
                  className={`px-1.5 py-0.2 rounded text-[10px] font-bold shrink-0 ${
                    log.tag === 'FINDING' || log.tag === 'CRITICAL'
                      ? 'bg-[#93000a]/50 text-[#ffb4ab] border border-[#ffb4ab]/40'
                      : log.tag === 'WARN'
                      ? 'bg-[#f59e0b]/20 text-[#fbbf24]'
                      : log.tag === 'VALIDATION'
                      ? 'bg-[#10b981]/20 text-[#10b981]'
                      : log.tag === 'TEST'
                      ? 'bg-[#3b82f6]/20 text-[#60a5fa]'
                      : 'bg-[#262a35] text-[#8c909f]'
                  }`}
                >
                  [{log.tag}]
                </span>
                <span className={`flex-1 ${log.tag === 'FINDING' ? 'text-[#ffb4ab] font-bold' : 'text-[#dfe2f1]'}`}>
                  {log.text}
                </span>
              </div>
            ))}
            <div ref={terminalEndRef} />
          </div>

          <div className="p-2.5 bg-[#171b26] border-t border-[#24314c] flex items-center justify-between font-mono text-[10px] text-[#8c909f]">
            <span>Lignes affichées : {filteredLogs.length}</span>
            <button
              type="button"
              onClick={onGoToResults}
              className="text-[#4cd7f6] hover:underline flex items-center gap-1"
            >
              <span>Voir les preuves réelles dans l'Evidence Hub</span>
              <span className="material-symbols-outlined text-[13px]">arrow_forward</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
