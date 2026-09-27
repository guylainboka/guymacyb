import React, { useState, useEffect, useRef } from 'react';
import { ActiveTestFamily, TerminalLog } from '../../types';

interface ActiveTestsViewProps {
  testFamilies: ActiveTestFamily[];
  terminalLogs: TerminalLog[];
  isTesting: boolean;
  onStopTest: () => void;
  onStartTest: () => void;
  onGoToResults: () => void;
  onGoToLab?: () => void;
  safeMode: boolean;
  setSafeMode: React.Dispatch<React.SetStateAction<boolean>>;
}

export const ActiveTestsView: React.FC<ActiveTestsViewProps> = ({
  testFamilies,
  terminalLogs,
  isTesting,
  onStopTest,
  onStartTest,
  onGoToResults,
  onGoToLab,
  safeMode,
  setSafeMode,
}) => {
  const [selectedFamily, setSelectedFamily] = useState<ActiveTestFamily>(testFamilies[2]); // Default B.A.C.
  const [progress, setProgress] = useState<number>(68);
  const [logFilter, setLogFilter] = useState<string>('');
  const [autoScroll, setAutoScroll] = useState<boolean>(true);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll terminal logs if enabled
  useEffect(() => {
    if (autoScroll && terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [terminalLogs, autoScroll]);

  // Simulate progress advance during active test
  useEffect(() => {
    if (!isTesting) return;
    const interval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 100) return 100;
        return prev + 1;
      });
    }, 400);
    return () => clearInterval(interval);
  }, [isTesting]);

  const filteredLogs = terminalLogs.filter((l) => {
    if (!logFilter) return true;
    const q = logFilter.toLowerCase();
    return l.text.toLowerCase().includes(q) || l.tag.toLowerCase().includes(q);
  });

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
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                isTesting ? 'bg-[#ffb4ab] animate-ping' : 'bg-[#10b981]'
              }`}
            ></span>
            <span>{isTesting ? 'TESTS ACTIFS EN COURS' : 'TESTS TERMINÉS / EN ATTENTE'}</span>
          </div>

          <div className="flex items-center gap-3 text-[#c2c6d6]">
            <span>Progression: <strong className="text-white">{progress}%</strong></span>
            <span className="text-[#424754]">|</span>
            <span>Workers: 4 threads</span>
            <span className="text-[#424754]">|</span>
            <span className="text-[#4cd7f6]">Rate: 42 req/s</span>
          </div>
        </div>

        {/* Safe Mode Toggle & Emergency Control */}
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => setSafeMode(!safeMode)}
            className={`px-3 py-1.5 rounded border transition-colors ${
              safeMode
                ? 'bg-[#10b981]/15 border-[#10b981]/40 text-[#10b981]'
                : 'bg-[#93000a]/20 border-[#ffb4ab]/30 text-[#ffb4ab]'
            }`}
          >
            Mode Non-Destructif [{safeMode ? 'ACTIF' : 'OFF'}]
          </button>

          {onGoToLab && (
            <button
              type="button"
              onClick={onGoToLab}
              className="px-3 py-1.5 rounded bg-[#262a35] hover:bg-[#323746] text-[#4cd7f6] border border-[#4cd7f6]/40 font-bold tracking-wide flex items-center gap-1.5 shadow-sm"
            >
              <span className="material-symbols-outlined text-[16px]">science</span>
              <span>CYBER LAB (SIMULATIONS)</span>
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
              <span>RELANCER LES TESTS</span>
            </button>
          )}
        </div>
      </div>

      {/* 6-step Intelligent Pipeline Breadcrumbs */}
      <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3 overflow-x-auto shadow-sm">
        <div className="flex items-center justify-between min-w-[700px] font-mono text-[11px]">
          <div className="flex items-center gap-1.5 text-[#10b981]">
            <span className="material-symbols-outlined text-[15px]">check_circle</span>
            <span>1. RECON (100%)</span>
          </div>
          <span className="text-[#424754]">→</span>
          <div className="flex items-center gap-1.5 text-[#10b981]">
            <span className="material-symbols-outlined text-[15px]">check_circle</span>
            <span>2. DISCOVERY (137 pts)</span>
          </div>
          <span className="text-[#424754]">→</span>
          <div className="flex items-center gap-1.5 text-[#10b981]">
            <span className="material-symbols-outlined text-[15px]">check_circle</span>
            <span>3. CLASSIFICATION (42 APIs)</span>
          </div>
          <span className="text-[#424754]">→</span>
          <div className="flex items-center gap-1.5 text-[#4cd7f6] font-bold">
            <span className="material-symbols-outlined text-[15px] animate-spin">sync</span>
            <span>4. CHOIX DES TESTS</span>
          </div>
          <span className="text-[#424754]">→</span>
          <div className="flex items-center gap-1.5 text-[#4cd7f6] font-bold">
            <span className="material-symbols-outlined text-[15px]">bolt</span>
            <span>5. TEST & VALIDATION</span>
          </div>
          <span className="text-[#424754]">→</span>
          <div className="flex items-center gap-1.5 text-[#8c909f]">
            <span className="material-symbols-outlined text-[15px]">pending</span>
            <span>6. RAPPORT</span>
          </div>
        </div>
      </div>

      {/* Main Split View: Left Matrix / Right Live Terminal */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 flex-1 min-h-[520px]">
        {/* Left Pane: Matrice des Familles de Tests Actifs */}
        <div className="lg:col-span-6 bg-[#171b26] border border-[#24314c] rounded-lg flex flex-col overflow-hidden">
          <div className="p-3.5 bg-[#0a0e18] border-b border-[#24314c] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[18px] text-[#4cd7f6]">grid_view</span>
              <h3 className="font-mono text-xs font-bold text-[#dfe2f1] uppercase tracking-wider">
                Matrice des Familles de Tests Actifs
              </h3>
            </div>
            <span className="font-mono text-[11px] text-[#8c909f]">{testFamilies.length} Familles</span>
          </div>

          <div className="flex-1 overflow-y-auto p-3 flex flex-col gap-2 font-mono text-xs">
            {testFamilies.map((family) => {
              const isSelected = selectedFamily.id === family.id;
              return (
                <div
                  key={family.id}
                  onClick={() => setSelectedFamily(family)}
                  className={`p-3 rounded border transition-all cursor-pointer flex flex-col gap-1.5 ${
                    isSelected
                      ? 'bg-[#262a35] border-[#4cd7f6] shadow-sm'
                      : 'bg-[#0a0e18] border-[#24314c] hover:bg-[#1c1f2a]'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="material-symbols-outlined text-[18px] text-[#4cd7f6]">
                        {family.icon}
                      </span>
                      <strong className="text-[#dfe2f1] font-semibold">{family.name}</strong>
                    </div>

                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        family.status === 'PASS'
                          ? 'bg-[#10b981]/20 text-[#10b981]'
                          : family.status === 'FAIL'
                          ? 'bg-[#93000a]/40 text-[#ffb4ab] border border-[#ffb4ab]/30 animate-pulse'
                          : family.status === 'TESTING'
                          ? 'bg-[#3b82f6]/20 text-[#60a5fa] border border-[#3b82f6]/40'
                          : 'bg-[#f59e0b]/20 text-[#fbbf24]'
                      }`}
                    >
                      {family.status}
                    </span>
                  </div>

                  <p className="text-[11px] text-[#8c909f] leading-snug">{family.telemetrySummary}</p>
                </div>
              );
            })}
          </div>

          {/* Selected Evidence Trace Drawer */}
          {selectedFamily.evidenceTrace && (
            <div className="p-3 bg-[#0a0e18] border-t border-[#24314c] font-mono text-[11px] flex flex-col gap-1.5">
              <div className="flex items-center justify-between text-[#ffb4ab] font-bold">
                <span className="flex items-center gap-1.5">
                  <span className="material-symbols-outlined text-[14px]">bug_report</span>
                  Trace de validation en direct : {selectedFamily.name}
                </span>
                <span className="text-[10px] text-[#8c909f]">{selectedFamily.evidenceTrace.cwe}</span>
              </div>
              <div className="bg-[#171b26] p-2 rounded border border-[#24314c] text-[#dfe2f1] overflow-x-auto text-[10px]">
                <div className="text-[#4cd7f6]">{selectedFamily.evidenceTrace.req}</div>
                <div className="text-[#10b981] mt-1">{selectedFamily.evidenceTrace.res}</div>
              </div>
            </div>
          )}
        </div>

        {/* Right Pane: Interactive Live Terminal / Console */}
        <div className="lg:col-span-6 bg-[#0a0e18] border border-[#24314c] rounded-lg flex flex-col overflow-hidden shadow-inner">
          {/* Terminal Top Bar */}
          <div className="p-3 bg-[#171b26] border-b border-[#24314c] flex items-center justify-between font-mono text-xs">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[16px] text-[#10b981]">terminal</span>
              <span className="text-[#dfe2f1] font-bold">Console d'Audit & Journal en Direct</span>
              <span className="w-2 h-2 rounded-full bg-[#10b981] animate-ping ml-1"></span>
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

          {/* Terminal Screen Output */}
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

                <span
                  className={`flex-1 ${
                    log.tag === 'FINDING'
                      ? 'text-[#ffb4ab] font-bold'
                      : log.tag === 'VALIDATION'
                      ? 'text-[#34d399]'
                      : 'text-[#dfe2f1]'
                  }`}
                >
                  {log.text}
                </span>

                {log.confidence && (
                  <span className="text-[#3b82f6] text-[10px] shrink-0">
                    Confiance: {log.confidence}
                  </span>
                )}
              </div>
            ))}
            <div ref={terminalEndRef} />
          </div>

          {/* Terminal Footer Status */}
          <div className="p-2.5 bg-[#171b26] border-t border-[#24314c] flex items-center justify-between font-mono text-[10px] text-[#8c909f]">
            <span>Lignes affichées : {filteredLogs.length}</span>
            <button
              type="button"
              onClick={onGoToResults}
              className="text-[#4cd7f6] hover:underline flex items-center gap-1"
            >
              <span>Voir les 21 preuves qualifiées dans l'Evidence Hub</span>
              <span className="material-symbols-outlined text-[13px]">arrow_forward</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
