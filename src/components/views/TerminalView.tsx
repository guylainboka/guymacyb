import React, { useState, useRef, useEffect } from 'react';

type Shell = 'bash' | 'powershell' | 'cmd' | 'python';

interface TerminalLine {
  id: number;
  type: 'input' | 'output' | 'error' | 'system';
  text: string;
  shell?: Shell;
}

const SHELL_META: Record<Shell, { label: string; icon: string; prompt: string; color: string }> = {
  bash:        { label: 'Bash / Termux',   icon: 'terminal',       prompt: '$',     color: 'text-emerald-400' },
  powershell:  { label: 'PowerShell',      icon: 'code_blocks',    prompt: 'PS>',   color: 'text-sky-400' },
  cmd:         { label: 'CMD Windows',     icon: 'developer_mode', prompt: 'C:\\>', color: 'text-amber-400' },
  python:      { label: 'Python REPL',     icon: 'data_object',    prompt: '>>>',   color: 'text-violet-400' },
};

const QUICK_CMDS: Record<Shell, string[]> = {
  bash:        ['whoami', 'uname -a', 'ip a', 'ls -la', 'nmap --version', 'aircrack-ng --help | head -5'],
  powershell:  ['Get-Process', 'Get-NetAdapter', 'Get-LocalUser', 'systeminfo | Select-String "OS"', 'Get-Service | Where-Object Status -eq "Running"'],
  cmd:         ['ver', 'ipconfig /all', 'netstat -an | findstr LISTEN', 'tasklist', 'systeminfo'],
  python:      ['import os; print(os.uname())', 'import socket; print(socket.gethostname())', 'print([x for x in range(10)])'],
};

export const TerminalView: React.FC = () => {
  const [shell, setShell] = useState<Shell>('bash');
  const [input, setInput] = useState('');
  const [lines, setLines] = useState<TerminalLine[]>([
    { id: 0, type: 'system', text: 'Terminal Guyma Cyb prêt. Sélectionnez un shell et tapez vos commandes.' },
    { id: 1, type: 'system', text: '⚠ L\'exécution de commandes dangereuses (rm -rf /, fork bomb...) est bloquée.' },
  ]);
  const [history, setHistory] = useState<string[]>([]);
  const [histIdx, setHistIdx] = useState(-1);
  const [isRunning, setIsRunning] = useState(false);
  const lineId = useRef(2);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo(0, scrollRef.current.scrollHeight);
  }, [lines]);

  const addLine = (type: TerminalLine['type'], text: string, sh?: Shell) => {
    setLines((p) => [...p, { id: lineId.current++, type, text, shell: sh }]);
  };

  const runCommand = async (cmd: string) => {
    if (!cmd.trim() || isRunning) return;
    addLine('input', `${SHELL_META[shell].prompt} ${cmd}`, shell);
    setHistory((h) => [...h, cmd]);
    setHistIdx(-1);
    setIsRunning(true);
    try {
      const res = await fetch('/api/terminal/exec', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ shell, command: cmd }),
      });
      const data = await res.json();
      if (data.stdout) addLine('output', data.stdout);
      if (data.stderr) addLine('error', data.stderr);
      if (data.error && !data.stdout && !data.stderr) addLine('error', data.error);
      if (!data.stdout && !data.stderr && !data.error) addLine('system', '(aucune sortie)');
      addLine('system', `[exit ${data.exitCode}] • ${data.durationMs}ms • ${data.cwd || ''}`);
    } catch (e: any) {
      addLine('error', 'Erreur API: ' + e.message);
    } finally {
      setIsRunning(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    runCommand(input);
    setInput('');
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (history.length === 0) return;
      const newIdx = histIdx === -1 ? history.length - 1 : Math.max(0, histIdx - 1);
      setHistIdx(newIdx);
      setInput(history[newIdx]);
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (histIdx === -1) return;
      const newIdx = histIdx + 1;
      if (newIdx >= history.length) { setHistIdx(-1); setInput(''); }
      else { setHistIdx(newIdx); setInput(history[newIdx]); }
    } else if (e.key === 'l' && e.ctrlKey) {
      e.preventDefault();
      setLines([]);
    }
  };

  const meta = SHELL_META[shell];

  return (
    <div className="h-full flex flex-col bg-[#0a0e18] text-[#dfe2f1] p-6">
      <div className="max-w-7xl mx-auto w-full flex-1 flex flex-col min-h-0">
        {/* En-tête */}
        <div className="mb-4">
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <span className="material-symbols-outlined text-emerald-400">terminal</span>
            Terminal Intégré
          </h1>
          <p className="text-sm text-[#8c909f] mt-1">
            Bash / Termux, PowerShell, CMD Windows et Python REPL — exécution directe avec historique (↑/↓) et Ctrl+L pour vider.
          </p>
        </div>

        {/* Sélecteur de shell */}
        <div className="flex flex-wrap gap-2 mb-3">
          {(Object.keys(SHELL_META) as Shell[]).map((s) => {
            const m = SHELL_META[s];
            const active = shell === s;
            return (
              <button
                key={s}
                onClick={() => setShell(s)}
                className={`px-3 py-1.5 text-xs rounded border font-mono flex items-center gap-1.5 transition-colors ${
                  active ? `${m.color} bg-[#171b26] border-current` : 'text-[#8c909f] bg-[#171b26] border-[#24314c] hover:text-[#dfe2f1]'
                }`}
                type="button"
              >
                <span className="material-symbols-outlined text-[16px]">{m.icon}</span>
                {m.label}
              </button>
            );
          })}
        </div>

        {/* Commandes rapides */}
        <div className="flex flex-wrap gap-1.5 mb-3">
          {QUICK_CMDS[shell].map((c) => (
            <button
              key={c}
              onClick={() => runCommand(c)}
              disabled={isRunning}
              className="px-2 py-0.5 text-[10px] font-mono rounded bg-[#0a0e18] border border-[#24314c] text-[#8c909f] hover:text-emerald-400 hover:border-emerald-500/40 disabled:opacity-40 transition-colors"
              type="button"
            >
              {c.length > 40 ? c.slice(0, 40) + '…' : c}
            </button>
          ))}
        </div>

        {/* Terminal */}
        <div className="flex-1 min-h-0 bg-[#050810] border border-[#24314c] rounded-lg flex flex-col overflow-hidden">
          {/* Barre de titre style terminal */}
          <div className="px-3 py-1.5 border-b border-[#24314c] flex items-center justify-between bg-[#171b26]">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500/70"></span>
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500/70"></span>
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/70"></span>
            </div>
            <span className={`text-[11px] font-mono ${meta.color}`}>{meta.label}</span>
            <span className="text-[10px] text-[#8c909f] font-mono">guymacyb@localhost</span>
          </div>

          {/* Sortie */}
          <div ref={scrollRef} className="flex-1 overflow-y-auto p-3 font-mono text-[12px] leading-relaxed">
            {lines.map((l) => (
              <div
                key={l.id}
                className={
                  l.type === 'input' ? `${meta.color} whitespace-pre-wrap`
                  : l.type === 'error' ? 'text-rose-400 whitespace-pre-wrap'
                  : l.type === 'system' ? 'text-[#5c607a] italic whitespace-pre-wrap'
                  : 'text-[#c2c6d6] whitespace-pre-wrap'
                }
              >
                {l.text}
              </div>
            ))}
            {isRunning && (
              <div className="text-[#8c909f] italic">
                <span className="material-symbols-outlined animate-spin text-[14px] align-middle">progress_activity</span> exécution...
              </div>
            )}
          </div>

          {/* Entrée */}
          <form onSubmit={handleSubmit} className="border-t border-[#24314c] p-2 flex items-center gap-2 bg-[#0a0e18]">
            <span className={`font-mono text-sm ${meta.color}`}>{meta.prompt}</span>
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={`Tapez une commande ${meta.label}...`}
              className="flex-1 bg-transparent border-none outline-none font-mono text-sm text-[#dfe2f1] placeholder-[#5c607a]"
              autoFocus
              disabled={isRunning}
              spellCheck={false}
            />
            <button
              type="submit"
              disabled={isRunning || !input.trim()}
              className="px-3 py-1 text-xs rounded bg-emerald-600/20 border border-emerald-500/40 text-emerald-400 hover:bg-emerald-600/30 disabled:opacity-40 transition-colors"
            >
              Exécuter
            </button>
          </form>
        </div>

        {/* Note bas */}
        <div className="mt-3 text-[11px] text-[#8c909f] flex items-center gap-2">
          <span className="material-symbols-outlined text-[14px]">info</span>
          <span>
            Sur Windows : PowerShell et CMD natifs. Bash nécessite Git for Windows. Pour les commandes sudo/admin, relancez Guyma Cyb en tant qu'administrateur.
          </span>
        </div>
      </div>
    </div>
  );
};
