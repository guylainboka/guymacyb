import React, { useState, useEffect } from 'react';
import { TargetConfig } from '../../types';
import { ShadowScanLogo } from './ShadowScanLogo';

interface HeaderProps {
  targetConfig: TargetConfig;
  setTargetConfig: React.Dispatch<React.SetStateAction<TargetConfig>>;
  onLaunchAnalysis: () => void;
  onLaunchAttack: () => void;
  isAnalyzing: boolean;
  isTesting: boolean;
  onOpenSettings: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  targetConfig,
  setTargetConfig,
  onLaunchAnalysis,
  onLaunchAttack,
  isAnalyzing,
  isTesting,
  onOpenSettings,
}) => {
  const [cpuUsage, setCpuUsage] = useState<number>(12);
  const [ramUsage, setRamUsage] = useState<number>(410);
  const [isScopeMenuOpen, setIsScopeMenuOpen] = useState<boolean>(false);
  const [isEditingTarget, setIsEditingTarget] = useState<boolean>(false);
  const [inputUrl, setInputUrl] = useState<string>(targetConfig.url);
  const [isMaximized, setIsMaximized] = useState<boolean>(false);

  // Dynamic light telemetry fluctuation to feel like a real native engine
  useEffect(() => {
    const timer = setInterval(() => {
      setCpuUsage((prev) => {
        const delta = Math.floor(Math.random() * 5) - 2;
        return Math.max(8, Math.min(26, prev + delta));
      });
      setRamUsage((prev) => {
        const delta = Math.floor(Math.random() * 3) - 1;
        return Math.max(405, Math.min(425, prev + delta));
      });
    }, 3000);
    return () => clearInterval(timer);
  }, []);

  const handleTargetSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (inputUrl.trim()) {
      setTargetConfig((prev) => ({
        ...prev,
        url: inputUrl.trim().startsWith('http') ? inputUrl.trim() : `https://${inputUrl.trim()}`,
      }));
    }
    setIsEditingTarget(false);
  };

  const toggleMaximize = () => {
    setIsMaximized(!isMaximized);
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().catch(() => {});
    } else {
      document.exitFullscreen().catch(() => {});
    }
  };

  return (
    <header className="fixed top-0 left-0 right-0 z-50 flex flex-col bg-[#0a0e18] border-b border-[#24314c] select-none">
      {/* Native Desktop Titlebar */}
      <div className="h-8 w-full bg-[#0a0e18] flex items-center justify-between px-3 border-b border-[#1b243b]">
        <div className="flex items-center gap-2">
          <ShadowScanLogo size={18} />
          <span className="font-mono text-xs text-[#dfe2f1] font-medium tracking-tight">
            ShadowScan Desktop v1.0.0 - Enterprise Security Assessment Engine
          </span>
          <div className="flex items-center gap-1.5 px-2 py-0.5 bg-[#171b26] rounded text-[#c2c6d6] font-mono text-[11px] border border-[#262a35]">
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-[#4cd7f6] animate-pulse"></span>
            <span>Local SQLite DB Connected ({targetConfig.localDbName})</span>
          </div>
        </div>

        {/* Window Control Buttons */}
        <div className="flex items-center h-full">
          <button
            title="Minimiser"
            className="h-full w-9 flex items-center justify-center text-[#c2c6d6] hover:bg-[#1c1f2a] hover:text-white transition-colors"
            type="button"
            onClick={() => {}}
          >
            <span className="material-symbols-outlined text-[14px]">minimize</span>
          </button>
          <button
            title={isMaximized ? 'Restaurer' : 'Agrandir'}
            className="h-full w-9 flex items-center justify-center text-[#c2c6d6] hover:bg-[#1c1f2a] hover:text-white transition-colors"
            type="button"
            onClick={toggleMaximize}
          >
            <span className="material-symbols-outlined text-[14px]">
              {isMaximized ? 'filter_none' : 'check_box_outline_blank'}
            </span>
          </button>
          <button
            title="Fermer la session"
            className="h-full w-9 flex items-center justify-center text-[#c2c6d6] hover:bg-[#93000a] hover:text-white transition-colors"
            type="button"
            onClick={() => {
              if (confirm('Fermer la session active de ShadowScan ?')) {
                window.location.reload();
              }
            }}
          >
            <span className="material-symbols-outlined text-[14px]">close</span>
          </button>
        </div>
      </div>

      {/* Main Command & Execution Toolbar */}
      <div className="h-12 w-full bg-[#171b26] px-4 flex items-center justify-between shadow-sm">
        <div className="flex items-center gap-3 flex-1 max-w-4xl">
          {/* Target URL Capsule */}
          <div className="flex items-center bg-[#0a0e18] rounded px-3 py-1 gap-2 flex-1 border border-[#24314c] focus-within:border-[#3b82f6] transition-colors">
            <span className="inline-block w-2 h-2 rounded-full bg-[#4cd7f6] shrink-0"></span>
            <span className="font-mono text-[10px] text-[#8c909f] uppercase tracking-wider shrink-0">Cible:</span>
            {isEditingTarget ? (
              <form onSubmit={handleTargetSubmit} className="flex-1 flex items-center">
                <input
                  className="bg-transparent font-mono text-xs text-[#dfe2f1] focus:outline-none w-full"
                  type="text"
                  value={inputUrl}
                  onChange={(e) => setInputUrl(e.target.value)}
                  onBlur={handleTargetSubmit}
                  autoFocus
                />
              </form>
            ) : (
              <span
                onClick={() => setIsEditingTarget(true)}
                title="Cliquer pour modifier la cible"
                className="font-mono text-xs text-[#dfe2f1] hover:text-[#4cd7f6] cursor-pointer truncate flex-1"
              >
                {targetConfig.url}
              </span>
            )}
            <div className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-[#1c1f2a] font-mono text-[10px] text-[#4cd7f6] shrink-0 border border-[#24314c]">
              <span className="material-symbols-outlined text-[12px]">verified_user</span>
              <span>In Scope</span>
            </div>
          </div>

          {/* Scope Dropdown */}
          <div className="relative">
            <button
              type="button"
              onClick={() => setIsScopeMenuOpen(!isScopeMenuOpen)}
              className="flex items-center bg-[#0a0e18] rounded px-3 py-1 text-[#c2c6d6] gap-1.5 font-mono text-xs border border-[#24314c] hover:bg-[#1c1f2a] transition-colors"
            >
              <span className="material-symbols-outlined text-[14px] text-[#4cd7f6]">hub</span>
              <span>
                {targetConfig.scope === 'wildcard' ? 'Target + Subdomains' : 'Target Only (Strict)'}
              </span>
              <span className="material-symbols-outlined text-[14px]">arrow_drop_down</span>
            </button>

            {isScopeMenuOpen && (
              <div className="absolute top-full left-0 mt-1 w-56 bg-[#171b26] border border-[#24314c] rounded shadow-xl z-50 py-1 font-mono text-xs">
                <button
                  type="button"
                  onClick={() => {
                    setTargetConfig((p) => ({ ...p, scope: 'strict' }));
                    setIsScopeMenuOpen(false);
                  }}
                  className={`w-full text-left px-3 py-2 flex items-center justify-between hover:bg-[#1c1f2a] ${
                    targetConfig.scope === 'strict' ? 'text-[#4cd7f6] bg-[#0a0e18]' : 'text-[#dfe2f1]'
                  }`}
                >
                  <span>Cible uniquement (Strict)</span>
                  {targetConfig.scope === 'strict' && <span className="material-symbols-outlined text-[14px]">check</span>}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setTargetConfig((p) => ({ ...p, scope: 'wildcard' }));
                    setIsScopeMenuOpen(false);
                  }}
                  className={`w-full text-left px-3 py-2 flex items-center justify-between hover:bg-[#1c1f2a] ${
                    targetConfig.scope === 'wildcard' ? 'text-[#4cd7f6] bg-[#0a0e18]' : 'text-[#dfe2f1]'
                  }`}
                >
                  <span>Cible + Sous-domaines (*)</span>
                  {targetConfig.scope === 'wildcard' && <span className="material-symbols-outlined text-[14px]">check</span>}
                </button>
              </div>
            )}
          </div>

          {/* Dual Action Execution Buttons */}
          <div className="flex items-center gap-2">
            <button
              onClick={onLaunchAnalysis}
              disabled={isAnalyzing}
              className={`flex items-center gap-1.5 px-3 py-1 rounded font-mono text-xs font-medium transition-all ${
                isAnalyzing
                  ? 'bg-[#4d8eff]/50 text-white cursor-wait'
                  : 'bg-[#4d8eff] hover:bg-[#3b82f6] text-white shadow-sm'
              }`}
              type="button"
            >
              <span className={`material-symbols-outlined text-[14px] ${isAnalyzing ? 'animate-spin' : ''}`}>
                {isAnalyzing ? 'refresh' : 'play_arrow'}
              </span>
              <span>{isAnalyzing ? 'Analyse...' : 'Lancer Analyse'}</span>
            </button>

            <button
              onClick={onLaunchAttack}
              className={`flex items-center gap-1.5 px-3 py-1 rounded font-mono text-xs font-medium transition-all ${
                isTesting
                  ? 'bg-[#93000a] text-white animate-pulse'
                  : 'bg-[#262a35] hover:bg-[#313540] text-[#ffb4ab] border border-[#ffb4ab]/30'
              }`}
              type="button"
            >
              <span className="material-symbols-outlined text-[14px]">
                {isTesting ? 'bolt' : 'bug_report'}
              </span>
              <span>{isTesting ? 'Attaque Active...' : 'Tester / Attaquer'}</span>
            </button>
          </div>
        </div>

        {/* Live Engine Telemetry & Operator Profile */}
        <div className="flex items-center gap-5">
          <div className="hidden lg:flex items-center gap-4 text-[#c2c6d6] font-mono text-xs">
            <span className="flex items-center gap-1">
              <span className="material-symbols-outlined text-[14px] text-[#4cd7f6]">memory</span>
              CPU {cpuUsage}%
            </span>
            <span className="flex items-center gap-1">
              <span className="material-symbols-outlined text-[14px] text-[#3b82f6]">storage</span>
              RAM {ramUsage}MB
            </span>
            <span className="flex items-center gap-1">
              <span className="material-symbols-outlined text-[14px] text-[#10b981]">dynamic_form</span>
              Threads: 8
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onOpenSettings}
              title={`Opérateur: ${targetConfig.operatorId} - Ouvrir paramètres`}
              className="flex items-center gap-1.5 px-2 py-1 rounded bg-[#262a35] hover:bg-[#313540] text-[#dfe2f1] font-mono text-xs border border-[#424754]"
              type="button"
            >
              <div className="w-5 h-5 rounded-full bg-[#3b82f6] flex items-center justify-center text-white text-[11px] font-bold">
                OP
              </div>
              <span className="hidden sm:inline">{targetConfig.operatorId}</span>
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
