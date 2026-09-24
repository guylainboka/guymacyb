import React from 'react';
import { TargetConfig } from '../../types';

interface FooterProps {
  targetConfig: TargetConfig;
  safeMode: boolean;
  setSafeMode: React.Dispatch<React.SetStateAction<boolean>>;
  engineStatus: string;
  findingsCount: number;
}

export const Footer: React.FC<FooterProps> = ({
  targetConfig,
  safeMode,
  setSafeMode,
  engineStatus,
  findingsCount,
}) => {
  return (
    <footer className="fixed bottom-0 left-0 right-0 h-6 bg-[#0a0e18] z-50 px-4 flex items-center justify-between font-mono text-[10px] text-[#8c909f] border-t border-[#1b243b] select-none">
      <div className="flex items-center gap-3 truncate max-w-xl">
        <span className="flex items-center gap-1.5 text-[#dfe2f1] truncate">
          <span className="inline-block w-1.5 h-1.5 rounded-full bg-[#4cd7f6] shrink-0"></span>
          Cible: <span className="text-[#4cd7f6]">{targetConfig.url}</span>
        </span>
        <span className="text-[#424754]">|</span>
        <span className="shrink-0">
          Scope:{' '}
          <strong className="text-[#dfe2f1]">
            {targetConfig.scope === 'wildcard' ? 'Target + Subdomains (*)' : 'Strict Host'}
          </strong>
        </span>
        <span className="text-[#424754]">|</span>
        <span className="truncate">
          SQLite: <span className="text-[#10b981]">Connected</span> (137 endpoints, {findingsCount} findings)
        </span>
      </div>

      <div className="hidden md:flex items-center gap-3">
        <span>Memory: 412 MB</span>
        <span className="text-[#424754]">|</span>
        <span>Workers: 4/4 active</span>
      </div>

      <div className="flex items-center gap-3">
        <span className="flex items-center gap-1 text-[#dfe2f1]">
          <span className="material-symbols-outlined text-[#4cd7f6] text-[12px]">radio_button_checked</span>
          Status: <span className="text-[#4cd7f6]">{engineStatus}</span>
        </span>
        <span className="text-[#424754]">|</span>
        <button
          type="button"
          onClick={() => setSafeMode(!safeMode)}
          className={`flex items-center gap-1 transition-colors ${
            safeMode ? 'text-[#10b981] hover:text-[#34d399]' : 'text-[#ffb4ab] hover:text-[#ffdad6]'
          }`}
          title="Basculer le mode de sécurité"
        >
          <span>Mode: Non-Destructive Safe Mode [{safeMode ? 'ON' : 'OFF'}]</span>
        </button>
      </div>
    </footer>
  );
};
