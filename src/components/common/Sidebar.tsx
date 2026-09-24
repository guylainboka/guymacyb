import React from 'react';
import { ModuleView } from '../../types';

interface SidebarProps {
  currentView: ModuleView;
  onSelectView: (view: ModuleView) => void;
  onOpenSettings: () => void;
  onOpenDocs: () => void;
  findingsCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentView,
  onSelectView,
  onOpenSettings,
  onOpenDocs,
  findingsCount,
}) => {
  const navItems: { id: ModuleView; label: string; icon: string; badge?: string }[] = [
    {
      id: 'scanner-and-recon',
      label: 'Scanner & Recon',
      icon: 'radar',
    },
    {
      id: 'analyse-web',
      label: 'Analyse Web',
      icon: 'travel_explore',
      badge: '137 URI',
    },
    {
      id: 'tests-actifs-and-attaque',
      label: 'Tests Actifs & Attaque',
      icon: 'terminal',
      badge: 'Live',
    },
    {
      id: 'laboratoire-attaques',
      label: 'Laboratoire d\'Attaque',
      icon: 'science',
      badge: 'Cyber Lab',
    },
    {
      id: 'resultats-and-preuves',
      label: 'Résultats & Preuves',
      icon: 'fact_check',
      badge: `${findingsCount}`,
    },
    {
      id: 'rapport-and-remediation',
      label: 'Rapport & Remédiation',
      icon: 'assessment',
    },
  ];

  return (
    <aside className="fixed left-0 top-20 bottom-6 w-64 bg-[#171b26] z-40 flex flex-col justify-between border-r border-[#24314c] shadow-sm select-none">
      <div className="flex flex-col gap-1 p-2">
        <div className="px-3 py-1 font-mono text-[10px] text-[#8c909f] uppercase tracking-wider">
          Workspace Modules
        </div>
        <nav className="flex flex-col gap-1">
          {navItems.map((item) => {
            const isActive = currentView === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectView(item.id)}
                className={`flex items-center justify-between px-3 py-2 rounded text-xs font-medium transition-all ${
                  isActive
                    ? 'bg-[#4d8eff] text-white shadow-sm'
                    : 'text-[#c2c6d6] hover:bg-[#262a35] hover:text-[#dfe2f1]'
                }`}
                type="button"
              >
                <div className="flex items-center gap-2.5">
                  <span className={`material-symbols-outlined text-[18px] ${isActive ? 'text-white' : 'text-[#4cd7f6]'}`}>
                    {item.icon}
                  </span>
                  <span>{item.label}</span>
                </div>
                {item.badge && (
                  <span
                    className={`font-mono text-[10px] px-1.5 py-0.5 rounded ${
                      isActive
                        ? 'bg-[#00285d] text-[#adc6ff]'
                        : item.id === 'tests-actifs-and-attaque'
                        ? 'bg-[#93000a]/40 text-[#ffb4ab]'
                        : 'bg-[#262a35] text-[#8c909f]'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Sidebar Footer with Agent telemetry and shortcuts */}
      <div className="p-3 flex flex-col gap-2 bg-[#0a0e18] border-t border-[#1b243b]">
        <div className="flex items-center justify-between font-mono text-[10px] text-[#8c909f] px-1">
          <span className="flex items-center gap-1.5 text-[#dfe2f1]">
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-[#10b981]"></span>
            Local Agent: OK
          </span>
          <span className="text-[#8c909f]">Port 9090</span>
        </div>
        <div className="flex items-center justify-between text-[#c2c6d6] px-1 pt-1 border-t border-[#171b26]">
          <button
            onClick={onOpenSettings}
            className="flex items-center gap-1 font-mono text-[11px] text-[#8c909f] hover:text-[#dfe2f1] transition-colors"
            type="button"
          >
            <span className="material-symbols-outlined text-[14px]">settings</span>
            Paramètres
          </button>
          <button
            onClick={onOpenDocs}
            className="flex items-center gap-1 font-mono text-[11px] text-[#8c909f] hover:text-[#dfe2f1] transition-colors"
            type="button"
          >
            <span className="material-symbols-outlined text-[14px]">help</span>
            Docs
          </button>
        </div>
      </div>
    </aside>
  );
};
