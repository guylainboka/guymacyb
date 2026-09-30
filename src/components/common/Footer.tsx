import React, { useEffect, useState } from 'react';
import { TargetConfig } from '../../types';

interface FooterProps {
  targetConfig: TargetConfig;
  safeMode: boolean;
  setSafeMode: React.Dispatch<React.SetStateAction<boolean>>;
  engineStatus: string;
  findingsCount: number;
}

interface FooterHealthState {
  reachable: boolean;
  endpointsCount: number | null;
  memoryMb: number | null;
  threads: number | null;
}

/**
 * Doctrine « zéro simulation » : ce footer n'affiche que des valeurs réelles.
 * L'ancien code hardcodait « 137 endpoints », « Memory: 412 MB » et
 * « Workers: 4/4 active » dans le JSX — des compteurs fictifs contredits par
 * la base SQLite vide au premier lancement. Désormais :
 *  - endpoints → compteur SQL réel exposé par /api/health (sqlite.endpointsCount)
 *  - mémoire  → process.memoryUsage().heapUsed réel du backend (/api/health.memoryMb)
 *  - workers  → remplacé par « Threads: N » = os.cpus().length réel (/api/health.threads)
 * Si le backend est injoignable, on affiche « — » et « Injoignable » (jamais de valeur inventée).
 */
export const Footer: React.FC<FooterProps> = ({
  targetConfig,
  safeMode,
  setSafeMode,
  engineStatus,
  findingsCount,
}) => {
  const [health, setHealth] = useState<FooterHealthState>({
    reachable: false,
    endpointsCount: null,
    memoryMb: null,
    threads: null,
  });

  useEffect(() => {
    let cancelled = false;

    const pollHealth = async () => {
      try {
        const res = await fetch('/api/health');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        if (cancelled) return;
        setHealth({
          reachable: true,
          endpointsCount:
            typeof data?.sqlite?.endpointsCount === 'number' ? data.sqlite.endpointsCount : null,
          memoryMb: typeof data?.memoryMb === 'number' ? data.memoryMb : null,
          threads: typeof data?.threads === 'number' ? data.threads : null,
        });
      } catch {
        if (cancelled) return;
        // Backend injoignable : état honnête, aucune valeur fictive affichée.
        setHealth({ reachable: false, endpointsCount: null, memoryMb: null, threads: null });
      }
    };

    pollHealth();
    const interval = setInterval(pollHealth, 10000); // 10s (le Header rafraîchit déjà toutes les 5s)
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const dash = '—';

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
          SQLite:{' '}
          {health.reachable ? (
            <>
              <span className="text-[#10b981]">Connected</span> ({health.endpointsCount ?? dash} endpoints, {findingsCount} findings)
            </>
          ) : (
            <span className="text-[#ffb4ab]">Injoignable</span>
          )}
        </span>
      </div>

      <div className="hidden md:flex items-center gap-3">
        <span className="text-[#dfe2f1] font-semibold">Guyma Cyb v1.0.0</span>
        <span className="text-[#424754]">|</span>
        <span title="Mémoire heap réelle du processus backend (process.memoryUsage, via /api/health)">
          Memory: {health.memoryMb !== null ? `${health.memoryMb} MB` : dash}
        </span>
        <span className="text-[#424754]">|</span>
        <span title="Nombre réel de cœurs CPU disponibles côté backend (os.cpus(), via /api/health)">
          Threads: {health.threads !== null ? health.threads : dash}
        </span>
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
