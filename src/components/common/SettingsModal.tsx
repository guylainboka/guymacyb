import React, { useState } from 'react';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  operatorId: string;
  setOperatorId: (id: string) => void;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({
  isOpen,
  onClose,
  operatorId,
  setOperatorId,
}) => {
  const [threads, setThreads] = useState<number>(8);
  const [rateLimit, setRateLimit] = useState<number>(42);
  const [timeoutMs, setTimeoutMs] = useState<number>(5000);
  const [customHeader, setCustomHeader] = useState<string>('X-Assessment-Agent: ShadowScan/1.0.0');
  const [proxyEnabled, setProxyEnabled] = useState<boolean>(false);
  const [proxyUrl, setProxyUrl] = useState<string>('http://127.0.0.1:8080');

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 animate-in fade-in duration-200">
      <div className="bg-[#171b26] border border-[#24314c] rounded-lg max-w-xl w-full shadow-2xl overflow-hidden flex flex-col font-sans">
        {/* Header */}
        <div className="bg-[#0a0e18] px-5 py-3 border-b border-[#24314c] flex items-center justify-between">
          <div className="flex items-center gap-2 text-[#4cd7f6]">
            <span className="material-symbols-outlined text-[20px]">tune</span>
            <span className="font-mono text-xs font-bold uppercase tracking-wider">
              PARAMÈTRES DU MOTEUR LOCAL SHADOWSCAN
            </span>
          </div>
          <button onClick={onClose} className="text-[#8c909f] hover:text-white" type="button">
            <span className="material-symbols-outlined text-[18px]">close</span>
          </button>
        </div>

        {/* Content */}
        <div className="p-6 flex flex-col gap-4 max-h-[75vh] overflow-y-auto font-mono text-xs">
          {/* Operator identification */}
          <div className="flex flex-col gap-1.5">
            <label className="text-[#c2c6d6] font-semibold flex items-center gap-1.5">
              <span className="material-symbols-outlined text-[15px] text-[#4cd7f6]">badge</span>
              Identifiant d'opérateur (Audit Ledger)
            </label>
            <input
              type="text"
              value={operatorId}
              onChange={(e) => setOperatorId(e.target.value)}
              className="bg-[#0a0e18] border border-[#24314c] rounded px-3 py-2 text-[#dfe2f1] focus:outline-none focus:border-[#3b82f6]"
            />
            <span className="text-[10px] text-[#8c909f]">Inscrit dans les traces cryptographiques locales de SQLite shadow_audit.db.</span>
          </div>

          {/* Concurrency and Rate Limits */}
          <div className="grid grid-cols-2 gap-4">
            <div className="flex flex-col gap-1.5">
              <label className="text-[#c2c6d6] font-semibold">Pool de threads (Workers)</label>
              <select
                value={threads}
                onChange={(e) => setThreads(Number(e.target.value))}
                className="bg-[#0a0e18] border border-[#24314c] rounded px-3 py-2 text-[#dfe2f1] focus:outline-none"
              >
                <option value={2}>2 Threads (Low impact)</option>
                <option value={4}>4 Threads (Balanced)</option>
                <option value={8}>8 Threads (Optimal)</option>
                <option value={16}>16 Threads (Turbo Lab)</option>
              </select>
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-[#c2c6d6] font-semibold">Débit max (req/seconde)</label>
              <input
                type="number"
                value={rateLimit}
                onChange={(e) => setRateLimit(Number(e.target.value))}
                className="bg-[#0a0e18] border border-[#24314c] rounded px-3 py-2 text-[#dfe2f1] focus:outline-none"
              />
            </div>
          </div>

          {/* HTTP Client timeout */}
          <div className="flex flex-col gap-1.5">
            <label className="text-[#c2c6d6] font-semibold">Timeout HTTP (ms)</label>
            <input
              type="number"
              value={timeoutMs}
              onChange={(e) => setTimeoutMs(Number(e.target.value))}
              className="bg-[#0a0e18] border border-[#24314c] rounded px-3 py-2 text-[#dfe2f1] focus:outline-none"
            />
          </div>

          {/* Custom Headers */}
          <div className="flex flex-col gap-1.5">
            <label className="text-[#c2c6d6] font-semibold">En-tête HTTP d'audit personnalisé</label>
            <input
              type="text"
              value={customHeader}
              onChange={(e) => setCustomHeader(e.target.value)}
              className="bg-[#0a0e18] border border-[#24314c] rounded px-3 py-2 text-[#dfe2f1] focus:outline-none"
            />
            <span className="text-[10px] text-[#8c909f]">Permet au WAF de la cible de classifier les requêtes du test autorisé.</span>
          </div>

          {/* Proxy Config */}
          <div className="bg-[#0a0e18] p-3 rounded border border-[#24314c] flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-[#dfe2f1]">Proxy amont (Burp Suite / OWASP ZAP)</span>
              <input
                type="checkbox"
                checked={proxyEnabled}
                onChange={(e) => setProxyEnabled(e.target.checked)}
                className="w-4 h-4 accent-[#4cd7f6] cursor-pointer"
              />
            </div>
            {proxyEnabled && (
              <input
                type="text"
                value={proxyUrl}
                onChange={(e) => setProxyUrl(e.target.value)}
                placeholder="http://127.0.0.1:8080"
                className="bg-[#171b26] border border-[#24314c] rounded px-3 py-1.5 text-[#dfe2f1] focus:outline-none mt-1"
              />
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="bg-[#0a0e18] px-5 py-3 border-t border-[#24314c] flex items-center justify-between">
          <a
            href="/api/database/export"
            download="shadow_core.db"
            className="flex items-center gap-1.5 text-[#8c909f] hover:text-[#4cd7f6] font-mono text-xs transition-colors"
          >
            <span className="material-symbols-outlined text-[15px]">database</span>
            <span>Télécharger la Base SQLite (shadow_core.db)</span>
          </a>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 rounded font-mono text-xs bg-[#4d8eff] hover:bg-[#3b82f6] text-white font-medium"
          >
            Enregistrer & Fermer
          </button>
        </div>
      </div>
    </div>
  );
};
