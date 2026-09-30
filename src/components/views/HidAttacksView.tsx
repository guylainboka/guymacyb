import React, { useState } from 'react';

interface PayloadType {
  id: string;
  label: string;
  icon: string;
  description: string;
  accent: string;
}

const PAYLOAD_TYPES: PayloadType[] = [
  {
    id: 'reverse_shell',
    label: 'Reverse Shell PowerShell',
    icon: 'terminal',
    description: 'Établit un reverse-shell TCP vers l\'attaquant via PowerShell.',
    accent: '#ff5d5d',
  },
  {
    id: 'wifi_passwords',
    label: 'Extraction des clés WiFi',
    icon: 'wifi_password',
    description: 'Récupère les profils et mots de passe WiFi en clair (netsh).',
    accent: '#4cd7f6',
  },
  {
    id: 'privilege_escalation',
    label: 'Élévation de privilèges',
    icon: 'shield_lock',
    description: 'Tente d\'ouvrir un shell admin via le menu Win+X (UAC bypass).',
    accent: '#ffb74d',
  },
  {
    id: 'keylogger_drop',
    label: 'Drop de keylogger Python',
    icon: 'keyboard',
    description: 'Dépose un keylogger Python minimal dans %TEMP% et le lance.',
    accent: '#b794f6',
  },
  {
    id: 'ransomware_sim',
    label: 'Rançongiciel de démonstration (payload bénin)',
    icon: 'lock',
    description: 'DÉMO — affiche une note de rançon, aucun chiffrement réel.',
    accent: '#10b981',
  },
];

interface HidResult {
  tool?: string;
  type?: string;
  language?: string;
  payload?: string;
  description?: string;
  mitigation?: string;
  durationMs?: number;
  error?: string;
}

export const HidAttacksView: React.FC = () => {
  const [activeType, setActiveType] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [result, setResult] = useState<HidResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  const handleSelect = async (typeId: string) => {
    setActiveType(typeId);
    setIsLoading(true);
    setError(null);
    setResult(null);
    setCopied(false);
    try {
      const res = await fetch('/api/hid/payload', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: typeId }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data?.error || `Échec HTTP ${res.status}`);
      } else if (data?.error) {
        setError(data.error);
      } else {
        setResult(data);
      }
    } catch (e: any) {
      setError(e?.message || 'Échec de la génération du payload HID');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = async () => {
    if (!result?.payload) return;
    try {
      await navigator.clipboard.writeText(result.payload);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setError('Clipboard indisponible (HTTPS requis ou navigateur restrictif).');
    }
  };

  return (
    <div className="h-full overflow-y-auto bg-[#0a0e18] text-[#dfe2f1] p-6">
      <div className="max-w-7xl mx-auto">
        {/* En-tête */}
        <div className="mb-6">
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <span className="material-symbols-outlined text-[#ff5d5d]">keyboard</span>
            HID Attacks — DuckyScript Arsenal
          </h1>
          <p className="text-sm text-[#8c909f] mt-1">
            Génération de payloads DuckyScript réels et fonctionnels pour Hak5 Rubber Ducky, Flipper Zero, ou gadget configfs.
          </p>
        </div>

        {/* Avertissement légal */}
        <div className="mb-6 px-4 py-3 rounded bg-[#ffb000]/10 border border-[#ffb000]/30 text-[#ffd152] text-xs font-mono flex items-start gap-2">
          <span className="material-symbols-outlined text-[18px]">warning</span>
          <div>
            <div className="font-semibold mb-0.5">Usage autorisé uniquement</div>
            <div>
              Ces payloads DuckyScript sont RÉELS et fonctionnels. L'exécution nécessite un device USB HID (Hak5 Rubber Ducky,
              Flipper Zero, ou gadget configfs). À n'utiliser que sur des systèmes vous appartenant ou avec autorisation
              explicite du propriétaire.
            </div>
          </div>
        </div>

        {/* Grille de types de payloads */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 mb-6">
          {PAYLOAD_TYPES.map((pt) => (
            <button
              key={pt.id}
              onClick={() => handleSelect(pt.id)}
              type="button"
              className={`text-left p-4 rounded-lg border transition-all ${
                activeType === pt.id
                  ? 'bg-[#1f2433] border-[#4d8eff]'
                  : 'bg-[#171b26] border-[#24314c] hover:border-[#3b486a] hover:bg-[#1a1f2c]'
              }`}
            >
              <div className="flex items-center gap-3 mb-2">
                <span
                  className="material-symbols-outlined text-[24px]"
                  style={{ color: pt.accent }}
                >
                  {pt.icon}
                </span>
                <div className="text-sm font-semibold text-[#dfe2f1]">{pt.label}</div>
              </div>
              <div className="text-[11px] text-[#8c909f] font-mono leading-relaxed">
                {pt.description}
              </div>
            </button>
          ))}
        </div>

        {/* Erreur */}
        {error && (
          <div className="px-4 py-3 mb-4 rounded bg-[#93000a]/20 border border-[#93000a]/40 text-[#ffb4ab] text-sm font-mono flex items-start gap-2">
            <span className="material-symbols-outlined text-[18px]">error</span>
            <div>
              <div className="font-semibold mb-0.5">Échec de la génération</div>
              <div className="text-[12px]">{error}</div>
            </div>
          </div>
        )}

        {/* Loading */}
        {isLoading && (
          <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-6 text-center">
            <span className="material-symbols-outlined text-[#4d8eff] animate-spin inline-block text-[24px]">
              progress_activity
            </span>
            <div className="text-xs text-[#8c909f] mt-2 font-mono">Génération du payload DuckyScript…</div>
          </div>
        )}

        {/* Résultat */}
        {result && !isLoading && (
          <div className="space-y-4">
            {/* Header bar */}
            <div className="bg-[#171b26] border border-[#24314c] rounded-lg px-4 py-3 flex items-center justify-between">
              <div className="text-xs font-mono text-[#8c909f]">
                Type: <span className="text-[#4cd7f6]">{result.type}</span> •
                {' '}Langage: <span className="text-[#4cd7f6]">{result.language}</span> •
                {' '}{result.durationMs ? `${result.durationMs}ms` : ''}
              </div>
              <button
                onClick={handleCopy}
                type="button"
                className="px-3 py-1.5 bg-[#4cd7f6]/15 border border-[#4cd7f6]/40 text-[#4cd7f6] rounded text-xs font-medium hover:bg-[#4cd7f6]/25 flex items-center gap-1.5 transition-colors"
              >
                <span className="material-symbols-outlined text-[14px]">
                  {copied ? 'check' : 'content_copy'}
                </span>
                {copied ? 'Copié !' : 'Copier'}
              </button>
            </div>

            {/* Description + mitigation */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4">
                <div className="text-[10px] text-[#8c909f] font-mono uppercase mb-1 flex items-center gap-1.5">
                  <span className="material-symbols-outlined text-[14px] text-[#4d8eff]">description</span>
                  Description
                </div>
                <div className="text-xs text-[#c2c6d6] leading-relaxed">
                  {result.description || '—'}
                </div>
              </div>
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4">
                <div className="text-[10px] text-[#8c909f] font-mono uppercase mb-1 flex items-center gap-1.5">
                  <span className="material-symbols-outlined text-[14px] text-emerald-400">shield</span>
                  Mitigation
                </div>
                <div className="text-xs text-[#c2c6d6] leading-relaxed">
                  {result.mitigation || '—'}
                </div>
              </div>
            </div>

            {/* Payload block */}
            <div className="bg-[#171b26] border border-[#24314c] rounded-lg overflow-hidden">
              <div className="px-4 py-2 border-b border-[#24314c] flex items-center justify-between">
                <div className="text-[10px] text-[#8c909f] font-mono uppercase flex items-center gap-1.5">
                  <span className="material-symbols-outlined text-[14px] text-[#ff5d5d]">code</span>
                  Payload DuckyScript
                </div>
                <div className="text-[10px] text-[#8c909f] font-mono">
                  {result.payload ? `${result.payload.length} chars` : ''}
                </div>
              </div>
              <pre className="bg-[#0a0e18] p-4 text-[11px] font-mono text-[#c2c6d6] max-h-96 overflow-y-auto whitespace-pre-wrap break-all">
{result.payload || '(payload vide)'}
              </pre>
            </div>
          </div>
        )}

        {/* État initial */}
        {!isLoading && !result && !error && (
          <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-8 text-center">
            <span className="material-symbols-outlined text-[48px] text-[#4d8eff] opacity-40">keyboard</span>
            <div className="text-sm text-[#8c909f] mt-2">
              Sélectionnez un type de payload ci-dessus pour générer le DuckyScript réel.
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
