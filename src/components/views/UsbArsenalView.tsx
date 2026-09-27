import React, { useState } from 'react';

interface Gadget {
  name?: string;
  idVendor?: string;
  idProduct?: string;
  manufacturer?: string;
  product?: string;
  serial?: string;
  UDC?: string;
  configs?: string[];
  functions?: string[];
}

interface UsbResult {
  tool?: string;
  action?: string;
  profile?: string;
  platform?: string;
  configfsMounted?: boolean;
  availableUDCs?: string[];
  gadgets?: Gadget[];
  currentGadgets?: number;
  applied?: boolean;
  boundUDC?: string;
  function?: string;
  functionType?: string;
  gadgetName?: string;
  idVendor?: string;
  idProduct?: string;
  udcs?: string[];
  durationMs?: number;
  error?: string;
}

const PROFILES: { id: string; label: string; icon: string; desc: string }[] = [
  { id: 'hid-keyboard', label: 'HID Keyboard', icon: 'keyboard', desc: 'Clavier HID (Logitech 0x046d:c31c)' },
  { id: 'mass-storage', label: 'Mass Storage', icon: 'usb', desc: 'Stockage de masse USB (Kingston 0x0951:1657)' },
  { id: 'rndis', label: 'RNDIS Ethernet', icon: 'lan', desc: 'Adaptateur réseau RNDIS (0x0525:a4a2)' },
  { id: 'ecm', label: 'CDC ECM Ethernet', icon: 'lan', desc: 'Adaptateur réseau CDC-ECM (0x0525:a4d1)' },
  { id: 'acm', label: 'CDC ACM Serial', icon: 'cable', desc: 'Port série CDC-ACM (0x0525:a4a7)' },
];

export const UsbArsenalView: React.FC = () => {
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [result, setResult] = useState<UsbResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedProfile, setSelectedProfile] = useState<string>('hid-keyboard');

  const call = async (action: string, profile?: string) => {
    setIsLoading(true);
    setError(null);
    setResult(null);
    try {
      const body: any = { action };
      if (profile) body.profile = profile;
      const res = await fetch('/api/usb-arsenal', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data?.error || `Échec HTTP ${res.status}`);
      } else {
        setResult(data);
        if (data?.error && !data?.applied) {
          setError(data.error);
        }
      }
    } catch (e: any) {
      setError(e?.message || 'Échec de l\'appel USB Arsenal');
    } finally {
      setIsLoading(false);
    }
  };

  const gadgets = result?.gadgets || [];

  return (
    <div className="h-full overflow-y-auto bg-[#0a0e18] text-[#dfe2f1] p-6">
      <div className="max-w-7xl mx-auto">
        {/* En-tête */}
        <div className="mb-6">
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <span className="material-symbols-outlined text-[#4cd7f6]">usb</span>
            USB Arsenal — Gestion de gadgets configfs
          </h1>
          <p className="text-sm text-[#8c909f] mt-1">
            Création et binding de gadgets USB via configfs (HID, mass-storage, RNDIS, ECM, ACM).
          </p>
        </div>

        {/* Avertissement */}
        <div className="mb-6 px-4 py-3 rounded bg-[#ffb000]/10 border border-[#ffb000]/30 text-[#ffd152] text-xs font-mono flex items-start gap-2">
          <span className="material-symbols-outlined text-[18px]">warning</span>
          <div>
            <div className="font-semibold mb-0.5">Plateforme Linux/WSL + USB OTG requis</div>
            <div>
              USB gadget profiling nécessite Linux/WSL avec configfs (<code className="text-[#4cd7f6]">/sys/kernel/config/usb_gadget</code>) + un câble USB OTG.
              Sur Windows sans WSL, ou sans UDC disponible, un message honnête sera retourné.
            </div>
          </div>
        </div>

        {/* Actions rapides */}
        <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4 mb-4">
          <div className="text-[10px] text-[#8c909f] font-mono uppercase mb-3">Actions rapides</div>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => call('list')}
              disabled={isLoading}
              type="button"
              className="px-4 py-2 bg-[#4cd7f6]/15 border border-[#4cd7f6]/40 text-[#4cd7f6] rounded text-sm font-medium hover:bg-[#4cd7f6]/25 disabled:opacity-50 flex items-center gap-2 transition-colors"
            >
              <span className="material-symbols-outlined text-[18px]">list</span>
              Lister les gadgets
            </button>
            <button
              onClick={() => call('status')}
              disabled={isLoading}
              type="button"
              className="px-4 py-2 bg-[#4d8eff]/15 border border-[#4d8eff]/40 text-[#4d8eff] rounded text-sm font-medium hover:bg-[#4d8eff]/25 disabled:opacity-50 flex items-center gap-2 transition-colors"
            >
              <span className="material-symbols-outlined text-[18px]">monitor_heart</span>
              Statut
            </button>
          </div>
        </div>

        {/* Apply profile */}
        <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4 mb-4">
          <div className="text-[10px] text-[#8c909f] font-mono uppercase mb-3">Appliquer un profil</div>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2 mb-3">
            {PROFILES.map((p) => (
              <button
                key={p.id}
                onClick={() => setSelectedProfile(p.id)}
                type="button"
                className={`text-left p-3 rounded border transition-all ${
                  selectedProfile === p.id
                    ? 'bg-[#1f2433] border-[#4d8eff]'
                    : 'bg-[#0a0e18] border-[#24314c] hover:border-[#3b486a]'
                }`}
              >
                <div className="flex items-center gap-1.5 mb-1">
                  <span className="material-symbols-outlined text-[16px] text-[#4cd7f6]">{p.icon}</span>
                  <span className="text-[11px] font-semibold text-[#dfe2f1]">{p.label}</span>
                </div>
                <div className="text-[9px] text-[#8c909f] font-mono leading-tight">{p.desc}</div>
              </button>
            ))}
          </div>
          <button
            onClick={() => call('apply', selectedProfile)}
            disabled={isLoading}
            type="button"
            className="px-5 py-2 bg-[#10b981]/15 border border-[#10b981]/40 text-[#10b981] rounded text-sm font-medium hover:bg-[#10b981]/25 disabled:opacity-50 flex items-center gap-2 transition-colors"
          >
            {isLoading ? (
              <><span className="material-symbols-outlined text-[18px] animate-spin">progress_activity</span> Application…</>
            ) : (
              <><span className="material-symbols-outlined text-[18px]">bolt</span> Appliquer « {selectedProfile} »</>
            )}
          </button>
        </div>

        {/* Erreur */}
        {error && (
          <div className="px-4 py-3 mb-4 rounded bg-[#93000a]/20 border border-[#93000a]/40 text-[#ffb4ab] text-sm font-mono flex items-start gap-2">
            <span className="material-symbols-outlined text-[18px]">error</span>
            <div>
              <div className="font-semibold mb-0.5">Opération impossible</div>
              <div className="text-[12px]">{error}</div>
            </div>
          </div>
        )}

        {/* Loading */}
        {isLoading && !error && (
          <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-6 text-center">
            <span className="material-symbols-outlined text-[#4d8eff] animate-spin inline-block text-[24px]">
              progress_activity
            </span>
            <div className="text-xs text-[#8c909f] mt-2 font-mono">Opération USB en cours…</div>
          </div>
        )}

        {/* Résultat */}
        {result && !isLoading && (
          <div className="space-y-4">
            {/* Summary */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                <div className="text-[10px] text-[#8c909f] font-mono uppercase">Plateforme</div>
                <div className="text-sm font-bold text-[#dfe2f1]">{result.platform || '—'}</div>
              </div>
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                <div className="text-[10px] text-[#8c909f] font-mono uppercase">configfs</div>
                <div className={`text-sm font-bold ${result.configfsMounted ? 'text-emerald-400' : 'text-[#ffb4ab]'}`}>
                  {result.configfsMounted ? 'Monté' : 'Non monté'}
                </div>
              </div>
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                <div className="text-[10px] text-[#8c909f] font-mono uppercase">UDCs dispo</div>
                <div className="text-sm font-bold text-[#4cd7f6]">{result.availableUDCs?.length || 0}</div>
              </div>
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                <div className="text-[10px] text-[#8c909f] font-mono uppercase">Gadgets actuels</div>
                <div className="text-sm font-bold text-[#4d8eff]">{result.currentGadgets ?? gadgets.length}</div>
              </div>
            </div>

            {/* Applied banner */}
            {result.applied && (
              <div className="px-4 py-3 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-sm font-mono flex items-start gap-2">
                <span className="material-symbols-outlined text-[18px]">check_circle</span>
                <div>
                  <div className="font-semibold">Gadget appliqué</div>
                  <div className="text-[12px] text-[#c2c6d6]">
                    {result.gadgetName} ({result.idVendor}:{result.idProduct}) • function={result.function} •
                    UDC={result.boundUDC || '(non bindé — USB OTG requis)'}
                  </div>
                </div>
              </div>
            )}

            {/* Raw JSON */}
            <div className="bg-[#171b26] border border-[#24314c] rounded-lg overflow-hidden">
              <div className="px-4 py-2 border-b border-[#24314c] flex items-center justify-between">
                <div className="text-[10px] text-[#8c909f] font-mono uppercase flex items-center gap-1.5">
                  <span className="material-symbols-outlined text-[14px] text-[#4cd7f6]">code</span>
                  Détails gadgets
                </div>
                <div className="text-[10px] text-[#8c909f] font-mono">
                  action: {result.action} • {result.durationMs ? `${result.durationMs}ms` : ''}
                </div>
              </div>
              <pre className="bg-[#0a0e18] p-4 text-[11px] font-mono text-[#c2c6d6] max-h-96 overflow-y-auto whitespace-pre-wrap break-all">
{JSON.stringify(gadgets, null, 2)}
              </pre>
            </div>
          </div>
        )}

        {/* État initial */}
        {!isLoading && !result && !error && (
          <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-8 text-center">
            <span className="material-symbols-outlined text-[48px] text-[#4cd7f6] opacity-40">usb</span>
            <div className="text-sm text-[#8c909f] mt-2">
              Utilisez « Lister les gadgets » ou « Appliquer un profil » ci-dessus.
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
