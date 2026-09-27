import React, { useState } from 'react';

interface LocalDevice {
  ip: string;
  hostname?: string;
  mac?: string;
  vendor?: string;
  discoveredVia: string | string[];
  openPorts?: number[];
  services?: Array<string | { port?: number; service?: string; state?: string }>;
}

interface ScanResult {
  tool?: string;
  mode?: string;
  devices?: LocalDevice[];
  total?: number;
  byProtocol?: Record<string, number>;
  scannedAt?: string;
  durationMs?: number;
  error?: string;
}

const protocolColor = (proto: string): string => {
  switch ((proto || '').toLowerCase()) {
    case 'mdns':
      return 'bg-[#4cd7f6]/10 border border-[#4cd7f6]/30 text-[#4cd7f6]';
    case 'ssdp':
      return 'bg-[#4d8eff]/10 border border-[#4d8eff]/30 text-[#4d8eff]';
    case 'netbios':
      return 'bg-amber-500/10 border border-amber-500/30 text-amber-400';
    case 'rdns':
      return 'bg-[#262a35] border border-[#24314c] text-[#8c909f]';
    case 'tcp':
      return 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-400';
    default:
      return 'bg-[#262a35] border border-[#24314c] text-[#c2c6d6]';
  }
};

export const ReseauLocalView: React.FC = () => {
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    setIsScanning(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch('/api/localnetwork/scan', { method: 'POST' });
      const data = await res.json();
      setResult(data);
      if (data?.error && !data?.devices?.length) {
        setError(data.error);
      }
    } catch (e: any) {
      setError(e?.message || 'Échec du scan réseau local');
    } finally {
      setIsScanning(false);
    }
  };

  const devices = result?.devices || [];
  // The script returns `devices` with a `discoveredVia: string[]` array per device
  // but does NOT return a `byProtocol` summary. Compute it locally so the summary
  // cards reflect actual counts (mDNS / SSDP / NetBIOS / rDNS / TCP).
  const byProtocol: Record<string, number> = {};
  for (const d of devices) {
    const protos = Array.isArray(d.discoveredVia)
      ? d.discoveredVia
      : (d.discoveredVia ? [d.discoveredVia] : []);
    for (const p of protos) {
      const key = (p || '').toLowerCase();
      if (!key) continue;
      byProtocol[key] = (byProtocol[key] || 0) + 1;
    }
    // Also count TCP separately if the device has any open ports.
    if (Array.isArray(d.openPorts) && d.openPorts.length > 0) {
      byProtocol['tcp'] = (byProtocol['tcp'] || 0) + 1;
    }
  }

  return (
    <div className="h-full overflow-y-auto bg-[#0a0e18] text-[#dfe2f1] p-6">
      <div className="max-w-7xl mx-auto">
        {/* En-tête */}
        <div className="mb-6">
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <span className="material-symbols-outlined text-[#4cd7f6]">lan</span>
            Réseau Local — Découverte Rootless
          </h1>
          <p className="text-sm text-[#8c909f] mt-1">
            Détection rootless réelle — mDNS/SSDP/NetBIOS/rDNS + scan TCP. Aucun privilège root requis.
          </p>
        </div>

        {/* Action */}
        <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4 mb-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-sm text-[#dfe2f1] font-medium flex items-center gap-2">
                <span className="material-symbols-outlined text-[18px] text-[#4cd7f6]">sensors</span>
                Scanner le réseau local
              </div>
              <p className="text-[11px] text-[#8c909f] font-mono mt-1">
                multicast mDNS (224.0.0.251:5353) • SSDP (239.255.255.250:1900) • NetBIOS (137) • rDNS /24 sweep • scan TCP top-ports
              </p>
            </div>
            <button
              onClick={handleScan}
              disabled={isScanning}
              className="px-5 py-2 bg-[#4cd7f6]/15 border border-[#4cd7f6]/40 text-[#4cd7f6] rounded text-sm font-medium hover:bg-[#4cd7f6]/25 disabled:opacity-50 flex items-center gap-2 transition-colors"
              type="button"
            >
              {isScanning ? (
                <><span className="material-symbols-outlined animate-spin text-[18px]">progress_activity</span> Scan en cours...</>
              ) : (
                <><span className="material-symbols-outlined text-[18px]">play_arrow</span> Scanner le réseau local</>
              )}
            </button>
          </div>
        </div>

        {/* Error / empty */}
        {error && (
          <div className="px-4 py-3 mb-4 rounded bg-[#93000a]/20 border border-[#93000a]/40 text-[#ffb4ab] text-sm font-mono flex items-start gap-2">
            <span className="material-symbols-outlined text-[18px]">error</span>
            <div>
              <div className="font-semibold mb-0.5">Scan impossible</div>
              <div className="text-[12px]">{error}</div>
            </div>
          </div>
        )}

        {!isScanning && !result && !error && (
          <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-8 text-center">
            <span className="material-symbols-outlined text-[48px] text-[#4cd7f6] opacity-40">lan</span>
            <div className="text-sm text-[#8c909f] mt-2">
              Cliquez sur « Scanner le réseau local » pour découvrir les appareils présents sur ce segment /24.
            </div>
          </div>
        )}

        {/* Results */}
        {result && (
          <>
            {/* Summary cards */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-4">
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                <div className="text-[10px] text-[#8c909f] font-mono uppercase">Total appareils</div>
                <div className="text-2xl font-bold text-[#dfe2f1]">{result.total ?? devices.length}</div>
              </div>
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                <div className="text-[10px] text-[#8c909f] font-mono uppercase">mDNS</div>
                <div className="text-2xl font-bold text-[#4cd7f6]">{byProtocol.mdns || 0}</div>
              </div>
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                <div className="text-[10px] text-[#8c909f] font-mono uppercase">SSDP</div>
                <div className="text-2xl font-bold text-[#4d8eff]">{byProtocol.ssdp || 0}</div>
              </div>
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                <div className="text-[10px] text-[#8c909f] font-mono uppercase">NetBIOS</div>
                <div className="text-2xl font-bold text-amber-400">{byProtocol.netbios || 0}</div>
              </div>
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                <div className="text-[10px] text-[#8c909f] font-mono uppercase">rDNS</div>
                <div className="text-2xl font-bold text-[#8c909f]">{byProtocol.rdns || 0}</div>
              </div>
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                <div className="text-[10px] text-[#8c909f] font-mono uppercase">TCP</div>
                <div className="text-2xl font-bold text-emerald-400">{byProtocol.tcp || 0}</div>
              </div>
            </div>

            {result.error && (
              <div className="px-3 py-2 mb-3 rounded bg-[#93000a]/20 border border-[#93000a]/40 text-[#ffb4ab] text-xs font-mono">
                {result.error}
              </div>
            )}

            {/* Devices table */}
            <div className="bg-[#171b26] border border-[#24314c] rounded-lg overflow-hidden">
              <div className="px-4 py-2 border-b border-[#24314c] flex items-center justify-between">
                <div className="text-xs font-mono text-[#8c909f]">
                  Mode: <span className="text-[#4cd7f6]">{result.mode || result.tool || 'real-scan'}</span>
                </div>
                <div className="text-[10px] text-[#8c909f]">
                  {result.scannedAt} • {result.durationMs ? `${result.durationMs}ms` : ''}
                </div>
              </div>
              <div className="max-h-96 overflow-y-auto">
                <table className="w-full text-sm">
                  <thead className="bg-[#0a0e18] sticky top-0">
                    <tr className="text-[10px] text-[#8c909f] font-mono uppercase">
                      <th className="text-left px-3 py-2">IP</th>
                      <th className="text-left px-3 py-2">Hostname</th>
                      <th className="text-left px-3 py-2">MAC</th>
                      <th className="text-left px-3 py-2">Fabriquant</th>
                      <th className="text-left px-3 py-2">Protocole</th>
                      <th className="text-left px-3 py-2">Ports ouverts</th>
                      <th className="text-left px-3 py-2">Services</th>
                    </tr>
                  </thead>
                  <tbody>
                    {devices.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="px-3 py-6 text-center text-[#8c909f] text-sm">
                          Aucun appareil découvert. Réseau peut être silencieux ou isolé.
                        </td>
                      </tr>
                    ) : devices.map((d, i) => (
                      <tr key={`${d.ip}-${i}`} className="border-t border-[#24314c] hover:bg-[#1f2433]">
                        <td className="px-3 py-2 font-mono text-[11px] text-[#dfe2f1]">{d.ip}</td>
                        <td className="px-3 py-2 text-[#c2c6d6]">{d.hostname || <span className="italic text-[#8c909f]">—</span>}</td>
                        <td className="px-3 py-2 font-mono text-[11px] text-[#8c909f]">{d.mac || '—'}</td>
                        <td className="px-3 py-2 text-[11px] text-[#8c909f]">{d.vendor || '—'}</td>
                        <td className="px-3 py-2">
                          {(() => {
                            const protos = Array.isArray(d.discoveredVia)
                              ? d.discoveredVia
                              : (d.discoveredVia ? [d.discoveredVia] : ['?']);
                            return protos.map((p, idx) => (
                              <span key={idx} className={`inline-block mr-1 px-2 py-0.5 text-[10px] font-mono rounded border ${protocolColor(p)}`}>
                                {(p || '?').toUpperCase()}
                              </span>
                            ));
                          })()}
                        </td>
                        <td className="px-3 py-2 font-mono text-[11px] text-emerald-400">
                          {d.openPorts && d.openPorts.length > 0 ? d.openPorts.join(', ') : '—'}
                        </td>
                        <td className="px-3 py-2 text-[11px] text-[#8c909f]">
                          {d.services && d.services.length > 0
                            ? d.services.map((s) =>
                                typeof s === 'string'
                                  ? s
                                  : `${s.port || '?'}/${s.service || s.state || '?'}`
                              ).join(', ')
                            : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
};
