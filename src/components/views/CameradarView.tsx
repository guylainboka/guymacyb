import React, { useState } from 'react';

interface Camera {
  ip: string;
  port: number;
  realm: string;
  model: string;
  found: boolean;
  cracked: boolean;
  credentials?: { user: string; pass: string };
}

interface CameradarResult {
  tool?: string;
  subnet?: string;
  cameras?: Camera[];
  totalCameras?: number;
  crackedCount?: number;
  durationMs?: number;
  error?: string;
}

export const CameradarView: React.FC = () => {
  const [subnet, setSubnet] = useState<string>('');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [result, setResult] = useState<CameradarResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    setIsScanning(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch('/api/cameradar/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subnet: subnet || undefined }),
      });
      const data = await res.json();
      setResult(data);
      if (data?.error && !(data?.cameras?.length)) {
        setError(data.error);
      }
    } catch (e: any) {
      setError(e?.message || 'Échec du scan RTSP');
    } finally {
      setIsScanning(false);
    }
  };

  const cameras = result?.cameras || [];

  return (
    <div className="h-full overflow-y-auto bg-[#0a0e18] text-[#dfe2f1] p-6">
      <div className="max-w-7xl mx-auto">
        {/* En-tête */}
        <div className="mb-6">
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <span className="material-symbols-outlined text-[#ff5d5d]">videocam</span>
            Cameradar — Sweep RTSP
          </h1>
          <p className="text-sm text-[#8c909f] mt-1">
            Découverte de caméras IP RTSP (port 554) + test des credentials par défaut.
          </p>
        </div>

        {/* Avertissement */}
        <div className="mb-6 px-4 py-3 rounded bg-[#ffb000]/10 border border-[#ffb000]/30 text-[#ffd152] text-xs font-mono flex items-start gap-2">
          <span className="material-symbols-outlined text-[18px]">warning</span>
          <div>
            <div className="font-semibold mb-0.5">Usage autorisé uniquement</div>
            <div>
              Scan RÉEL des caméras RTSP (port 554) + test des credentials par défaut (admin/admin, root/root…).
              À n'utiliser que sur votre propre réseau ou avec autorisation explicite du propriétaire.
            </div>
          </div>
        </div>

        {/* Action */}
        <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4 mb-4">
          <div className="flex flex-wrap items-end gap-3">
            <div className="flex-1 min-w-[260px]">
              <label className="block text-xs text-[#8c909f] mb-1 font-mono">
                Subnet (optionnel — auto-détecté si vide)
              </label>
              <input
                type="text"
                value={subnet}
                onChange={(e) => setSubnet(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleScan()}
                placeholder="192.168.1.0/24 ou 192.168.1 (vide = auto)"
                className="w-full px-3 py-2 bg-[#0a0e18] border border-[#24314c] rounded text-sm font-mono text-[#dfe2f1] focus:border-[#4d8eff] outline-none"
              />
            </div>
            <button
              onClick={handleScan}
              disabled={isScanning}
              type="button"
              className="px-5 py-2 bg-[#ff5d5d]/15 border border-[#ff5d5d]/40 text-[#ff5d5d] rounded text-sm font-medium hover:bg-[#ff5d5d]/25 disabled:opacity-50 flex items-center gap-2 transition-colors"
            >
              {isScanning ? (
                <><span className="material-symbols-outlined animate-spin text-[18px]">progress_activity</span> Scan en cours…</>
              ) : (
                <><span className="material-symbols-outlined text-[18px]">play_arrow</span> Scanner</>
              )}
            </button>
          </div>
          <p className="text-[11px] text-[#8c909f] mt-2 font-mono">
            Sweep TCP rootless /24 sur port 554 → DESCRIBE RTSP (realm/model) → test 20 paires de credentials par défaut.
          </p>
        </div>

        {/* Erreur */}
        {error && (
          <div className="px-4 py-3 mb-4 rounded bg-[#93000a]/20 border border-[#93000a]/40 text-[#ffb4ab] text-sm font-mono flex items-start gap-2">
            <span className="material-symbols-outlined text-[18px]">error</span>
            <div>
              <div className="font-semibold mb-0.5">Scan impossible</div>
              <div className="text-[12px]">{error}</div>
            </div>
          </div>
        )}

        {/* État initial */}
        {!isScanning && !result && !error && (
          <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-8 text-center">
            <span className="material-symbols-outlined text-[48px] text-[#ff5d5d] opacity-40">videocam</span>
            <div className="text-sm text-[#8c909f] mt-2">
              Lancez un scan RTSP sur votre sous-réseau local pour découvrir les caméras IP exposées.
            </div>
          </div>
        )}

        {/* Loading */}
        {isScanning && (
          <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-6 text-center">
            <span className="material-symbols-outlined text-[#ff5d5d] animate-spin inline-block text-[24px]">
              progress_activity
            </span>
            <div className="text-xs text-[#8c909f] mt-2 font-mono">
              Sweep /24 sur port 554 + RTSP DESCRIBE + credential sweep… (jusqu'à 90s)
            </div>
          </div>
        )}

        {/* Résultat */}
        {result && !isScanning && (
          <>
            {/* Summary */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                <div className="text-[10px] text-[#8c909f] font-mono uppercase">Subnet scanné</div>
                <div className="text-sm font-bold text-[#4cd7f6] font-mono">{result.subnet || '—'}</div>
              </div>
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                <div className="text-[10px] text-[#8c909f] font-mono uppercase">Caméras trouvées</div>
                <div className="text-2xl font-bold text-[#dfe2f1]">{result.totalCameras ?? cameras.length}</div>
              </div>
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                <div className="text-[10px] text-[#8c909f] font-mono uppercase">Crackées</div>
                <div className="text-2xl font-bold text-emerald-400">{result.crackedCount ?? 0}</div>
              </div>
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                <div className="text-[10px] text-[#8c909f] font-mono uppercase">Durée</div>
                <div className="text-sm font-bold text-[#8c909f] font-mono">
                  {result.durationMs ? `${result.durationMs}ms` : '—'}
                </div>
              </div>
            </div>

            {result.error && cameras.length === 0 && (
              <div className="px-3 py-2 mb-3 rounded bg-[#93000a]/20 border border-[#93000a]/40 text-[#ffb4ab] text-xs font-mono">
                {result.error}
              </div>
            )}

            {/* Table des caméras */}
            <div className="bg-[#171b26] border border-[#24314c] rounded-lg overflow-hidden">
              <div className="px-4 py-2 border-b border-[#24314c] flex items-center justify-between">
                <div className="text-xs font-mono text-[#8c909f]">
                  Mode: <span className="text-[#4cd7f6]">{result.tool || 'cameradar'}</span>
                </div>
                <div className="text-[10px] text-[#8c909f]">
                  {cameras.length} caméra(s) découverte(s)
                </div>
              </div>
              <div className="max-h-96 overflow-y-auto">
                <table className="w-full text-sm">
                  <thead className="bg-[#0a0e18] sticky top-0">
                    <tr className="text-[10px] text-[#8c909f] font-mono uppercase">
                      <th className="text-left px-3 py-2">IP</th>
                      <th className="text-left px-3 py-2">Port</th>
                      <th className="text-left px-3 py-2">Realm</th>
                      <th className="text-left px-3 py-2">Modèle</th>
                      <th className="text-left px-3 py-2">Découvert</th>
                      <th className="text-left px-3 py-2">Crackée</th>
                      <th className="text-left px-3 py-2">Credentials</th>
                    </tr>
                  </thead>
                  <tbody>
                    {cameras.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="px-3 py-6 text-center text-[#8c909f] text-sm">
                          Aucune caméra RTSP découverte sur ce sous-réseau.
                        </td>
                      </tr>
                    ) : cameras.map((c, i) => (
                      <tr key={`${c.ip}-${i}`} className="border-t border-[#24314c] hover:bg-[#1f2433]">
                        <td className="px-3 py-2 font-mono text-[11px] text-[#dfe2f1]">{c.ip}</td>
                        <td className="px-3 py-2 font-mono text-[11px] text-[#8c909f]">{c.port}</td>
                        <td className="px-3 py-2 text-[11px] text-[#c2c6d6]">{c.realm || '—'}</td>
                        <td className="px-3 py-2 text-[11px] text-[#c2c6d6]">{c.model || '—'}</td>
                        <td className="px-3 py-2">
                          {c.found ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[10px] font-mono">
                              <span className="material-symbols-outlined text-[12px]">check_circle</span> OUI
                            </span>
                          ) : (
                            <span className="text-[10px] text-[#8c909f] font-mono">non</span>
                          )}
                        </td>
                        <td className="px-3 py-2">
                          {c.cracked ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[#ff5d5d]/10 border border-[#ff5d5d]/30 text-[#ff5d5d] text-[10px] font-mono">
                              <span className="material-symbols-outlined text-[12px]">vpn_key</span> OUI
                            </span>
                          ) : (
                            <span className="text-[10px] text-[#8c909f] font-mono">non</span>
                          )}
                        </td>
                        <td className="px-3 py-2 font-mono text-[11px] text-[#4cd7f6]">
                          {c.cracked && c.credentials
                            ? `${c.credentials.user || '(vide)'}:${c.credentials.pass || '(vide)'}`
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
