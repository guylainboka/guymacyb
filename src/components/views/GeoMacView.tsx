import React, { useState } from 'react';

interface GeoMacResult {
  tool?: string;
  mac?: string;
  oui?: string;
  vendor?: string;
  vendorFull?: string;
  country?: string;
  address?: string;
  latitude?: number;
  lat?: number;
  longitude?: number;
  lng?: number;
  latLng?: [number, number];
  source?: string;
  hasCoordinates?: boolean;
  wigleApi?: boolean;
  output?: string;
  // geomac-locate.sh returns `note` (e.g. WiGLE-disabled explanation) and a
  // null `error` — we surface the note to the user.
  note?: string | null;
  accuracy?: number | null;
  durationMs?: number;
  error?: string | null;
}

export const GeoMacView: React.FC = () => {
  const [mac, setMac] = useState<string>('00:1B:44:11:3A:B7');
  const [isLocating, setIsLocating] = useState<boolean>(false);
  const [result, setResult] = useState<GeoMacResult | null>(null);

  const handleLocate = async () => {
    if (!mac.trim()) return;
    setIsLocating(true);
    setResult(null);
    try {
      const res = await fetch('/api/geomac/locate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mac: mac.trim() }),
      });
      const data = await res.json();
      setResult(data);
    } catch (e: any) {
      setResult({ error: e?.message || 'Échec de la localisation MAC' });
    } finally {
      setIsLocating(false);
    }
  };

  // Résolution des coords dans différents formats possibles du backend
  const lat = result?.latitude ?? result?.lat ?? (Array.isArray(result?.latLng) ? result!.latLng![0] : undefined);
  const lng = result?.longitude ?? result?.lng ?? (Array.isArray(result?.latLng) ? result!.latLng![1] : undefined);
  const hasCoords = (typeof lat === 'number' && typeof lng === 'number') || result?.hasCoordinates;

  const osmSrc = (typeof lat === 'number' && typeof lng === 'number')
    ? (() => {
        const d = 0.01;
        const bbox = `${(lng as number) - d}%2C${(lat as number) - d}%2C${(lng as number) + d}%2C${(lat as number) + d}`;
        return `https://www.openstreetmap.org/export/embed.html?bbox=${bbox}&marker=${(lat as number)}%2C${(lng as number)}`;
      })()
    : null;

  return (
    <div className="h-full overflow-y-auto bg-[#0a0e18] text-[#dfe2f1] p-6">
      <div className="max-w-7xl mx-auto">
        {/* En-tête */}
        <div className="mb-6">
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <span className="material-symbols-outlined text-[#4cd7f6]">location_on</span>
            GeoMac — Géolocalisation d'adresses MAC
          </h1>
          <p className="text-sm text-[#8c909f] mt-1">
            Identification du fabriquant via la base OUI IEEE + géoloc optionnelle via WiGLE (clé API requise).
          </p>
        </div>

        {/* Formulaire */}
        <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4 mb-6">
          <div className="flex flex-wrap gap-3 items-end">
            <div className="flex-1 min-w-[260px]">
              <label className="block text-xs text-[#8c909f] mb-1 font-mono">Adresse MAC</label>
              <input
                type="text"
                value={mac}
                onChange={(e) => setMac(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleLocate()}
                placeholder="00:1B:44:11:3A:B7"
                className="w-full px-3 py-2 bg-[#0a0e18] border border-[#24314c] rounded text-sm font-mono text-[#dfe2f1] focus:border-[#4cd7f6] outline-none"
              />
            </div>
            <button
              onClick={handleLocate}
              disabled={isLocating}
              className="px-5 py-2 bg-[#4cd7f6]/15 border border-[#4cd7f6]/40 text-[#4cd7f6] rounded text-sm font-medium hover:bg-[#4cd7f6]/25 disabled:opacity-50 flex items-center gap-2 transition-colors"
              type="button"
            >
              {isLocating ? (
                <><span className="material-symbols-outlined animate-spin text-[18px]">progress_activity</span> Localisation...</>
              ) : (
                <><span className="material-symbols-outlined text-[18px]">my_location</span> Localiser</>
              )}
            </button>
          </div>
          <p className="text-[11px] text-[#8c909f] mt-2 font-mono">
            OUI vendor via base IEEE registar (réel) • coordonnées GPS optionnelles via WiGLE API (env <code>WIGLE_API_KEY</code>).
          </p>
        </div>

        {/* Error */}
        {result?.error && (
          <div className="px-4 py-3 mb-4 rounded bg-[#93000a]/20 border border-[#93000a]/40 text-[#ffb4ab] text-sm font-mono flex items-start gap-2">
            <span className="material-symbols-outlined text-[18px]">error</span>
            <div>
              <div className="font-semibold mb-0.5">Localisation échouée</div>
              <div className="text-[12px]">{result.error}</div>
            </div>
          </div>
        )}

        {/* Résultats */}
        {result && !result.error && (
          <div className="space-y-4">
            {/* Vendor card */}
            <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-5">
              <div className="flex items-start gap-4">
                <div className="w-14 h-14 rounded-lg bg-[#0a0e18] border border-[#24314c] flex items-center justify-center shrink-0">
                  <span className="material-symbols-outlined text-[28px] text-[#4cd7f6]">memory</span>
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-[10px] text-[#8c909f] font-mono uppercase mb-1">Fabriquant (OUI IEEE)</div>
                  <div className="text-lg font-bold text-[#dfe2f1]">{result.vendor || result.vendorFull || 'Inconnu'}</div>
                  <div className="text-xs text-[#8c909f] font-mono mt-1">
                    OUI: <span className="text-[#4cd7f6]">{result.oui || '—'}</span>
                    {' • '}MAC: <span className="text-[#c2c6d6]">{result.mac}</span>
                  </div>
                  {result.country && (
                    <div className="text-xs text-[#8c909f] font-mono mt-1">
                      Pays: <span className="text-[#dfe2f1]">{result.country}</span>
                    </div>
                  )}
                  {result.address && (
                    <div className="text-xs text-[#8c909f] font-mono mt-1">
                      Adresse: <span className="text-[#dfe2f1]">{result.address}</span>
                    </div>
                  )}
                  <div className="text-[10px] text-[#8c909f] font-mono mt-2">
                    Source: <span className="text-[#4cd7f6]">{result.source || result.tool || 'oui'}</span>
                    {result.durationMs ? ` • ${result.durationMs}ms` : ''}
                  </div>
                </div>
              </div>
            </div>

            {/* Carte OSM */}
            {hasCoords && osmSrc ? (
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg overflow-hidden">
                <div className="px-4 py-2 border-b border-[#24314c] flex items-center justify-between">
                  <div className="text-xs font-mono text-[#8c909f]">
                    Coordonnées: <span className="text-[#4cd7f6]">{typeof lat === 'number' ? lat.toFixed(5) : '—'}, {typeof lng === 'number' ? lng.toFixed(5) : '—'}</span>
                  </div>
                  <div className="text-[10px] text-[#8c909f]">Carte: OpenStreetMap</div>
                </div>
                <iframe
                  title="OSM map"
                  src={osmSrc}
                  className="w-full h-[420px] bg-[#0a0e18]"
                  loading="lazy"
                />
                <div className="px-4 py-2 border-t border-[#24314c] text-[10px] text-[#8c909f] font-mono">
                  <a
                    href={`https://www.openstreetmap.org/?mlat=${lat}&mlon=${lng}#map=14/${lat}/${lng}`}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="text-[#4cd7f6] hover:underline"
                  >
                    Ouvrir dans OpenStreetMap ↗
                  </a>
                </div>
              </div>
            ) : (
              <div className="px-4 py-3 rounded bg-[#171b26] border border-amber-500/30 text-amber-400 text-sm font-mono flex items-start gap-2">
                <span className="material-symbols-outlined text-[18px]">info</span>
                <div>
                  <div className="font-semibold mb-0.5">Pas de coordonnées GPS</div>
                  <div className="text-[12px] text-[#c2c6d6]">
                    {result.note
                      ? result.note
                      : 'WiGLE API key (WIGLE_API_KEY env) requise pour la géolocalisation réelle. Vendor OUI identifié.'}
                  </div>
                </div>
              </div>
            )}

            {/* Sortie brute si présente */}
            {result.output && (
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                <div className="text-[10px] text-[#8c909f] font-mono uppercase mb-1">Sortie brute du script</div>
                <pre className="bg-[#0a0e18] border border-[#24314c] rounded p-3 text-[11px] font-mono text-[#c2c6d6] max-h-64 overflow-y-auto whitespace-pre-wrap break-all">
{result.output}
                </pre>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
