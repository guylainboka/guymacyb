import React, { useState } from 'react';

type Tab = 'searchsploit' | 'hashcat';

interface ExploitEntry {
  id?: string;
  title?: string;
  type?: string;
  platform?: string;
  date?: string;
  path?: string;
  [k: string]: any;
}

interface SearchsploitResult {
  tool?: string;
  query?: string;
  results?: ExploitEntry[];
  count?: number;
  installed?: boolean;
  output?: string;
  error?: string;
}

interface HashcatResult {
  tool?: string;
  // NOTE: arsenal-hashcat.sh returns `mode` as a STRING (e.g. "0"), not a number.
  mode?: number | string;
  hash?: string;
  native?: boolean;            // true when hashcat binary is installed
  // NOTE: arsenal-hashcat.sh returns `cracked` as the cracked plaintext (string)
  // OR null when not cracked. The view's interface historically had `cracked: boolean`
  // + `password: string` — but the API never returns those. Treat any non-null
  // `cracked` value as success and use it as the plaintext for the success banner.
  cracked?: string | null | boolean;
  password?: string;            // not returned by the API (kept for backward compat)
  plaintext?: string;           // not returned by the API (kept for backward compat)
  output?: string;
  exitCode?: number;
  durationMs?: number;
  error?: string;
}

const HASHCAT_MODES = [
  { value: 0, label: '0 — MD5' },
  { value: 100, label: '100 — SHA1' },
  { value: 1400, label: '1400 — SHA256' },
  { value: 1000, label: '1000 — NTLM' },
  { value: 1800, label: '1800 — sha512crypt $6$' },
  { value: 3200, label: '3200 — bcrypt $2b$' },
  { value: 13100, label: '13100 — Kerberos 5' },
];

export const ArsenalView: React.FC = () => {
  const [tab, setTab] = useState<Tab>('searchsploit');

  // Searchsploit state
  const [query, setQuery] = useState<string>('apache 2.4');
  const [isSearching, setIsSearching] = useState<boolean>(false);
  const [ssResult, setSsResult] = useState<SearchsploitResult | null>(null);

  // Hashcat state
  const [hash, setHash] = useState<string>('5f4dcc3b5aa765d61d8327deb882cf99'); // md5 of "password"
  const [mode, setMode] = useState<number>(0);
  const [wordlist, setWordlist] = useState<string>('/usr/share/wordlists/rockyou.txt');
  const [isCracking, setIsCracking] = useState<boolean>(false);
  const [hcResult, setHcResult] = useState<HashcatResult | null>(null);

  const handleSearchsploit = async () => {
    if (!query.trim()) return;
    setIsSearching(true);
    setSsResult(null);
    try {
      const res = await fetch('/api/arsenal/searchsploit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query }),
      });
      const data = await res.json();
      setSsResult(data);
    } catch (e: any) {
      setSsResult({ error: e?.message || 'Échec de la recherche searchsploit', results: [] });
    } finally {
      setIsSearching(false);
    }
  };

  const handleHashcat = async () => {
    if (!hash.trim()) return;
    setIsCracking(true);
    setHcResult(null);
    try {
      const res = await fetch('/api/arsenal/hashcat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash, mode, wordlist: wordlist || undefined }),
      });
      const data = await res.json();
      setHcResult(data);
    } catch (e: any) {
      setHcResult({ error: e?.message || 'Échec du crack hashcat' });
    } finally {
      setIsCracking(false);
    }
  };

  const ssResults = ssResult?.results || [];

  return (
    <div className="h-full overflow-y-auto bg-[#0a0e18] text-[#dfe2f1] p-6">
      <div className="max-w-7xl mx-auto">
        {/* En-tête */}
        <div className="mb-6">
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <span className="material-symbols-outlined text-[#4d8eff]">inventory_2</span>
            Arsenal — SearchSploit & Hashcat
          </h1>
          <p className="text-sm text-[#8c909f] mt-1">
            Recherche d'exploits publics (ExploitDB) et cassage de hashes par dictionnaire (hashcat).
          </p>
        </div>

        {/* Onglets */}
        <div className="flex gap-1 mb-6 border-b border-[#24314c]">
          {([
            { id: 'searchsploit' as Tab, label: 'SearchSploit', icon: 'search' },
            { id: 'hashcat' as Tab, label: 'Hashcat', icon: 'vpn_key' },
          ]).map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors flex items-center gap-2 ${
                tab === t.id
                  ? 'border-[#4d8eff] text-[#4d8eff]'
                  : 'border-transparent text-[#8c909f] hover:text-[#dfe2f1]'
              }`}
              type="button"
            >
              <span className="material-symbols-outlined text-[18px]">{t.icon}</span>
              {t.label}
            </button>
          ))}
        </div>

        {/* ============ SearchSploit ============ */}
        {tab === 'searchsploit' && (
          <div className="space-y-4">
            <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4">
              <div className="flex flex-wrap gap-3 items-end">
                <div className="flex-1 min-w-[260px]">
                  <label className="block text-xs text-[#8c909f] mb-1 font-mono">Requête de recherche</label>
                  <input
                    type="text"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleSearchsploit()}
                    placeholder="apache 2.4, openssh, heartbleed..."
                    className="w-full px-3 py-2 bg-[#0a0e18] border border-[#24314c] rounded text-sm font-mono text-[#dfe2f1] focus:border-[#4d8eff] outline-none"
                  />
                </div>
                <button
                  onClick={handleSearchsploit}
                  disabled={isSearching}
                  className="px-5 py-2 bg-[#4d8eff]/15 border border-[#4d8eff]/40 text-[#4d8eff] rounded text-sm font-medium hover:bg-[#4d8eff]/25 disabled:opacity-50 flex items-center gap-2 transition-colors"
                  type="button"
                >
                  {isSearching ? (
                    <><span className="material-symbols-outlined animate-spin text-[18px]">progress_activity</span> Recherche...</>
                  ) : (
                    <><span className="material-symbols-outlined text-[18px]">search</span> Rechercher</>
                  )}
                </button>
              </div>
              <p className="text-[11px] text-[#8c909f] mt-2 font-mono">
                Utilise <code>searchsploit</code> (ExploitDB) via le pont WSL/Linux. Aucune simulation.
              </p>
            </div>

            {ssResult?.error && (
              <div className="px-4 py-3 rounded bg-[#93000a]/20 border border-[#93000a]/40 text-[#ffb4ab] text-sm font-mono flex items-start gap-2">
                <span className="material-symbols-outlined text-[18px]">error</span>
                <div>
                  <div className="font-semibold mb-0.5">searchsploit indisponible</div>
                  <div className="text-[12px]">{ssResult.error}</div>
                  <div className="text-[11px] mt-1 text-[#c2c6d6]">Installer avec : <code className="text-[#4cd7f6]">sudo apt install exploitdb</code></div>
                </div>
              </div>
            )}

            {ssResult && !ssResult.error && (
              <>
                <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3 flex items-center justify-between">
                  <div className="text-xs font-mono text-[#8c909f]">
                    Requête: <span className="text-[#4cd7f6]">{ssResult.query}</span> •
                    {' '}{ssResult.count ?? ssResults.length} résultat(s)
                  </div>
                  <div className="text-[10px] text-[#8c909f]">via {ssResult.tool || 'searchsploit'}</div>
                </div>

                <div className="bg-[#171b26] border border-[#24314c] rounded-lg overflow-hidden">
                  <div className="max-h-96 overflow-y-auto">
                    <table className="w-full text-sm">
                      <thead className="bg-[#0a0e18] sticky top-0">
                        <tr className="text-[10px] text-[#8c909f] font-mono uppercase">
                          <th className="text-left px-3 py-2">ID</th>
                          <th className="text-left px-3 py-2">Titre</th>
                          <th className="text-left px-3 py-2">Type</th>
                          <th className="text-left px-3 py-2">Plateforme</th>
                          <th className="text-left px-3 py-2">Date</th>
                        </tr>
                      </thead>
                      <tbody>
                        {ssResults.length === 0 ? (
                          <tr>
                            <td colSpan={5} className="px-3 py-6 text-center text-[#8c909f] text-sm">
                              Aucun exploit trouvé pour cette requête.
                            </td>
                          </tr>
                        ) : ssResults.map((r, i) => (
                          <tr key={r.id || i} className="border-t border-[#24314c] hover:bg-[#1f2433]">
                            <td className="px-3 py-2 font-mono text-[11px] text-[#4cd7f6]">{r.id || '—'}</td>
                            <td className="px-3 py-2 text-[#dfe2f1]">{r.title || r.path || '—'}</td>
                            <td className="px-3 py-2 text-[11px] text-[#c2c6d6]">{r.type || '—'}</td>
                            <td className="px-3 py-2 text-[11px] text-[#8c909f]">{r.platform || '—'}</td>
                            <td className="px-3 py-2 font-mono text-[11px] text-[#8c909f]">{r.date || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </>
            )}
          </div>
        )}

        {/* ============ Hashcat ============ */}
        {tab === 'hashcat' && (
          <div className="space-y-4">
            <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                <div className="sm:col-span-2 lg:col-span-3">
                  <label className="block text-xs text-[#8c909f] mb-1 font-mono">Hash à casser</label>
                  <input
                    type="text"
                    value={hash}
                    onChange={(e) => setHash(e.target.value)}
                    placeholder="5f4dcc3b5aa765d61d8327deb882cf99"
                    className="w-full px-3 py-2 bg-[#0a0e18] border border-[#24314c] rounded text-sm font-mono text-[#dfe2f1] focus:border-[#4d8eff] outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs text-[#8c909f] mb-1 font-mono">Mode (hash-type)</label>
                  <select
                    value={mode}
                    onChange={(e) => setMode(parseInt(e.target.value, 10))}
                    className="w-full px-3 py-2 bg-[#0a0e18] border border-[#24314c] rounded text-sm font-mono text-[#dfe2f1] focus:border-[#4d8eff] outline-none"
                  >
                    {HASHCAT_MODES.map((m) => (
                      <option key={m.value} value={m.value}>{m.label}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-[#8c909f] mb-1 font-mono">Wordlist (path)</label>
                  <input
                    type="text"
                    value={wordlist}
                    onChange={(e) => setWordlist(e.target.value)}
                    placeholder="/usr/share/wordlists/rockyou.txt"
                    className="w-full px-3 py-2 bg-[#0a0e18] border border-[#24314c] rounded text-sm font-mono text-[#dfe2f1] focus:border-[#4d8eff] outline-none"
                  />
                </div>
                <div className="flex items-end">
                  <button
                    onClick={handleHashcat}
                    disabled={isCracking}
                    className="w-full px-5 py-2 bg-[#4d8eff]/15 border border-[#4d8eff]/40 text-[#4d8eff] rounded text-sm font-medium hover:bg-[#4d8eff]/25 disabled:opacity-50 flex items-center justify-center gap-2 transition-colors"
                    type="button"
                  >
                    {isCracking ? (
                      <><span className="material-symbols-outlined animate-spin text-[18px]">progress_activity</span> Crack en cours...</>
                    ) : (
                      <><span className="material-symbols-outlined text-[18px]">vpn_key</span> Lancer hashcat</>
                    )}
                  </button>
                </div>
              </div>
              <p className="text-[11px] text-[#8c909f] mt-2 font-mono">
                Utilise <code>hashcat</code> en mode dictionary attack. Aucune simulation — sortie réelle du binaire.
              </p>
            </div>

            {hcResult?.error && (
              <div className="px-4 py-3 rounded bg-[#93000a]/20 border border-[#93000a]/40 text-[#ffb4ab] text-sm font-mono flex items-start gap-2">
                <span className="material-symbols-outlined text-[18px]">error</span>
                <div>
                  <div className="font-semibold mb-0.5">hashcat indisponible</div>
                  <div className="text-[12px]">{hcResult.error}</div>
                  <div className="text-[11px] mt-1 text-[#c2c6d6]">Installer avec : <code className="text-[#4cd7f6]">sudo apt install hashcat</code></div>
                </div>
              </div>
            )}

            {hcResult && !hcResult.error && (
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg overflow-hidden">
                <div className="px-4 py-2 border-b border-[#24314c] flex items-center justify-between">
                  <div className="text-xs font-mono text-[#8c909f]">
                    Mode: <span className="text-[#4cd7f6]">{hcResult.mode}</span> •
                    {' '}Status: {(hcResult.cracked || hcResult.password)
                      ? <span className="text-emerald-400 font-semibold">CRACKÉ</span>
                      : <span className="text-[#ffb4ab]">non cracké</span>
                    }
                  </div>
                  <div className="text-[10px] text-[#8c909f]">{hcResult.durationMs ? `${hcResult.durationMs}ms` : ''} • exit={hcResult.exitCode ?? '—'}</div>
                </div>
                {(hcResult.cracked || hcResult.password) && (
                  <div className="px-4 py-3 bg-emerald-500/10 border-b border-emerald-500/30 flex items-center gap-2">
                    <span className="material-symbols-outlined text-emerald-400">check_circle</span>
                    <div>
                      <div className="text-[10px] text-[#8c909f] font-mono uppercase">Mot de passe retrouvé</div>
                      {/* arsenal-hashcat.sh returns the cracked plaintext in the `cracked` field
                          (not in a `password` field). Fall back to `password`/`plaintext` for
                          any future or alternate backend that exposes those names. */}
                      <div className="font-mono text-emerald-400 text-sm">{hcResult.password || hcResult.plaintext || (typeof hcResult.cracked === 'string' ? hcResult.cracked : '(cracké)')}</div>
                    </div>
                  </div>
                )}
                <div className="p-3">
                  <div className="text-[10px] text-[#8c909f] font-mono uppercase mb-1">Sortie hashcat</div>
                  <pre className="bg-[#0a0e18] border border-[#24314c] rounded p-3 text-[11px] font-mono text-[#c2c6d6] max-h-80 overflow-y-auto whitespace-pre-wrap break-all">
{hcResult.output || '(aucune sortie)'}
                  </pre>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
