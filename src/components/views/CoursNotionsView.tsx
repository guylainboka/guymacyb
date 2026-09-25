import React, { useState, useMemo } from 'react';
import { CourseNotion } from '../../types';

interface CoursNotionsViewProps {
  onGoToLab?: () => void;
  onGoToWifi?: () => void;
}

const CATEGORY_META: Record<string, { label: string; icon: string; color: string }> = {
  wifi:    { label: 'WiFi',           icon: 'wifi',           color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30' },
  network: { label: 'Réseau',         icon: 'lan',            color: 'text-sky-400 bg-sky-500/10 border-sky-500/30' },
  crypto:  { label: 'Cryptographie',  icon: 'vpn_key',        color: 'text-amber-400 bg-amber-500/10 border-amber-500/30' },
  attack:  { label: 'Attaques',       icon: 'gpp_bad',        color: 'text-rose-400 bg-rose-500/10 border-rose-500/30' },
  defense: { label: 'Défense',        icon: 'gpp_good',       color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30' },
};

const LEVEL_COLOR: Record<string, string> = {
  'DÉBUTANT': 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
  'INTERMÉDIAIRE': 'text-amber-400 bg-amber-500/10 border-amber-500/30',
  'AVANCÉ': 'text-rose-400 bg-rose-500/10 border-rose-500/30',
};

export const CoursNotionsView: React.FC<CoursNotionsViewProps> = ({ onGoToLab, onGoToWifi }) => {
  const [notions, setNotions] = useState<CourseNotion[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selected, setSelected] = useState<CourseNotion | null>(null);
  const [filter, setFilter] = useState<string>('ALL');
  const [search, setSearch] = useState<string>('');

  React.useEffect(() => {
    fetch('/api/courses/notions')
      .then((r) => r.json())
      .then((data) => {
        setNotions(Array.isArray(data) ? data : []);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const filtered = useMemo(() => {
    return notions.filter((n) => {
      if (filter !== 'ALL' && n.category !== filter) return false;
      if (search && !n.title.toLowerCase().includes(search.toLowerCase()) && !n.summary.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
  }, [notions, filter, search]);

  // Rendu du contenu markdown simplifié (## titres, **bold**, listes -, paragraphes)
  const renderContent = (content: string) => {
    const lines = content.split('\n');
    const out: React.ReactNode[] = [];
    let list: React.ReactNode[] = [];
    let key = 0;

    const flushList = () => {
      if (list.length > 0) {
        out.push(<ul key={`ul-${key++}`} className="list-disc list-inside space-y-1 my-2 text-sm text-[#c2c6d6]">{list}</ul>);
        list = [];
      }
    };

    for (const line of lines) {
      const t = line.trim();
      if (t.startsWith('## ')) {
        flushList();
        out.push(<h3 key={`h-${key++}`} className="text-base font-semibold text-emerald-400 mt-4 mb-1.5">{t.slice(3)}</h3>);
      } else if (t.startsWith('### ')) {
        flushList();
        out.push(<h4 key={`h-${key++}`} className="text-sm font-semibold text-sky-400 mt-3 mb-1">{t.slice(4)}</h4>);
      } else if (t.startsWith('- ') || t.startsWith('* ')) {
        list.push(<li key={`li-${key++}`} className="text-sm text-[#c2c6d6]">{renderInline(t.slice(2))}</li>);
      } else if (t === '') {
        flushList();
      } else {
        flushList();
        out.push(<p key={`p-${key++}`} className="text-sm text-[#c2c6d6] my-1.5 leading-relaxed">{renderInline(t)}</p>);
      }
    }
    flushList();
    return out;
  };

  const renderInline = (text: string) => {
    // **bold** et `code`
    const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
    return parts.map((p, i) => {
      if (p.startsWith('**') && p.endsWith('**')) {
        return <strong key={i} className="text-[#dfe2f1] font-semibold">{p.slice(2, -2)}</strong>;
      }
      if (p.startsWith('`') && p.endsWith('`')) {
        return <code key={i} className="px-1 py-0.5 bg-[#0a0e18] border border-[#24314c] rounded text-[11px] font-mono text-emerald-400">{p.slice(1, -1)}</code>;
      }
      return <span key={i}>{p}</span>;
    });
  };

  if (loading) {
    return (
      <div className="h-full flex items-center justify-center bg-[#0a0e18] text-[#8c909f]">
        <div className="flex items-center gap-3">
          <span className="material-symbols-outlined animate-spin">progress_activity</span>
          Chargement des notions...
        </div>
      </div>
    );
  }

  return (
    <div className="h-full overflow-y-auto bg-[#0a0e18] text-[#dfe2f1] p-6">
      <div className="max-w-7xl mx-auto">
        {/* En-tête */}
        <div className="mb-6 flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <span className="material-symbols-outlined text-sky-400">school</span>
              Cours & Notions
            </h1>
            <p className="text-sm text-[#8c909f] mt-1">
              Fondamentaux WiFi, réseau, cryptographie et attaques — {notions.length} notions disponibles.
            </p>
          </div>
          {onGoToWifi && (
            <button
              onClick={onGoToWifi}
              className="px-3 py-1.5 text-xs rounded bg-emerald-600/15 border border-emerald-500/30 text-emerald-400 hover:bg-emerald-600/25 flex items-center gap-1.5 transition-colors"
              type="button"
            >
              <span className="material-symbols-outlined text-[16px]">wifi</span>
              Aller au module WiFi
            </button>
          )}
        </div>

        <div className="grid grid-cols-12 gap-4">
          {/* Colonne gauche : liste + filtres */}
          <div className="col-span-12 lg:col-span-4 space-y-3">
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Rechercher une notion..."
              className="w-full px-3 py-2 bg-[#171b26] border border-[#24314c] rounded text-sm text-[#dfe2f1] focus:border-sky-500 outline-none"
            />

            <div className="flex flex-wrap gap-1.5">
              <button
                onClick={() => setFilter('ALL')}
                className={`px-2.5 py-1 text-[11px] rounded border font-mono transition-colors ${filter === 'ALL' ? 'bg-sky-500/20 border-sky-500/50 text-sky-400' : 'bg-[#171b26] border-[#24314c] text-[#8c909f] hover:text-[#dfe2f1]'}`}
                type="button"
              >Toutes</button>
              {Object.entries(CATEGORY_META).map(([k, m]) => (
                <button
                  key={k}
                  onClick={() => setFilter(k)}
                  className={`px-2.5 py-1 text-[11px] rounded border font-mono transition-colors flex items-center gap-1 ${filter === k ? 'bg-sky-500/20 border-sky-500/50 text-sky-400' : 'bg-[#171b26] border-[#24314c] text-[#8c909f] hover:text-[#dfe2f1]'}`}
                  type="button"
                >
                  <span className="material-symbols-outlined text-[13px]">{m.icon}</span>
                  {m.label}
                </button>
              ))}
            </div>

            <div className="bg-[#171b26] border border-[#24314c] rounded-lg overflow-hidden max-h-[560px] overflow-y-auto">
              {filtered.length === 0 ? (
                <div className="px-4 py-8 text-center text-sm text-[#8c909f]">Aucune notion trouvée.</div>
              ) : (
                filtered.map((n) => {
                  const m = CATEGORY_META[n.category] || CATEGORY_META.network;
                  const isSel = selected?.id === n.id;
                  return (
                    <button
                      key={n.id}
                      onClick={() => setSelected(n)}
                      className={`w-full text-left px-3 py-2.5 border-b border-[#24314c] last:border-0 transition-colors ${isSel ? 'bg-sky-500/10' : 'hover:bg-[#1f2433]'}`}
                      type="button"
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`px-1.5 py-0.5 text-[9px] font-mono rounded border ${m.color}`}>
                          {m.label}
                        </span>
                        <span className={`px-1.5 py-0.5 text-[9px] font-mono rounded border ${LEVEL_COLOR[n.level]}`}>
                          {n.level}
                        </span>
                      </div>
                      <div className="text-sm font-medium text-[#dfe2f1]">{n.title}</div>
                      <div className="text-[11px] text-[#8c909f] mt-0.5 line-clamp-2">{n.summary}</div>
                    </button>
                  );
                })
              )}
            </div>
          </div>

          {/* Colonne droite : détail notion */}
          <div className="col-span-12 lg:col-span-8">
            {!selected ? (
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-8 h-full flex flex-col items-center justify-center text-center min-h-[400px]">
                <span className="material-symbols-outlined text-[#24314c] text-[80px] mb-3">menu_book</span>
                <p className="text-[#8c909f] text-sm">Sélectionnez une notion dans la liste pour afficher son contenu.</p>
              </div>
            ) : (
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-6 max-h-[620px] overflow-y-auto">
                <div className="flex items-center gap-2 mb-2">
                  <span className={`px-2 py-0.5 text-[10px] font-mono rounded border ${CATEGORY_META[selected.category].color}`}>
                    {CATEGORY_META[selected.category].label}
                  </span>
                  <span className={`px-2 py-0.5 text-[10px] font-mono rounded border ${LEVEL_COLOR[selected.level]}`}>
                    {selected.level}
                  </span>
                </div>
                <h2 className="text-xl font-bold text-[#dfe2f1] mb-2">{selected.title}</h2>
                <p className="text-sm text-[#8c909f] italic mb-4">{selected.summary}</p>

                <div className="border-t border-[#24314c] pt-4">
                  {renderContent(selected.content)}
                </div>

                {selected.keyPoints.length > 0 && (
                  <div className="mt-5 bg-[#0a0e18] border border-[#24314c] rounded-lg p-4">
                    <div className="text-xs font-mono text-emerald-400 uppercase mb-2 flex items-center gap-1.5">
                      <span className="material-symbols-outlined text-[16px]">key</span>
                      Points clés à retenir
                    </div>
                    <ul className="space-y-1.5">
                      {selected.keyPoints.map((p, i) => (
                        <li key={i} className="text-sm text-[#c2c6d6] flex items-start gap-2">
                          <span className="text-emerald-400 mt-0.5">▸</span>
                          <span>{p}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {selected.references.length > 0 && (
                  <div className="mt-4">
                    <div className="text-xs font-mono text-sky-400 uppercase mb-2 flex items-center gap-1.5">
                      <span className="material-symbols-outlined text-[16px]">link</span>
                      Références
                    </div>
                    <ul className="space-y-1">
                      {selected.references.map((r, i) => (
                        <li key={i} className="text-xs text-sky-400/80 font-mono">{r}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {onGoToLab && selected.category === 'attack' && (
                  <button
                    onClick={onGoToLab}
                    className="mt-5 px-3 py-1.5 text-xs rounded bg-rose-600/15 border border-rose-500/30 text-rose-400 hover:bg-rose-600/25 flex items-center gap-1.5 transition-colors"
                    type="button"
                  >
                    <span className="material-symbols-outlined text-[16px]">science</span>
                    Tester cette attaque en laboratoire
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
