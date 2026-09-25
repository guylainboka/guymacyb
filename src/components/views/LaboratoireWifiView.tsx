import React, { useState, useEffect } from 'react';
import { WifiLabVector, WifiAttackCategory, WifiLabSimulationResult, Finding } from '../../types';

interface LaboratoireWifiViewProps {
  onCommitFindingToApp: (finding: Finding) => void;
  onGoToResults: () => void;
  onGoToCours: () => void;
}

const CATEGORY_LABEL: Record<string, { label: string; icon: string; color: string }> = {
  WIFI_DEAUTH:     { label: 'Déauthentification',  icon: 'block',          color: 'text-rose-400 bg-rose-500/10 border-rose-500/30' },
  WIFI_EVIL_TWIN:  { label: 'Evil Twin',           icon: 'wifi_calling',   color: 'text-rose-400 bg-rose-500/10 border-rose-500/30' },
  WIFI_KRACK:      { label: 'KRACK (WPA2)',        icon: 'no_encryption',  color: 'text-amber-400 bg-amber-500/10 border-amber-500/30' },
  WIFI_WPS:        { label: 'WPS (PIN)',           icon: 'pin',            color: 'text-amber-400 bg-amber-500/10 border-amber-500/30' },
  WIFI_HANDSHAKE:  { label: 'Handshake/PMKID',     icon: 'key',            color: 'text-sky-400 bg-sky-500/10 border-sky-500/30' },
  WIFI_DOWNGRADE:  { label: 'Downgrade WPA3',      icon: 'downloading',    color: 'text-amber-400 bg-amber-500/10 border-amber-500/30' },
};

export const LaboratoireWifiView: React.FC<LaboratoireWifiViewProps> = ({
  onCommitFindingToApp,
  onGoToResults,
  onGoToCours,
}) => {
  const [vectors, setVectors] = useState<WifiLabVector[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<WifiLabVector | null>(null);
  const [filter, setFilter] = useState<string>('ALL');
  const [targetMode, setTargetMode] = useState<'vulnerable' | 'remediated'>('vulnerable');
  const [isSimulating, setIsSimulating] = useState(false);
  const [isBatchRunning, setIsBatchRunning] = useState(false);
  const [activeTab, setActiveTab] = useState<'simulation' | 'remediation' | 'code'>('simulation');
  const [simResult, setSimResult] = useState<WifiLabSimulationResult | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/wifi/lab/vectors')
      .then((r) => r.json())
      .then((data) => {
        setVectors(Array.isArray(data) ? data : []);
        if (data.length > 0) setSelected(data[0]);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const showToast = (m: string) => { setToast(m); setTimeout(() => setToast(null), 3500); };

  const filtered = vectors.filter((v) => filter === 'ALL' || v.category === filter);

  const runSim = async (mode: 'vulnerable' | 'remediated') => {
    if (!selected) return;
    setIsSimulating(true);
    setSimResult(null);
    try {
      const res = await fetch('/api/wifi/lab/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vectorId: selected.id, targetMode: mode, operatorId: 'SEC-OPS-0982' }),
      });
      const data = await res.json();
      setSimResult(data);
      if (data.findingCandidate) {
        onCommitFindingToApp(data.findingCandidate);
        showToast(`Preuve enregistrée : ${data.findingCandidate.title}`);
      } else {
        showToast(data.status === 'PROTECTED' ? 'Poste défensif validé ✓' : 'Simulation terminée');
      }
    } catch {
      showToast('Erreur API simulation');
    } finally {
      setIsSimulating(false);
    }
  };

  const runBatch = async () => {
    setIsBatchRunning(true);
    try {
      const res = await fetch('/api/wifi/lab/generate-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ operatorId: 'SEC-OPS-0982' }),
      });
      const data = await res.json();
      showToast(`Rapport généré : ${data.vectorsAudited || 0} vecteurs audités et persistés`);
      onGoToResults();
    } catch {
      showToast('Erreur génération rapport');
    } finally {
      setIsBatchRunning(false);
    }
  };

  if (loading) {
    return (
      <div className="h-full flex items-center justify-center bg-[#0a0e18] text-[#8c909f]">
        <div className="flex items-center gap-3">
          <span className="material-symbols-outlined animate-spin">progress_activity</span>
          Chargement du laboratoire WiFi...
        </div>
      </div>
    );
  }

  return (
    <div className="h-full overflow-y-auto bg-[#0a0e18] text-[#dfe2f1] p-6">
      {toast && (
        <div className="fixed top-24 right-6 z-50 px-4 py-2 bg-emerald-600/20 border border-emerald-500/40 rounded text-sm text-emerald-300 shadow-lg backdrop-blur">
          {toast}
        </div>
      )}
      <div className="max-w-7xl mx-auto">
        {/* En-tête */}
        <div className="mb-5 flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <span className="material-symbols-outlined text-rose-400">science</span>
              Laboratoire d'Attaques WiFi
            </h1>
            <p className="text-sm text-[#8c909f] mt-1">
              Simulations défensives en bac à sable : {vectors.length} vecteurs WiFi (WPA, WPA2, WPA3, WPS, Evil Twin, KRACK...).
            </p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={onGoToCours}
              className="px-3 py-1.5 text-xs rounded bg-[#171b26] border border-[#24314c] hover:border-sky-500/50 text-[#c2c6d6] flex items-center gap-1.5 transition-colors"
              type="button"
            >
              <span className="material-symbols-outlined text-[16px]">school</span>
              Cours
            </button>
            <button
              onClick={runBatch}
              disabled={isBatchRunning}
              className="px-3 py-1.5 text-xs rounded bg-rose-600/15 border border-rose-500/30 text-rose-400 hover:bg-rose-600/25 disabled:opacity-50 flex items-center gap-1.5 transition-colors"
              type="button"
            >
              {isBatchRunning ? <><span className="material-symbols-outlined animate-spin text-[16px]">progress_activity</span> Génération...</> : <><span className="material-symbols-outlined text-[16px]">assessment</span> Rapport complet</>}
            </button>
          </div>
        </div>

        {/* Filtres */}
        <div className="flex flex-wrap gap-1.5 mb-4">
          <button
            onClick={() => setFilter('ALL')}
            className={`px-2.5 py-1 text-[11px] rounded border font-mono transition-colors ${filter === 'ALL' ? 'bg-rose-500/20 border-rose-500/50 text-rose-400' : 'bg-[#171b26] border-[#24314c] text-[#8c909f] hover:text-[#dfe2f1]'}`}
            type="button"
          >Tous ({vectors.length})</button>
          {Object.entries(CATEGORY_LABEL).map(([k, m]) => {
            const count = vectors.filter(v => v.category === k).length;
            return (
              <button
                key={k}
                onClick={() => setFilter(k)}
                className={`px-2.5 py-1 text-[11px] rounded border font-mono transition-colors flex items-center gap-1 ${filter === k ? 'bg-rose-500/20 border-rose-500/50 text-rose-400' : 'bg-[#171b26] border-[#24314c] text-[#8c909f] hover:text-[#dfe2f1]'}`}
                type="button"
              >
                <span className="material-symbols-outlined text-[13px]">{m.icon}</span>
                {m.label} ({count})
              </button>
            );
          })}
        </div>

        <div className="grid grid-cols-12 gap-4">
          {/* Liste vecteurs */}
          <div className="col-span-12 lg:col-span-4 bg-[#171b26] border border-[#24314c] rounded-lg overflow-hidden max-h-[580px] overflow-y-auto">
            {filtered.map((v) => {
              const m = CATEGORY_LABEL[v.category] || CATEGORY_LABEL.WIFI_DEAUTH;
              const isSel = selected?.id === v.id;
              const sevColor = v.severity === 'CRITICAL' ? 'text-rose-400' : v.severity === 'HIGH' ? 'text-red-400' : v.severity === 'MEDIUM' ? 'text-amber-400' : 'text-sky-400';
              return (
                <button
                  key={v.id}
                  onClick={() => { setSelected(v); setSimResult(null); }}
                  className={`w-full text-left px-3 py-2.5 border-b border-[#24314c] last:border-0 transition-colors ${isSel ? 'bg-rose-500/10' : 'hover:bg-[#1f2433]'}`}
                  type="button"
                >
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <span className={`px-1.5 py-0.5 text-[9px] font-mono rounded border ${m.color}`}>{m.label}</span>
                    <span className={`text-[10px] font-mono ${sevColor}`}>{v.severity}</span>
                  </div>
                  <div className="text-sm font-medium text-[#dfe2f1]">{v.name}</div>
                  <div className="text-[11px] text-[#8c909f] mt-0.5 line-clamp-2">{v.description}</div>
                  <div className="flex items-center gap-2 mt-1 text-[10px] font-mono text-[#8c909f]">
                    <span>Diff: {v.difficulty}</span>
                    <span>•</span>
                    <span>Target: {v.targetEncryption}</span>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Détail vecteur */}
          <div className="col-span-12 lg:col-span-8">
            {!selected ? (
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-8 text-center text-[#8c909f]">
                Sélectionnez un vecteur dans la liste.
              </div>
            ) : (
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg overflow-hidden">
                {/* Titre */}
                <div className="px-5 py-4 border-b border-[#24314c]">
                  <div className="flex items-center gap-2 mb-2">
                    <span className={`px-2 py-0.5 text-[10px] font-mono rounded border ${CATEGORY_LABEL[selected.category].color}`}>
                      {CATEGORY_LABEL[selected.category].label}
                    </span>
                    <span className="px-2 py-0.5 text-[10px] font-mono rounded border bg-[#0a0e18] border-[#24314c] text-[#8c909f]">
                      MITRE {selected.mitre}
                    </span>
                    <span className="px-2 py-0.5 text-[10px] font-mono rounded border bg-[#0a0e18] border-[#24314c] text-[#8c909f]">
                      {selected.targetEncryption}
                    </span>
                  </div>
                  <h2 className="text-lg font-bold text-[#dfe2f1]">{selected.name}</h2>
                  <p className="text-sm text-[#8c909f] mt-1">{selected.description}</p>
                </div>

                {/* Onglets */}
                <div className="flex border-b border-[#24314c]">
                  {(['simulation', 'remediation', 'code'] as const).map((t) => (
                    <button
                      key={t}
                      onClick={() => setActiveTab(t)}
                      className={`px-4 py-2 text-xs font-medium border-b-2 transition-colors ${activeTab === t ? 'border-rose-500 text-rose-400' : 'border-transparent text-[#8c909f] hover:text-[#dfe2f1]'}`}
                      type="button"
                    >
                      {t === 'simulation' ? 'Simulation' : t === 'remediation' ? 'Remédiation' : 'Code'}
                    </button>
                  ))}
                </div>

                <div className="p-5 max-h-[460px] overflow-y-auto">
                  {activeTab === 'simulation' && (
                    <div className="space-y-4">
                      {/* Scénario */}
                      <div>
                        <div className="text-[10px] font-mono text-[#8c909f] uppercase mb-1">Scénario d'attaque</div>
                        <p className="text-sm text-[#c2c6d6]">{selected.attackScenario}</p>
                      </div>

                      {/* Mode cible */}
                      <div>
                        <div className="text-[10px] font-mono text-[#8c909f] uppercase mb-2">Mode de la cible simulée</div>
                        <div className="flex gap-2">
                          <button
                            onClick={() => setTargetMode('vulnerable')}
                            className={`px-3 py-1.5 text-xs rounded border font-mono transition-colors ${targetMode === 'vulnerable' ? 'bg-rose-500/20 border-rose-500/50 text-rose-400' : 'bg-[#0a0e18] border-[#24314c] text-[#8c909f]'}`}
                            type="button"
                          >Vulnérable</button>
                          <button
                            onClick={() => setTargetMode('remediated')}
                            className={`px-3 py-1.5 text-xs rounded border font-mono transition-colors ${targetMode === 'remediated' ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-400' : 'bg-[#0a0e18] border-[#24314c] text-[#8c909f]'}`}
                            type="button"
                          >Remédiée</button>
                        </div>
                      </div>

                      {/* Payload de test sûr */}
                      <div>
                        <div className="text-[10px] font-mono text-[#8c909f] uppercase mb-1">Sonde de test (non destructive)</div>
                        <pre className="px-3 py-2 bg-[#0a0e18] border border-[#24314c] rounded text-[11px] font-mono text-emerald-400 whitespace-pre-wrap">{selected.safeTestPayload}</pre>
                      </div>

                      {/* Bouton lancer */}
                      <button
                        onClick={() => runSim(targetMode)}
                        disabled={isSimulating}
                        className="px-4 py-2 bg-rose-600/20 border border-rose-500/40 text-rose-400 rounded text-sm font-medium hover:bg-rose-600/30 disabled:opacity-50 flex items-center gap-2 transition-colors"
                        type="button"
                      >
                        {isSimulating ? (
                          <><span className="material-symbols-outlined animate-spin text-[18px]">progress_activity</span> Simulation en cours...</>
                        ) : (
                          <><span className="material-symbols-outlined text-[18px]">bolt</span> Lancer la simulation ({targetMode})</>
                        )}
                      </button>

                      {/* Résultat */}
                      {simResult && (
                        <div className={`rounded-lg border p-4 ${simResult.status === 'VULNERABLE' ? 'bg-rose-500/10 border-rose-500/30' : 'bg-emerald-500/10 border-emerald-500/30'}`}>
                          <div className="flex items-center justify-between mb-2">
                            <div className={`text-sm font-bold ${simResult.status === 'VULNERABLE' ? 'text-rose-400' : 'text-emerald-400'}`}>
                              {simResult.status === 'VULNERABLE' ? '⚠ VULNÉRABLE' : '✓ PROTÉGÉ'}
                            </div>
                            <div className="text-[10px] font-mono text-[#8c909f]">{simResult.durationMs}ms • AP intercepté: {simResult.apIntercepted ? 'Oui' : 'Non'}</div>
                          </div>
                          <pre className="text-[11px] font-mono text-[#c2c6d6] whitespace-pre-wrap bg-[#0a0e18] border border-[#24314c] rounded p-2 mb-2 max-h-40 overflow-y-auto">{simResult.responsePreview}</pre>
                          <ul className="space-y-1">
                            {simResult.securityObservations.map((o, i) => (
                              <li key={i} className="text-xs text-[#c2c6d6] flex items-start gap-2">
                                <span className="text-sky-400 mt-0.5">▸</span>
                                <span>{o}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}

                  {activeTab === 'remediation' && (
                    <div className="space-y-4">
                      <div className="grid grid-cols-2 gap-3">
                        <div className="bg-rose-500/5 border border-rose-500/20 rounded p-3">
                          <div className="text-[10px] font-mono text-rose-400 uppercase mb-1">Comportement vulnérable</div>
                          <p className="text-xs text-[#c2c6d6]">{selected.vulnerableBehaviorExplanation}</p>
                        </div>
                        <div className="bg-emerald-500/5 border border-emerald-500/20 rounded p-3">
                          <div className="text-[10px] font-mono text-emerald-400 uppercase mb-1">Comportement remédié</div>
                          <p className="text-xs text-[#c2c6d6]">{selected.remediatedBehaviorExplanation}</p>
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] font-mono text-emerald-400 uppercase mb-2">Contrôles défensifs recommandés</div>
                        <ul className="space-y-1.5">
                          {selected.defensiveControls.map((c, i) => (
                            <li key={i} className="text-sm text-[#c2c6d6] flex items-start gap-2">
                              <span className="text-emerald-400 mt-0.5">✓</span>
                              <span>{c}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                      <div>
                        <div className="text-[10px] font-mono text-sky-400 uppercase mb-1">Échantillon de réponse vulnérable</div>
                        <pre className="px-3 py-2 bg-[#0a0e18] border border-rose-500/20 rounded text-[11px] font-mono text-rose-300 whitespace-pre-wrap max-h-40 overflow-y-auto">{selected.vulnerableResponseSample}</pre>
                      </div>
                      <div>
                        <div className="text-[10px] font-mono text-sky-400 uppercase mb-1">Échantillon de réponse remédiée</div>
                        <pre className="px-3 py-2 bg-[#0a0e18] border border-emerald-500/20 rounded text-[11px] font-mono text-emerald-300 whitespace-pre-wrap max-h-40 overflow-y-auto">{selected.remediatedResponseSample}</pre>
                      </div>
                    </div>
                  )}

                  {activeTab === 'code' && (
                    <div className="space-y-3">
                      <div className="text-[10px] font-mono text-[#8c909f]">{selected.remediationCodeExample.language}</div>
                      <div>
                        <div className="text-[10px] font-mono text-rose-400 uppercase mb-1">❌ Code vulnérable</div>
                        <pre className="px-3 py-2 bg-[#0a0e18] border border-rose-500/20 rounded text-[11px] font-mono text-rose-300 whitespace-pre-wrap overflow-x-auto">{selected.remediationCodeExample.vulnerable}</pre>
                      </div>
                      <div>
                        <div className="text-[10px] font-mono text-emerald-400 uppercase mb-1">✅ Code sécurisé</div>
                        <pre className="px-3 py-2 bg-[#0a0e18] border border-emerald-500/20 rounded text-[11px] font-mono text-emerald-300 whitespace-pre-wrap overflow-x-auto">{selected.remediationCodeExample.fixed}</pre>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
