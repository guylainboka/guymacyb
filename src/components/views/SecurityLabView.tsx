import React, { useEffect, useState } from 'react';
import { LabAttackVector, Finding, LabProbeResult, TestAuthorization } from '../../types';
import { LAB_ATTACK_VECTORS } from '../../data/labAttackVectors';

interface SecurityLabViewProps {
  targetConfig: { url: string; operatorId: string };
  onCommitFindingToApp: (finding: Finding) => void;
  onGoToReport: () => void;
  onGoToResults: () => void;
}

/**
 * LABORATOIRE RÉEL — chaque sonde envoie de vraies requêtes HTTP à la cible
 * autorisée (attestation légale obligatoire, journalisée côté serveur) et
 * affiche les vraies réponses. Aucune réponse n'est fabriquée.
 */
export const SecurityLabView: React.FC<SecurityLabViewProps> = ({
  targetConfig,
  onCommitFindingToApp,
  onGoToReport,
  onGoToResults,
}) => {
  const [selectedVector, setSelectedVector] = useState<LabAttackVector>(LAB_ATTACK_VECTORS[0]);
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [isProbing, setIsProbing] = useState<boolean>(false);
  const [isBatchRunning, setIsBatchRunning] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'probe' | 'remediation' | 'code'>('probe');
  const [probeResults, setProbeResults] = useState<Record<string, LabProbeResult>>({});
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [authToken, setAuthToken] = useState<string>('');

  // Attestation légale — le texte exact provient du serveur (source de vérité)
  const [statements, setStatements] = useState<Record<string, string> | null>(null);
  const [attestationChecked, setAttestationChecked] = useState<boolean>(false);
  const [authorized, setAuthorized] = useState<boolean>(false);

  useEffect(() => {
    let cancelled = false;
    fetch('/api/authorization/statements')
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((data) => {
        if (!cancelled) setStatements(data);
      })
      .catch(() => {
        if (!cancelled) setStatements(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const categories: { key: string; label: string; icon: string }[] = [
    { key: 'ALL', label: 'Tous les Vecteurs', icon: 'apps' },
    { key: 'INJECTION', label: 'Injections (SQL / XSS)', icon: 'code' },
    { key: 'ACCESS_CONTROL', label: 'Contrôle d’Accès (IDOR)', icon: 'vpn_key' },
    { key: 'AUTHENTICATION', label: 'Authentification & JWT', icon: 'badge' },
    { key: 'SERVER_SIDE', label: 'Côté Serveur (SSRF / Path)', icon: 'dns' },
    { key: 'CONFIG', label: 'Configuration & CORS', icon: 'tune' },
  ];

  const filteredVectors = LAB_ATTACK_VECTORS.filter((vec) => {
    if (selectedCategory === 'ALL') return true;
    return vec.category === selectedCategory;
  });

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 5000);
  };

  const buildAuthorization = (level: 'ACTIVE' | 'DESTRUCTIVE'): TestAuthorization | null => {
    const statement = statements?.[level];
    if (!statement) {
      showToast('Déclaration légale indisponible — lancez le backend puis réessayez.');
      return null;
    }
    return {
      operatorId: targetConfig.operatorId || 'SEC-OPS-0982',
      targetUrl: targetConfig.url,
      level,
      statement,
      confirmedAt: new Date().toISOString(),
    };
  };

  // Sonde réelle individuelle
  const handleRunProbe = async () => {
    if (!authorized) {
      showToast('Attestation légale requise avant toute sonde réelle (cochez la déclaration ci-dessus).');
      return;
    }
    const authorization = buildAuthorization('ACTIVE');
    if (!authorization) return;
    setIsProbing(true);
    try {
      const res = await fetch('/api/lab/probe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vectorId: selectedVector.id,
          targetUrl: targetConfig.url,
          operatorId: targetConfig.operatorId || 'SEC-OPS-0982',
          authToken: authToken || undefined,
          authorization,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error || `HTTP ${res.status}`);

      const probe: LabProbeResult = data;
      setProbeResults((prev) => ({ ...prev, [probe.vectorId]: probe }));
      if (probe.findingCandidate) {
        onCommitFindingToApp(probe.findingCandidate);
      }
      showToast(
        `Sonde réelle exécutée : ${probe.requestsSent} requête(s) réelle(s) — verdict ${probe.verdict}.`
      );
    } catch (err: any) {
      showToast(`Échec de la sonde réelle : ${err?.message || 'API injoignable'}`);
    } finally {
      setIsProbing(false);
    }
  };

  // Suite complète des 8 sondes réelles
  const handleRunFullBatch = async () => {
    if (!authorized) {
      showToast('Attestation légale requise avant la suite réelle.');
      return;
    }
    const authorization = buildAuthorization('ACTIVE');
    if (!authorization) return;
    setIsBatchRunning(true);
    try {
      const res = await fetch('/api/lab/generate-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          operatorId: targetConfig.operatorId || 'SEC-OPS-0982',
          authorization,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error || `HTTP ${res.status}`);
      showToast(
        `Suite réelle terminée : ${data.vulnerableCount} vulnérable(s) / ${data.protectedCount} protégé(s) / ${data.inconclusiveCount} inconclusif(s) — ${data.totalRequests} requêtes réelles, rapport persisté (${data.scanId}).`
      );
    } catch (err: any) {
      showToast(`Échec de la suite réelle : ${err?.message || 'API injoignable'}`);
    } finally {
      setIsBatchRunning(false);
    }
  };

  const currentResult = probeResults[selectedVector.id];

  return (
    <div className="flex-1 overflow-y-auto p-5 flex flex-col gap-5 font-sans bg-[#0a0e18] text-[#dfe2f1]">
      {/* Toast Alert */}
      {toastMessage && (
        <div className="fixed bottom-12 right-6 z-50 bg-[#171b26] border border-[#4cd7f6] text-[#dfe2f1] px-4 py-3 rounded-lg shadow-xl flex items-center gap-3 animate-fade-in font-mono text-xs max-w-md">
          <span className="material-symbols-outlined text-[#4cd7f6] text-[20px]">verified</span>
          <span className="flex-1">{toastMessage}</span>
        </div>
      )}

      {/* Top Banner — Laboratoire RÉEL */}
      <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4 flex flex-wrap items-center justify-between gap-4 shadow-sm font-mono text-xs">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-[#4d8eff]/10 border border-[#4d8eff]/30 text-[#4cd7f6]">
            <span className="material-symbols-outlined text-[24px]">science</span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-white tracking-wide">
                LABORATOIRE D'ATTAQUES RÉEL (CYBER RANGE)
              </h2>
              <span className="px-2 py-0.5 rounded bg-[#93000a]/30 border border-[#ffb4ab]/30 text-[#ffb4ab] text-[10px] font-bold">
                SONDES RÉELLES — ATTESTATION REQUISE
              </span>
            </div>
            <p className="text-[#8c909f] text-[11px] mt-0.5">
              Les 8 vecteurs OWASP exécutés contre votre cible{' '}
              <span className="text-[#4cd7f6]">{targetConfig.url}</span> — vraies requêtes, vraies réponses, vrais verdicts.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={handleRunFullBatch}
            disabled={isBatchRunning || !authorized}
            className="px-3 py-1.5 rounded bg-[#262a35] hover:bg-[#323746] text-[#4cd7f6] border border-[#4cd7f6]/40 font-bold flex items-center gap-2 transition-all disabled:opacity-50"
          >
            <span className={`material-symbols-outlined text-[16px] ${isBatchRunning ? 'animate-spin' : ''}`}>
              {isBatchRunning ? 'sync' : 'auto_mode'}
            </span>
            <span>{isBatchRunning ? 'Sondes réelles en cours…' : 'Exécuter la Suite Complète (8)'}</span>
          </button>

          <button
            type="button"
            onClick={onGoToReport}
            className="px-3.5 py-1.5 rounded bg-[#4d8eff] hover:bg-[#3b82f6] text-white font-bold flex items-center gap-1.5 shadow-sm transition-all"
          >
            <span className="material-symbols-outlined text-[16px]">assessment</span>
            <span>Voir Rapport d'Audit</span>
          </button>
        </div>
      </div>

      {/* Attestation légale obligatoire */}
      <div className="bg-[#93000a]/10 border border-[#ffb4ab]/40 rounded-lg p-4 flex flex-col gap-2 font-sans text-xs">
        <div className="flex items-center gap-2 text-[#ffb4ab] font-bold uppercase tracking-wider font-mono text-[11px]">
          <span className="material-symbols-outlined text-[18px]">gavel</span>
          <span>Autorisation légale de la cible — obligatoire avant toute sonde réelle</span>
        </div>
        {statements ? (
          <>
            <label className="flex items-start gap-3 p-3 bg-[#1c1f2a] rounded cursor-pointer border border-[#262a35] hover:border-[#3b82f6]/50 transition-colors select-text">
              <input
                type="checkbox"
                checked={attestationChecked}
                onChange={(e) => {
                  setAttestationChecked(e.target.checked);
                  setAuthorized(e.target.checked);
                }}
                className="mt-0.5 w-4 h-4 accent-[#3b82f6] rounded cursor-pointer shrink-0"
              />
              <span className="text-[#dfe2f1] leading-relaxed">{statements.ACTIVE}</span>
            </label>
            {authorized ? (
              <span className="text-[#10b981] font-mono text-[11px] flex items-center gap-1.5">
                <span className="material-symbols-outlined text-[15px]">verified_user</span>
                Attestation ACTIVE acceptée — chaque sonde réelle sera journalisée avec votre identité ({targetConfig.operatorId || 'SEC-OPS-0982'}) et horodatée.
              </span>
            ) : (
              <span className="text-[#8c909f] font-mono text-[11px]">
                ⚠ Auditer un système sans autorisation est un délit pénal (Code pénal — atteintes aux STAD). Les sondes sont réelles.
              </span>
            )}
          </>
        ) : (
          <span className="text-[#8c909f] font-mono text-[11px]">
            Déclaration légale indisponible — vérifiez que le backend est démarré.
          </span>
        )}
      </div>

      {/* Categories Filter Tabs */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1">
        {categories.map((cat) => (
          <button
            key={cat.key}
            type="button"
            onClick={() => setSelectedCategory(cat.key)}
            className={`px-3 py-1.5 rounded text-xs font-medium flex items-center gap-2 transition-all shrink-0 ${
              selectedCategory === cat.key
                ? 'bg-[#4d8eff] text-white shadow-sm font-semibold'
                : 'bg-[#171b26] text-[#8c909f] hover:text-[#dfe2f1] hover:bg-[#262a35] border border-[#24314c]'
            }`}
          >
            <span className="material-symbols-outlined text-[15px]">{cat.icon}</span>
            <span>{cat.label}</span>
          </button>
        ))}
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 flex-1 min-h-[580px]">
        {/* Left Column: Vectors Catalog */}
        <div className="lg:col-span-5 bg-[#171b26] border border-[#24314c] rounded-lg flex flex-col overflow-hidden">
          <div className="p-3 bg-[#0a0e18] border-b border-[#24314c] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[18px] text-[#4cd7f6]">target</span>
              <h3 className="font-mono text-xs font-bold text-[#dfe2f1] uppercase tracking-wider">
                Catalogue des Vecteurs ({filteredVectors.length})
              </h3>
            </div>
            <span className="font-mono text-[10px] text-[#8c909f]">Sondes réelles</span>
          </div>

          <div className="flex-1 overflow-y-auto p-3 flex flex-col gap-2.5 font-mono text-xs">
            {filteredVectors.map((vector) => {
              const isSelected = selectedVector.id === vector.id;
              const result = probeResults[vector.id];
              return (
                <div
                  key={vector.id}
                  onClick={() => setSelectedVector(vector)}
                  className={`p-3 rounded border transition-all cursor-pointer flex flex-col gap-2 ${
                    isSelected
                      ? 'bg-[#262a35] border-[#4cd7f6] shadow-sm ring-1 ring-[#4cd7f6]/40'
                      : 'bg-[#0a0e18] border-[#24314c] hover:bg-[#1a1e2b]'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex flex-col gap-0.5">
                      <span className="text-[10px] text-[#8c909f]">{vector.owasp}</span>
                      <strong className="text-white text-xs font-semibold">{vector.name}</strong>
                    </div>

                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold shrink-0 ${
                        vector.severity === 'CRITICAL'
                          ? 'bg-[#93000a]/40 text-[#ffb4ab] border border-[#ffb4ab]/30'
                          : vector.severity === 'HIGH'
                          ? 'bg-[#ea580c]/20 text-[#fb923c] border border-[#fb923c]/30'
                          : 'bg-[#f59e0b]/20 text-[#fbbf24]'
                      }`}
                    >
                      {vector.severity}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-[10px] pt-1 border-t border-[#24314c]/60">
                    <span className="text-[#8c909f]">{vector.cwe.split(':')[0]}</span>
                    {result ? (
                      <span
                        className={`px-1.5 py-0.2 rounded font-bold text-[9px] ${
                          result.verdict === 'VULNERABLE'
                            ? 'bg-[#93000a]/30 text-[#ffb4ab]'
                            : result.verdict === 'PROTECTED'
                            ? 'bg-[#10b981]/20 text-[#34d399]'
                            : 'bg-[#f59e0b]/20 text-[#fbbf24]'
                        }`}
                      >
                        {result.verdict} ({result.requestsSent} req)
                      </span>
                    ) : (
                      <span className="text-[#64748b]">En attente de sonde réelle</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Real Probe Workspace */}
        <div className="lg:col-span-7 bg-[#171b26] border border-[#24314c] rounded-lg flex flex-col overflow-hidden">
          <div className="p-4 bg-[#0a0e18] border-b border-[#24314c] flex flex-col gap-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-bold text-white font-mono">{selectedVector.name}</h3>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#4d8eff]/20 text-[#4cd7f6] border border-[#4d8eff]/30">
                    {selectedVector.category}
                  </span>
                </div>
                <div className="text-[11px] text-[#8c909f] font-mono mt-0.5">{selectedVector.cwe}</div>
              </div>
            </div>

            <div className="flex items-center gap-2 font-mono text-xs pt-1 border-t border-[#24314c]">
              {([
                ['probe', 'play_arrow', 'Sonde Réelle'],
                ['remediation', 'verified_user', 'Contremesures & Remédiation'],
                ['code', 'code', 'Code Avant / Après'],
              ] as const).map(([key, icon, label]) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => setActiveTab(key)}
                  className={`px-3 py-1 rounded flex items-center gap-1.5 transition-all ${
                    activeTab === key
                      ? 'bg-[#262a35] text-[#4cd7f6] font-bold border border-[#4cd7f6]/40'
                      : 'text-[#8c909f] hover:text-white'
                  }`}
                >
                  <span className="material-symbols-outlined text-[15px]">{icon}</span>
                  <span>{label}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Tab 1: Sonde réelle */}
          {activeTab === 'probe' && (
            <div className="flex-1 p-4 overflow-y-auto flex flex-col gap-4 font-mono text-xs">
              <div className="bg-[#0a0e18] border border-[#24314c] rounded-lg p-3 flex flex-col gap-2">
                <div className="flex items-center justify-between text-[11px] text-[#8c909f]">
                  <span className="flex items-center gap-1 text-[#4cd7f6]">
                    <span className="material-symbols-outlined text-[15px]">send</span>
                    <span>Sonde de détection (payload réel, 1 tir, non altérant) :</span>
                  </span>
                  <span className="text-[10px] text-[#10b981]">Requêtes réelles contre {targetConfig.url}</span>
                </div>
                <div className="bg-[#171b26] p-2.5 rounded border border-[#24314c] text-[#dfe2f1] font-mono text-xs select-all max-h-24 overflow-y-auto">
                  {selectedVector.safeTestPayload}
                </div>
                {selectedVector.id === 'jwt-alg-none' && (
                  <div className="flex flex-col gap-1">
                    <label className="text-[11px] text-[#8c909f]">
                      Jeton JWT valide de l'opérateur (requis pour tester alg=none réellement) :
                    </label>
                    <input
                      type="text"
                      value={authToken}
                      onChange={(e) => setAuthToken(e.target.value)}
                      placeholder="eyJhbGciOiJIUzI1NiIs..."
                      className="bg-[#171b26] border border-[#24314c] rounded px-2 py-1.5 text-[11px] text-[#dfe2f1] focus:outline-none focus:border-[#4cd7f6]/60 select-text"
                    />
                  </div>
                )}
              </div>

              <div className="flex items-center justify-between bg-[#121622] p-3 rounded border border-[#24314c]">
                <span className="text-[11px] text-[#c2c6d6] flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#ffb4ab] animate-pulse"></span>
                  La sonde enverra de <strong className="text-[#ffb4ab]">vraies requêtes</strong> à{' '}
                  <strong className="text-[#4cd7f6]">{targetConfig.url}</strong>
                </span>
                <button
                  type="button"
                  onClick={handleRunProbe}
                  disabled={isProbing || !authorized}
                  className="px-4 py-2 rounded text-white font-bold flex items-center gap-2 shadow-md transition-all bg-[#93000a] hover:bg-[#ba1a1a] shadow-red-950/40 disabled:opacity-50"
                >
                  <span className={`material-symbols-outlined text-[16px] ${isProbing ? 'animate-spin' : ''}`}>
                    {isProbing ? 'sync' : 'play_circle'}
                  </span>
                  <span>{isProbing ? 'Sonde réelle en cours…' : 'Lancer la Sonde Réelle'}</span>
                </button>
              </div>

              {currentResult ? (
                <div className="flex flex-col gap-3">
                  <div className="grid grid-cols-4 gap-3">
                    <div className="bg-[#0a0e18] p-2.5 rounded border border-[#24314c] flex flex-col">
                      <span className="text-[10px] text-[#8c909f]">Verdict RÉEL</span>
                      <strong
                        className={`text-sm ${
                          currentResult.verdict === 'VULNERABLE'
                            ? 'text-[#ffb4ab]'
                            : currentResult.verdict === 'PROTECTED'
                            ? 'text-[#34d399]'
                            : 'text-[#fbbf24]'
                        }`}
                      >
                        {currentResult.verdict}
                      </strong>
                    </div>
                    <div className="bg-[#0a0e18] p-2.5 rounded border border-[#24314c] flex flex-col">
                      <span className="text-[10px] text-[#8c909f]">HTTP</span>
                      <strong className="text-sm text-[#4cd7f6]">{currentResult.httpStatus ?? '—'}</strong>
                    </div>
                    <div className="bg-[#0a0e18] p-2.5 rounded border border-[#24314c] flex flex-col">
                      <span className="text-[10px] text-[#8c909f]">Requêtes réelles</span>
                      <strong className="text-sm text-[#dfe2f1]">{currentResult.requestsSent}</strong>
                    </div>
                    <div className="bg-[#0a0e18] p-2.5 rounded border border-[#24314c] flex flex-col">
                      <span className="text-[10px] text-[#8c909f]">Durée réelle</span>
                      <strong className="text-sm text-[#dfe2f1]">{currentResult.durationMs} ms</strong>
                    </div>
                  </div>

                  {currentResult.cvssVector && (
                    <div className="bg-[#0a0e18] border border-[#24314c] rounded-lg p-3 flex flex-col gap-1.5 font-mono">
                      <div className="flex items-center justify-between gap-2 flex-wrap">
                        <span className="text-[11px] text-[#4cd7f6] font-bold">CVSS v3.1 — score CALCULÉ :</span>
                        <strong className="text-sm text-[#dfe2f1]">
                          {currentResult.cvssScore ?? '—'} / 10
                        </strong>
                      </div>
                      <code className="text-[10px] text-[#c2c6d6] select-text break-all">{currentResult.cvssVector}</code>
                    </div>
                  )}

                  <div className="bg-[#0a0e18] border border-[#24314c] rounded-lg p-3 flex flex-col gap-1.5">
                    <span className="text-[11px] text-[#8c909f] font-bold">
                      Échange HTTP RÉEL capturé (requête envoyée → réponse de la cible) :
                    </span>
                    <pre className="bg-[#171b26] p-3 rounded border border-[#24314c] text-[11px] text-[#dfe2f1] overflow-x-auto leading-relaxed max-h-44 select-text whitespace-pre-wrap">
                      {currentResult.realResponse}
                    </pre>
                  </div>

                  <div className="bg-[#0a0e18] border border-[#24314c] rounded-lg p-3 flex flex-col gap-2">
                    <span className="text-[11px] text-[#4cd7f6] font-bold flex items-center gap-1.5">
                      <span className="material-symbols-outlined text-[15px]">analytics</span>
                      <span>Observations réelles :</span>
                    </span>
                    <ul className="flex flex-col gap-1 text-[11px] text-[#c2c6d6] font-sans list-disc list-inside">
                      {currentResult.observations.map((obs, idx) => (
                        <li key={idx} className="leading-snug">{obs}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              ) : (
                <div className="flex-1 flex flex-col items-center justify-center p-8 text-center bg-[#0a0e18] rounded-lg border border-dashed border-[#24314c]">
                  <span className="material-symbols-outlined text-[40px] text-[#8c909f] mb-2">biotech</span>
                  <p className="text-xs text-[#c2c6d6] font-semibold">Aucune sonde réelle exécutée pour ce vecteur.</p>
                  <p className="text-[11px] text-[#8c909f] mt-1 max-w-sm">
                    Cliquez sur « Lancer la Sonde Réelle » pour envoyer de vraies requêtes à la cible et analyser ses vraies réponses.
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Tab 2: Contremesures (contenu pédagogique du catalogue) */}
          {activeTab === 'remediation' && (
            <div className="flex-1 p-4 overflow-y-auto flex flex-col gap-4 font-sans text-xs">
              <div className="bg-[#0a0e18] border border-[#24314c] rounded-lg p-3 flex flex-col gap-1.5 font-mono">
                <span className="text-[11px] text-[#4cd7f6] font-bold">Mécanisme de Défaillance :</span>
                <p className="text-xs text-[#c2c6d6] leading-relaxed font-sans">
                  {selectedVector.vulnerableBehaviorExplanation}
                </p>
              </div>

              <div className="bg-[#0a0e18] border border-[#24314c] rounded-lg p-4 flex flex-col gap-3 font-mono">
                <div className="flex items-center gap-2 text-[#34d399] font-bold text-xs">
                  <span className="material-symbols-outlined text-[18px]">verified</span>
                  <span>Mesures de Durcissement Recommandées (Blue Team) :</span>
                </div>
                <div className="grid grid-cols-1 gap-2.5 font-sans">
                  {selectedVector.defensiveControls.map((step, idx) => (
                    <div
                      key={idx}
                      className="p-2.5 bg-[#171b26] border border-[#24314c] rounded flex items-start gap-2.5 text-xs text-[#dfe2f1]"
                    >
                      <span className="w-5 h-5 rounded-full bg-[#10b981]/20 text-[#10b981] flex items-center justify-center font-bold text-[10px] shrink-0 font-mono">
                        {idx + 1}
                      </span>
                      <span className="leading-snug">{step}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex items-center justify-between pt-2">
                <button
                  type="button"
                  onClick={onGoToResults}
                  className="text-[#4cd7f6] hover:underline flex items-center gap-1 font-mono text-xs"
                >
                  <span>Consulter le Hub des Preuves Qualifiées</span>
                  <span className="material-symbols-outlined text-[14px]">arrow_forward</span>
                </button>
              </div>
            </div>
          )}

          {/* Tab 3: Code Avant / Après (pédagogique) */}
          {activeTab === 'code' && (
            <div className="flex-1 p-4 overflow-y-auto flex flex-col gap-4 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-[#8c909f]">
                  Langage de référence : <strong className="text-white">{selectedVector.remediationCodeExample.language}</strong>
                </span>
                <span className="text-[10px] text-[#10b981]">Conforme OWASP Benchmark</span>
              </div>

              <div className="bg-[#0a0e18] border border-[#93000a]/50 rounded-lg overflow-hidden flex flex-col">
                <div className="px-3 py-1.5 bg-[#93000a]/20 border-b border-[#93000a]/40 flex items-center justify-between">
                  <span className="text-[#ffb4ab] font-bold text-[11px] flex items-center gap-1">
                    <span className="material-symbols-outlined text-[14px]">close</span>
                    <span>Implémentation Vulnérable (À Proscrire)</span>
                  </span>
                </div>
                <pre className="p-3 text-[11px] text-[#ffb4ab] overflow-x-auto leading-relaxed bg-[#0a0e18] select-text">
                  {selectedVector.remediationCodeExample.vulnerable}
                </pre>
              </div>

              <div className="bg-[#0a0e18] border border-[#10b981]/50 rounded-lg overflow-hidden flex flex-col">
                <div className="px-3 py-1.5 bg-[#10b981]/20 border-b border-[#10b981]/40 flex items-center justify-between">
                  <span className="text-[#34d399] font-bold text-[11px] flex items-center gap-1">
                    <span className="material-symbols-outlined text-[14px]">check</span>
                    <span>Implémentation Corrigée & Sécurisée</span>
                  </span>
                  <button
                    type="button"
                    onClick={() => {
                      navigator.clipboard.writeText(selectedVector.remediationCodeExample.fixed);
                      showToast('Code de remédiation copié dans le presse-papier !');
                    }}
                    className="text-[10px] text-[#34d399] hover:underline flex items-center gap-1"
                  >
                    <span className="material-symbols-outlined text-[12px]">content_copy</span>
                    <span>Copier le correctif</span>
                  </button>
                </div>
                <pre className="p-3 text-[11px] text-[#34d399] overflow-x-auto leading-relaxed bg-[#0a0e18] select-text">
                  {selectedVector.remediationCodeExample.fixed}
                </pre>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
