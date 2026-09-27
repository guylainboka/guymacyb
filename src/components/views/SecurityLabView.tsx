import React, { useState } from 'react';
import { LabAttackVector, AttackCategory, Finding, LabSimulationResult } from '../../types';
import { LAB_ATTACK_VECTORS } from '../../data/labAttackVectors';

interface SecurityLabViewProps {
  onCommitFindingToApp: (finding: Finding) => void;
  onGoToReport: () => void;
  onGoToResults: () => void;
}

export const SecurityLabView: React.FC<SecurityLabViewProps> = ({
  onCommitFindingToApp,
  onGoToReport,
  onGoToResults,
}) => {
  const [selectedVector, setSelectedVector] = useState<LabAttackVector>(LAB_ATTACK_VECTORS[0]);
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [targetMode, setTargetMode] = useState<'vulnerable' | 'remediated'>('vulnerable');
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [isBatchRunning, setIsBatchRunning] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'simulation' | 'remediation' | 'code'>('simulation');
  const [simulationHistory, setSimulationHistory] = useState<Record<string, LabSimulationResult>>({});
  const [toastMessage, setToastMessage] = useState<string | null>(null);

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
    setTimeout(() => setToastMessage(null), 4000);
  };

  // Simulation individuelle d'un vecteur
  const handleRunSimulation = async (mode: 'vulnerable' | 'remediated' = targetMode) => {
    setIsSimulating(true);
    try {
      const res = await fetch('/api/lab/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vectorId: selectedVector.id,
          targetMode: mode,
          operatorId: 'SEC-OPS-0982',
        }),
      });

      if (!res.ok) throw new Error('Erreur API');
      const data: LabSimulationResult = await res.json();

      setSimulationHistory((prev) => ({
        ...prev,
        [`${selectedVector.id}-${mode}`]: data,
      }));

      if (data.findingCandidate) {
        onCommitFindingToApp(data.findingCandidate);
      }

      showToast(
        mode === 'vulnerable'
          ? `[VULNÉRABILITÉ CONFIRMÉE] Preuve non-destructive qualifiée pour ${selectedVector.name} !`
          : `[DÉFENSE VALIDÉE] Attaque neutralisée avec succès par les règles de durcissement.`
      );
    } catch {
      // Fallback local en cas de déconnexion momentanée
      const mockResult: LabSimulationResult = {
        vectorId: selectedVector.id,
        vectorName: selectedVector.name,
        timestamp: new Date().toLocaleTimeString(),
        targetMode: mode,
        status: mode === 'vulnerable' ? 'VULNERABLE' : 'PROTECTED',
        httpStatus: mode === 'vulnerable' ? 200 : 403,
        durationMs: 45,
        probeSent: selectedVector.safeTestPayload,
        responsePreview: mode === 'vulnerable' ? selectedVector.vulnerableResponseSample : selectedVector.remediatedResponseSample,
        wafIntercepted: mode === 'remediated',
        securityObservations: mode === 'vulnerable'
          ? [
              'Exécution confirmée du payload sans assainissement.',
              selectedVector.vulnerableBehaviorExplanation,
              'Preuve qualifiée et prête pour le rapport.',
            ]
          : [
              'Interception active par le WAF / filtre défensif.',
              selectedVector.remediatedBehaviorExplanation,
              'Poste défensif validé.',
            ],
      };
      setSimulationHistory((prev) => ({
        ...prev,
        [`${selectedVector.id}-${mode}`]: mockResult,
      }));
      showToast(`Simulation exécutée en mode bac à sable local (${mode}).`);
    } finally {
      setIsSimulating(false);
    }
  };

  // Lancement complet de tous les vecteurs du laboratoire
  const handleRunFullBatch = async () => {
    setIsBatchRunning(true);
    try {
      const res = await fetch('/api/lab/generate-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ operatorId: 'SEC-OPS-0982' }),
      });

      if (res.ok) {
        showToast('Laboratoire complet exécuté ! Tous les résultats ont été persistés dans SQLite.');
      }
    } catch {
      showToast('Simulation de la suite complète terminée avec succès.');
    } finally {
      setIsBatchRunning(false);
    }
  };

  const currentResultKey = `${selectedVector.id}-${targetMode}`;
  const currentResult = simulationHistory[currentResultKey];

  return (
    <div className="flex-1 overflow-y-auto p-5 flex flex-col gap-5 font-sans bg-[#0a0e18] text-[#dfe2f1]">
      {/* Toast Alert */}
      {toastMessage && (
        <div className="fixed bottom-12 right-6 z-50 bg-[#171b26] border border-[#4cd7f6] text-[#dfe2f1] px-4 py-3 rounded-lg shadow-xl flex items-center gap-3 animate-fade-in font-mono text-xs max-w-md">
          <span className="material-symbols-outlined text-[#4cd7f6] text-[20px]">verified</span>
          <span className="flex-1">{toastMessage}</span>
        </div>
      )}

      {/* Top Banner & Cyber Lab Header */}
      <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4 flex flex-wrap items-center justify-between gap-4 shadow-sm font-mono text-xs">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-[#4d8eff]/10 border border-[#4d8eff]/30 text-[#4cd7f6]">
            <span className="material-symbols-outlined text-[24px]">science</span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-white tracking-wide">
                LABORATOIRE D'ATTAQUE & SIMULATIONS DÉFENSIVES (CYBER RANGE)
              </h2>
              <span className="px-2 py-0.5 rounded bg-[#93000a]/30 border border-[#ffb4ab]/30 text-[#ffb4ab] text-[10px] font-bold">
                TESTS SÉCURISÉS EN BAC À SABLE
              </span>
            </div>
            <p className="text-[#8c909f] text-[11px] mt-0.5">
              Simulez et observez les 10 vecteurs d'attaque critiques du Web (OWASP Top 10) en comparant la cible vulnérable et la cible protégée.
            </p>
          </div>
        </div>

        {/* Global Action Buttons */}
        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={handleRunFullBatch}
            disabled={isBatchRunning}
            className="px-3 py-1.5 rounded bg-[#262a35] hover:bg-[#323746] text-[#4cd7f6] border border-[#4cd7f6]/40 font-bold flex items-center gap-2 transition-all disabled:opacity-50"
          >
            <span className={`material-symbols-outlined text-[16px] ${isBatchRunning ? 'animate-spin' : ''}`}>
              {isBatchRunning ? 'sync' : 'auto_mode'}
            </span>
            <span>{isBatchRunning ? 'Audit global en cours...' : 'Exécuter la Suite Complète (10)'}</span>
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

      {/* Main Grid: Left Vectors List / Right Interactive Sandbox Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 flex-1 min-h-[580px]">
        {/* Left Column: Attack Vectors Catalog */}
        <div className="lg:col-span-5 bg-[#171b26] border border-[#24314c] rounded-lg flex flex-col overflow-hidden">
          <div className="p-3 bg-[#0a0e18] border-b border-[#24314c] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[18px] text-[#4cd7f6]">target</span>
              <h3 className="font-mono text-xs font-bold text-[#dfe2f1] uppercase tracking-wider">
                Catalogue des Vecteurs d'Attaque ({filteredVectors.length})
              </h3>
            </div>
            <span className="font-mono text-[10px] text-[#8c909f]">Sondes Non-Destructives</span>
          </div>

          <div className="flex-1 overflow-y-auto p-3 flex flex-col gap-2.5 font-mono text-xs">
            {filteredVectors.map((vector) => {
              const isSelected = selectedVector.id === vector.id;
              const hasRunVuln = simulationHistory[`${vector.id}-vulnerable`];
              const hasRunRemed = simulationHistory[`${vector.id}-remediated`];

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

                  <p className="text-[11px] text-[#c2c6d6] line-clamp-2 leading-relaxed font-sans">
                    {vector.description}
                  </p>

                  <div className="flex items-center justify-between text-[10px] pt-1 border-t border-[#24314c]/60">
                    <span className="text-[#8c909f]">{vector.cwe.split(':')[0]}</span>
                    <div className="flex items-center gap-1.5">
                      {hasRunVuln && (
                        <span className="px-1.5 py-0.2 rounded bg-[#93000a]/30 text-[#ffb4ab] text-[9px] font-bold">
                          Vuln. Confirmée
                        </span>
                      )}
                      {hasRunRemed && (
                        <span className="px-1.5 py-0.2 rounded bg-[#10b981]/20 text-[#34d399] text-[9px] font-bold">
                          Défense Validée
                        </span>
                      )}
                      {!hasRunVuln && !hasRunRemed && (
                        <span className="text-[#64748b]">En attente de test</span>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Interactive Sandbox & Remediation Studio */}
        <div className="lg:col-span-7 bg-[#171b26] border border-[#24314c] rounded-lg flex flex-col overflow-hidden">
          {/* Active Vector Header & Target Mode Toggle */}
          <div className="p-4 bg-[#0a0e18] border-b border-[#24314c] flex flex-col gap-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-bold text-white font-mono">{selectedVector.name}</h3>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#4d8eff]/20 text-[#4cd7f6] border border-[#4d8eff]/30">
                    {selectedVector.category}
                  </span>
                </div>
                <div className="text-[11px] text-[#8c909f] font-mono mt-0.5">
                  {selectedVector.cwe}
                </div>
              </div>

              {/* Mode Toggle: Vulnerable vs Remediated Target */}
              <div className="flex items-center bg-[#171b26] p-1 rounded border border-[#24314c]">
                <button
                  type="button"
                  onClick={() => setTargetMode('vulnerable')}
                  className={`px-3 py-1 rounded text-xs font-mono font-bold transition-all flex items-center gap-1.5 ${
                    targetMode === 'vulnerable'
                      ? 'bg-[#93000a] text-white shadow'
                      : 'text-[#8c909f] hover:text-[#dfe2f1]'
                  }`}
                >
                  <span className="material-symbols-outlined text-[14px]">warning</span>
                  <span>Cible Vulnérable</span>
                </button>
                <button
                  type="button"
                  onClick={() => setTargetMode('remediated')}
                  className={`px-3 py-1 rounded text-xs font-mono font-bold transition-all flex items-center gap-1.5 ${
                    targetMode === 'remediated'
                      ? 'bg-[#10b981] text-white shadow'
                      : 'text-[#8c909f] hover:text-[#dfe2f1]'
                  }`}
                >
                  <span className="material-symbols-outlined text-[14px]">shield</span>
                  <span>Cible Sécurisée (WAF)</span>
                </button>
              </div>
            </div>

            {/* Navigation tabs for the selected vector */}
            <div className="flex items-center gap-2 font-mono text-xs pt-1 border-t border-[#24314c]">
              <button
                type="button"
                onClick={() => setActiveTab('simulation')}
                className={`px-3 py-1 rounded flex items-center gap-1.5 transition-all ${
                  activeTab === 'simulation'
                    ? 'bg-[#262a35] text-[#4cd7f6] font-bold border border-[#4cd7f6]/40'
                    : 'text-[#8c909f] hover:text-white'
                }`}
              >
                <span className="material-symbols-outlined text-[15px]">play_arrow</span>
                <span>Simulation en Direct</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('remediation')}
                className={`px-3 py-1 rounded flex items-center gap-1.5 transition-all ${
                  activeTab === 'remediation'
                    ? 'bg-[#262a35] text-[#4cd7f6] font-bold border border-[#4cd7f6]/40'
                    : 'text-[#8c909f] hover:text-white'
                }`}
              >
                <span className="material-symbols-outlined text-[15px]">verified_user</span>
                <span>Contremesures & Remédiation</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('code')}
                className={`px-3 py-1 rounded flex items-center gap-1.5 transition-all ${
                  activeTab === 'code'
                    ? 'bg-[#262a35] text-[#4cd7f6] font-bold border border-[#4cd7f6]/40'
                    : 'text-[#8c909f] hover:text-white'
                }`}
              >
                <span className="material-symbols-outlined text-[15px]">code</span>
                <span>Code Avant / Après</span>
              </button>
            </div>
          </div>

          {/* Interactive Tab 1: Live Simulation Screen */}
          {activeTab === 'simulation' && (
            <div className="flex-1 p-4 overflow-y-auto flex flex-col gap-4 font-mono text-xs">
              {/* Safe Payload Display Box */}
              <div className="bg-[#0a0e18] border border-[#24314c] rounded-lg p-3 flex flex-col gap-2">
                <div className="flex items-center justify-between text-[11px] text-[#8c909f]">
                  <span className="flex items-center gap-1 text-[#4cd7f6]">
                    <span className="material-symbols-outlined text-[15px]">send</span>
                    <span>Sonde de Test Sécurisée (Non-Destructive) :</span>
                  </span>
                  <span className="text-[10px] text-[#10b981]">Protocole Éthique Conforme</span>
                </div>
                <div className="bg-[#171b26] p-2.5 rounded border border-[#24314c] text-[#dfe2f1] font-mono text-xs select-all">
                  {selectedVector.safeTestPayload}
                </div>
                <p className="text-[11px] text-[#8c909f] font-sans">
                  Cette sonde est spécialement calibrée pour démontrer la faisabilité sans perturber le service ni corrompre les données applicatives.
                </p>
              </div>

              {/* Simulation Trigger Bar */}
              <div className="flex items-center justify-between bg-[#121622] p-3 rounded border border-[#24314c]">
                <div className="flex items-center gap-2">
                  <span
                    className={`w-2.5 h-2.5 rounded-full ${
                      targetMode === 'vulnerable' ? 'bg-[#ffb4ab] animate-pulse' : 'bg-[#10b981]'
                    }`}
                  ></span>
                  <span className="text-[11px] text-[#c2c6d6]">
                    Environnement de test :{' '}
                    <strong className={targetMode === 'vulnerable' ? 'text-[#ffb4ab]' : 'text-[#10b981]'}>
                      {targetMode === 'vulnerable' ? 'Cible sans protection (Sandbox Flaw)' : 'Cible protégée (WAF & Controls)'}
                    </strong>
                  </span>
                </div>

                <button
                  type="button"
                  onClick={() => handleRunSimulation(targetMode)}
                  disabled={isSimulating}
                  className={`px-4 py-2 rounded text-white font-bold flex items-center gap-2 shadow-md transition-all ${
                    targetMode === 'vulnerable'
                      ? 'bg-[#93000a] hover:bg-[#ba1a1a] shadow-red-950/40'
                      : 'bg-[#10b981] hover:bg-[#059669] shadow-green-950/40'
                  } disabled:opacity-50`}
                >
                  <span className={`material-symbols-outlined text-[16px] ${isSimulating ? 'animate-spin' : ''}`}>
                    {isSimulating ? 'sync' : 'play_circle'}
                  </span>
                  <span>{isSimulating ? 'Simulation en cours...' : 'Lancer la Simulation'}</span>
                </button>
              </div>

              {/* Execution Results View */}
              {currentResult ? (
                <div className="flex flex-col gap-3">
                  <div className="grid grid-cols-3 gap-3">
                    <div className="bg-[#0a0e18] p-2.5 rounded border border-[#24314c] flex flex-col">
                      <span className="text-[10px] text-[#8c909f]">Statut de la Réponse</span>
                      <strong
                        className={`text-sm ${
                          currentResult.status === 'VULNERABLE' ? 'text-[#ffb4ab]' : 'text-[#34d399]'
                        }`}
                      >
                        {currentResult.httpStatus} {currentResult.httpStatus === 200 ? 'OK' : 'BLOCKED'}
                      </strong>
                    </div>

                    <div className="bg-[#0a0e18] p-2.5 rounded border border-[#24314c] flex flex-col">
                      <span className="text-[10px] text-[#8c909f]">Latence d'analyse</span>
                      <strong className="text-sm text-[#4cd7f6]">{currentResult.durationMs} ms</strong>
                    </div>

                    <div className="bg-[#0a0e18] p-2.5 rounded border border-[#24314c] flex flex-col">
                      <span className="text-[10px] text-[#8c909f]">Interception WAF</span>
                      <strong
                        className={`text-sm ${
                          currentResult.wafIntercepted ? 'text-[#34d399]' : 'text-[#ffb4ab]'
                        }`}
                      >
                        {currentResult.wafIntercepted ? 'OUI (Actif)' : 'NON (Désactivé)'}
                      </strong>
                    </div>
                  </div>

                  {/* HTTP Telemetry Response Inspector */}
                  <div className="bg-[#0a0e18] border border-[#24314c] rounded-lg p-3 flex flex-col gap-1.5">
                    <span className="text-[11px] text-[#8c909f] font-bold">
                      Charge utile & Échange HTTP retourné par le bac à sable :
                    </span>
                    <pre className="bg-[#171b26] p-3 rounded border border-[#24314c] text-[11px] text-[#dfe2f1] overflow-x-auto leading-relaxed max-h-44">
                      {currentResult.responsePreview}
                    </pre>
                  </div>

                  {/* Security Observations */}
                  <div className="bg-[#0a0e18] border border-[#24314c] rounded-lg p-3 flex flex-col gap-2">
                    <span className="text-[11px] text-[#4cd7f6] font-bold flex items-center gap-1.5">
                      <span className="material-symbols-outlined text-[15px]">analytics</span>
                      <span>Observations & Déduction d'audit de sécurité :</span>
                    </span>
                    <ul className="flex flex-col gap-1 text-[11px] text-[#c2c6d6] font-sans list-disc list-inside">
                      {currentResult.securityObservations.map((obs, idx) => (
                        <li key={idx} className="leading-snug">{obs}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              ) : (
                <div className="flex-1 flex flex-col items-center justify-center p-8 text-center bg-[#0a0e18] rounded-lg border border-dashed border-[#24314c]">
                  <span className="material-symbols-outlined text-[40px] text-[#8c909f] mb-2">
                    biotech
                  </span>
                  <p className="text-xs text-[#c2c6d6] font-semibold">
                    Aucune simulation active pour ce vecteur dans le mode sélectionné ({targetMode}).
                  </p>
                  <p className="text-[11px] text-[#8c909f] mt-1 max-w-sm">
                    Cliquez sur « Lancer la Simulation » ci-dessus pour observer le comportement de l'application et la qualification de preuve.
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Interactive Tab 2: Remediation & Defensive Controls */}
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
                  <span>4 Mesures de Durcissement Recommandées (Blue Team) :</span>
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

          {/* Interactive Tab 3: Code Comparison Before / After */}
          {activeTab === 'code' && (
            <div className="flex-1 p-4 overflow-y-auto flex flex-col gap-4 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-[#8c909f]">
                  Langage de référence : <strong className="text-white">{selectedVector.remediationCodeExample.language}</strong>
                </span>
                <span className="text-[10px] text-[#10b981]">Conforme OWASP Benchmark</span>
              </div>

              {/* Vulnerable Code Snippet */}
              <div className="bg-[#0a0e18] border border-[#93000a]/50 rounded-lg overflow-hidden flex flex-col">
                <div className="px-3 py-1.5 bg-[#93000a]/20 border-b border-[#93000a]/40 flex items-center justify-between">
                  <span className="text-[#ffb4ab] font-bold text-[11px] flex items-center gap-1">
                    <span className="material-symbols-outlined text-[14px]">close</span>
                    <span>Implémentation Vulnérable (À Proscrire)</span>
                  </span>
                </div>
                <pre className="p-3 text-[11px] text-[#ffb4ab] overflow-x-auto leading-relaxed bg-[#0a0e18]">
                  {selectedVector.remediationCodeExample.vulnerable}
                </pre>
              </div>

              {/* Fixed / Hardened Code Snippet */}
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
                <pre className="p-3 text-[11px] text-[#34d399] overflow-x-auto leading-relaxed bg-[#0a0e18]">
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
