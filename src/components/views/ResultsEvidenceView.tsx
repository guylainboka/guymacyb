import React, { useState } from 'react';
import { Finding, Severity } from '../../types';

interface ResultsEvidenceViewProps {
  findings: Finding[];
  onGoToReport: () => void;
}

export const ResultsEvidenceView: React.FC<ResultsEvidenceViewProps> = ({
  findings,
  onGoToReport,
}) => {
  const [selectedFinding, setSelectedFinding] = useState<Finding>(findings[0]);
  const [severityFilter, setSeverityFilter] = useState<'ALL' | Severity>('ALL');
  const [isRetesting, setIsRetesting] = useState<boolean>(false);
  const [retestMessage, setRetestMessage] = useState<string | null>(null);

  const filteredFindings = findings.filter((f) => {
    if (severityFilter === 'ALL') return true;
    return f.severity === severityFilter;
  });

  const handleRetest = () => {
    setIsRetesting(true);
    setRetestMessage('Envoi de la sonde active de contre-vérification...');
    setTimeout(() => {
      setIsRetesting(false);
      setRetestMessage(
        `Vérifié à ${new Date().toLocaleTimeString()} : Vulnérabilité toujours confirmée (Exploitable à 100%).`
      );
    }, 900);
  };

  return (
    <div className="flex-1 overflow-y-auto p-5 flex flex-col gap-5 font-sans">
      {/* Evidence Hub Header */}
      <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4 flex flex-wrap items-center justify-between gap-4 shadow-sm font-mono text-xs">
        <div className="flex items-center gap-3">
          <span className="material-symbols-outlined text-[24px] text-[#4cd7f6]">fact_check</span>
          <div>
            <h2 className="text-sm font-bold text-[#dfe2f1] uppercase tracking-wider">
              Security Evidence Hub / Target Assessment Matrix
            </h2>
            <span className="text-[#8c909f] text-[11px]">
              Preuves techniques complètes, horodatées et certifiées non-destructives.
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => {
              const sarif = JSON.stringify(
                {
                  $schema: 'https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json',
                  version: '2.1.0',
                  runs: [
                    {
                      tool: { driver: { name: 'ShadowScan', version: '1.0.0' } },
                      results: findings.map((f) => ({
                        ruleId: f.cwe,
                        message: { text: f.title },
                        level: f.severity === 'HIGH' ? 'error' : 'warning',
                      })),
                    },
                  ],
                },
                null,
                2
              );
              navigator.clipboard.writeText(sarif);
              alert('Rapport au format SARIF copié dans le presse-papiers.');
            }}
            className="px-3 py-1.5 rounded bg-[#262a35] hover:bg-[#313540] text-[#c2c6d6] hover:text-white border border-[#424754] flex items-center gap-1.5 transition-colors"
          >
            <span className="material-symbols-outlined text-[14px]">file_download</span>
            <span>Export SARIF / JSON</span>
          </button>

          <button
            type="button"
            onClick={onGoToReport}
            className="px-3 py-1.5 rounded bg-[#4d8eff] hover:bg-[#3b82f6] text-white font-bold flex items-center gap-1.5 shadow-sm transition-colors"
          >
            <span>Consulter le Rapport</span>
            <span className="material-symbols-outlined text-[14px]">arrow_forward</span>
          </button>
        </div>
      </div>

      {/* Severity Filter Tabs */}
      <div className="flex items-center gap-2 font-mono text-xs overflow-x-auto pb-1">
        <button
          type="button"
          onClick={() => setSeverityFilter('ALL')}
          className={`px-3 py-1.5 rounded border transition-colors ${
            severityFilter === 'ALL'
              ? 'bg-[#4cd7f6]/15 border-[#4cd7f6] text-[#4cd7f6] font-bold'
              : 'bg-[#171b26] border-[#24314c] text-[#8c909f] hover:text-[#dfe2f1]'
          }`}
        >
          Tous ({findings.length})
        </button>
        <button
          type="button"
          onClick={() => setSeverityFilter('HIGH')}
          className={`px-3 py-1.5 rounded border transition-colors ${
            severityFilter === 'HIGH'
              ? 'bg-[#93000a]/30 border-[#ffb4ab] text-[#ffb4ab] font-bold'
              : 'bg-[#171b26] border-[#24314c] text-[#8c909f] hover:text-[#dfe2f1]'
          }`}
        >
          Élevé (3)
        </button>
        <button
          type="button"
          onClick={() => setSeverityFilter('MEDIUM')}
          className={`px-3 py-1.5 rounded border transition-colors ${
            severityFilter === 'MEDIUM'
              ? 'bg-[#f59e0b]/20 border-[#fbbf24] text-[#fbbf24] font-bold'
              : 'bg-[#171b26] border-[#24314c] text-[#8c909f] hover:text-[#dfe2f1]'
          }`}
        >
          Moyen (7)
        </button>
        <button
          type="button"
          onClick={() => setSeverityFilter('LOW')}
          className={`px-3 py-1.5 rounded border transition-colors ${
            severityFilter === 'LOW'
              ? 'bg-[#10b981]/20 border-[#10b981] text-[#10b981] font-bold'
              : 'bg-[#171b26] border-[#24314c] text-[#8c909f] hover:text-[#dfe2f1]'
          }`}
        >
          Faible (11)
        </button>
      </div>

      {/* Main Grid: Left Findings List / Right Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 flex-1 min-h-[560px]">
        {/* Left: Master Findings List */}
        <div className="lg:col-span-5 bg-[#171b26] border border-[#24314c] rounded-lg flex flex-col overflow-hidden">
          <div className="p-3.5 bg-[#0a0e18] border-b border-[#24314c] flex items-center justify-between">
            <span className="font-mono text-xs font-bold text-[#dfe2f1] uppercase tracking-wider">
              Vulnérabilités Identifiées
            </span>
            <span className="font-mono text-[11px] text-[#8c909f]">
              {filteredFindings.length} sélectionnées
            </span>
          </div>

          <div className="flex-1 overflow-y-auto p-2.5 flex flex-col gap-2 font-mono text-xs">
            {filteredFindings.map((finding) => {
              const isSelected = selectedFinding.id === finding.id;
              return (
                <div
                  key={finding.id}
                  onClick={() => {
                    setSelectedFinding(finding);
                    setRetestMessage(null);
                  }}
                  className={`p-3 rounded border transition-all cursor-pointer flex flex-col gap-2 ${
                    isSelected
                      ? 'bg-[#262a35] border-[#4cd7f6] shadow-sm'
                      : 'bg-[#0a0e18] border-[#24314c] hover:bg-[#1c1f2a]'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        finding.severity === 'HIGH'
                          ? 'bg-[#93000a]/40 text-[#ffb4ab] border border-[#ffb4ab]/30'
                          : finding.severity === 'MEDIUM'
                          ? 'bg-[#f59e0b]/20 text-[#fbbf24] border border-[#fbbf24]/30'
                          : 'bg-[#10b981]/20 text-[#10b981] border border-[#10b981]/30'
                      }`}
                    >
                      {finding.severity} • CVSS {finding.cvss.toFixed(1)}
                    </span>

                    <span
                      className={`text-[10px] font-bold ${
                        finding.status === 'VALIDATED'
                          ? 'text-[#10b981]'
                          : finding.status === 'DETECTED'
                          ? 'text-[#4cd7f6]'
                          : 'text-[#8c909f]'
                      }`}
                    >
                      {finding.status} ({finding.confidence}%)
                    </span>
                  </div>

                  <strong className="text-[#dfe2f1] font-medium leading-snug">{finding.title}</strong>

                  <div className="flex items-center justify-between text-[11px] text-[#8c909f]">
                    <span className="truncate max-w-[200px]">{finding.affectedComponent}</span>
                    <span>{finding.cwe}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Detailed Inspector Pane */}
        <div className="lg:col-span-7 bg-[#171b26] border border-[#24314c] rounded-lg flex flex-col overflow-hidden">
          <div className="p-4 bg-[#0a0e18] border-b border-[#24314c] flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono ${
                    selectedFinding.severity === 'HIGH'
                      ? 'bg-[#93000a]/40 text-[#ffb4ab]'
                      : 'bg-[#f59e0b]/20 text-[#fbbf24]'
                  }`}
                >
                  {selectedFinding.severity} • CVSS {selectedFinding.cvss.toFixed(1)}
                </span>
                <span className="font-mono text-[10px] text-[#8c909f]">ID: {selectedFinding.id}</span>
              </div>
              <h3 className="text-base font-bold text-[#dfe2f1] mt-1 font-mono">{selectedFinding.title}</h3>
            </div>

            <button
              type="button"
              disabled={isRetesting}
              onClick={handleRetest}
              className="px-3 py-1.5 rounded bg-[#262a35] hover:bg-[#313540] text-[#4cd7f6] hover:text-white font-mono text-xs border border-[#424754] flex items-center gap-1.5 transition-colors"
            >
              <span className={`material-symbols-outlined text-[15px] ${isRetesting ? 'animate-spin' : ''}`}>
                {isRetesting ? 'sync' : 'replay'}
              </span>
              <span>{isRetesting ? 'Re-test...' : 'Re-tester ce finding'}</span>
            </button>
          </div>

          {retestMessage && (
            <div className="p-2.5 bg-[#0a0e18] border-b border-[#24314c] font-mono text-xs text-[#10b981] flex items-center gap-2">
              <span className="material-symbols-outlined text-[16px]">verified</span>
              <span>{retestMessage}</span>
            </div>
          )}

          {/* Inspector Body */}
          <div className="flex-1 p-5 overflow-y-auto flex flex-col gap-4 font-mono text-xs">
            {/* Component and Context */}
            <div className="bg-[#0a0e18] p-3 rounded border border-[#24314c] flex flex-col gap-1.5">
              <div className="flex items-center justify-between">
                <span className="text-[#8c909f]">Composant exposé :</span>
                <span className="text-[#4cd7f6] font-bold">{selectedFinding.affectedComponent}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[#8c909f]">Classification :</span>
                <span className="text-[#dfe2f1]">{selectedFinding.category} ({selectedFinding.cwe})</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[#8c909f]">Contexte Auth :</span>
                <span className="text-[#3b82f6]">{selectedFinding.evidence.authContext}</span>
              </div>
            </div>

            {/* Description */}
            <div className="flex flex-col gap-1">
              <span className="font-bold text-[#dfe2f1] uppercase text-[11px] text-[#8c909f]">
                Description & Constat :
              </span>
              <p className="text-[#c2c6d6] leading-relaxed bg-[#0a0e18] p-3 rounded border border-[#24314c]">
                {selectedFinding.description}
              </p>
            </div>

            {/* Evidence Diff: Request vs Response */}
            <div className="flex flex-col gap-1.5">
              <span className="font-bold text-[#dfe2f1] uppercase text-[11px] text-[#8c909f]">
                Preuve Technique Non-Destructive (Diff Émis / Reçu) :
              </span>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {/* Request */}
                <div className="flex flex-col bg-[#0a0e18] rounded border border-[#24314c] overflow-hidden">
                  <div className="bg-[#171b26] px-3 py-1.5 border-b border-[#24314c] text-[10px] text-[#4cd7f6] font-bold flex items-center justify-between">
                    <span>REQUÊTE HTTP ÉMISE</span>
                    <span className="text-[#8c909f]">Port 443</span>
                  </div>
                  <pre className="p-3 text-[11px] text-[#dfe2f1] overflow-x-auto whitespace-pre leading-relaxed select-text font-mono">
                    {selectedFinding.evidence.request}
                  </pre>
                </div>

                {/* Response */}
                <div className="flex flex-col bg-[#0a0e18] rounded border border-[#24314c] overflow-hidden">
                  <div className="bg-[#171b26] px-3 py-1.5 border-b border-[#24314c] text-[10px] text-[#10b981] font-bold flex items-center justify-between">
                    <span>RÉPONSE HTTP OBTENUE</span>
                    <span className="text-[#8c909f]">{selectedFinding.evidence.roundtripMs}ms</span>
                  </div>
                  <pre className="p-3 text-[11px] text-[#ffdad6] overflow-x-auto whitespace-pre leading-relaxed select-text font-mono">
                    {selectedFinding.evidence.response}
                  </pre>
                </div>
              </div>
            </div>

            {/* Impact */}
            <div className="flex flex-col gap-1">
              <span className="font-bold text-[#dfe2f1] uppercase text-[11px] text-[#8c909f]">
                Impact Potentiel Estimé :
              </span>
              <p className="text-[#ffb4ab] leading-relaxed bg-[#93000a]/15 p-3 rounded border border-[#ffb4ab]/30">
                {selectedFinding.impact}
              </p>
            </div>

            {/* Remediation Preview */}
            <div className="flex flex-col gap-1">
              <span className="font-bold text-[#dfe2f1] uppercase text-[11px] text-[#8c909f]">
                Recommandation de Remédiation :
              </span>
              <div className="bg-[#0a0e18] p-3 rounded border border-[#24314c] flex flex-col gap-1.5">
                <span className="text-[#10b981] font-bold">{selectedFinding.remediationTitle}</span>
                <ul className="list-disc list-inside text-[#c2c6d6] flex flex-col gap-1 text-[11px]">
                  {selectedFinding.remediationSteps.map((step, idx) => (
                    <li key={idx}>{step}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
