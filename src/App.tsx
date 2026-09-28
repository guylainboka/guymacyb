import React, { useState } from 'react';
import { ModuleView, TargetConfig, HistoricalTarget, TerminalLog, Finding, EndpointItem, ActiveTestFamily } from './types';
import { Header } from './components/common/Header';
import { Sidebar } from './components/common/Sidebar';
import { Footer } from './components/common/Footer';
import { ActiveTestAuthModal } from './components/common/ActiveTestAuthModal';
import { SettingsModal } from './components/common/SettingsModal';
import { DocsModal } from './components/common/DocsModal';
import { DesktopPackagingModal } from './components/common/DesktopPackagingModal';
import { ScannerReconView } from './components/views/ScannerReconView';
import { DashboardView } from './components/views/DashboardView';
import { ReseauLocalView } from './components/views/ReseauLocalView';
import { ArsenalView } from './components/views/ArsenalView';
import { GeoMacView } from './components/views/GeoMacView';
import { CoreManagerView } from './components/views/CoreManagerView';
import { HidAttacksView } from './components/views/HidAttacksView';
import { UsbArsenalView } from './components/views/UsbArsenalView';
import { CameradarView } from './components/views/CameradarView';
import { AnalyseWebView } from './components/views/AnalyseWebView';
import { ActiveTestsView } from './components/views/ActiveTestsView';
import { ResultsEvidenceView } from './components/views/ResultsEvidenceView';
import { ReportRemediationView } from './components/views/ReportRemediationView';
import { SecurityLabView } from './components/views/SecurityLabView';
import { WifiReseauView } from './components/views/WifiReseauView';
import { CoursNotionsView } from './components/views/CoursNotionsView';
import { LaboratoireWifiView } from './components/views/LaboratoireWifiView';
import { TerminalView } from './components/views/TerminalView';

export default function App() {
  const [currentView, setCurrentView] = useState<ModuleView>('dashboard');
  const [targetConfig, setTargetConfig] = useState<TargetConfig>({
    url: 'https://example.com',
    port: 443,
    scope: 'wildcard',
    authorized: true,
    operatorId: 'SEC-OPS-0982',
    localDbName: 'shadow_core.db',
  });

  const [safeMode, setSafeMode] = useState<boolean>(true);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [isTesting, setIsTesting] = useState<boolean>(false);
  const [engineStatus, setEngineStatus] = useState<string>('Prêt pour évaluation');

  // Doctrine « zéro simulation » : tous les états démarrent VIDES. Aucune
  // donnée fictive n'est chargée au démarrage — l'utilisateur voit un
  // tableau de bord honnête (« Aucune donnée disponible ») jusqu'à ce qu'il
  // lance un vrai scan. Les cibles/findings/endpoints réels proviennent du
  // backend SQLite via le useEffect ci-dessous.
  const [historicalTargets, setHistoricalTargets] = useState<HistoricalTarget[]>([]);
  const [endpointsTree, setEndpointsTree] = useState<EndpointItem[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [testFamilies] = useState<ActiveTestFamily[]>([]);
  const [terminalLogs, setTerminalLogs] = useState<TerminalLog[]>([]);

  // Modals state
  const [isAuthModalOpen, setIsAuthModalOpen] = useState<boolean>(false);
  const [isSettingsModalOpen, setIsSettingsModalOpen] = useState<boolean>(false);
  const [isDocsModalOpen, setIsDocsModalOpen] = useState<boolean>(false);
  const [isPackagingModalOpen, setIsPackagingModalOpen] = useState<boolean>(false);

  // Load real historical targets and findings from SQLite on mount
  React.useEffect(() => {
    const ac = new AbortController();
    async function loadSqliteData() {
      try {
        const [targetsRes, findingsRes] = await Promise.all([
          fetch('/api/targets', { signal: ac.signal }),
          fetch('/api/findings', { signal: ac.signal }),
        ]);
        if (targetsRes.ok) {
          const targetsData = await targetsRes.json();
          if (Array.isArray(targetsData) && targetsData.length > 0) {
            setHistoricalTargets(targetsData);
          }
        }
        if (findingsRes.ok) {
          const findingsData = await findingsRes.json();
          if (Array.isArray(findingsData) && findingsData.length > 0) {
            setFindings(findingsData);
          }
        }
      } catch (err: any) {
        if (err?.name === 'AbortError') return; // composant démonté — ignore
        // Doctrine « zéro simulation » : on n'affiche plus de fallback implicite.
        // Le dashboard reste vide jusqu'à un vrai scan réussi.
        console.warn('Backend SQLite non joignable (les données réelles seront chargées au prochain scan) :', err);
      }
    }
    loadSqliteData();
    return () => ac.abort();
  }, []);

  // Start real passive/semi-active analysis on the server
  const handleLaunchAnalysis = async () => {
    setIsAnalyzing(true);
    setEngineStatus(`Analyse réseau réelle en cours sur ${targetConfig.url}...`);

    try {
      const res = await fetch('/api/scan/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: targetConfig.url,
          scope: targetConfig.scope,
          operatorId: targetConfig.operatorId,
        }),
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({ error: 'Erreur inconnue' }));
        throw new Error(errorData.error || 'Erreur réseau');
      }

      const scanResult = await res.json();

      // Update real endpoints discovered
      if (scanResult.endpoints && scanResult.endpoints.length > 0) {
        setEndpointsTree(scanResult.endpoints);
      }

      // Update findings with real identified vulnerabilities
      if (scanResult.findings && scanResult.findings.length > 0) {
        setFindings(scanResult.findings);
      }

      // Append real terminal logs
      const auditLog: TerminalLog = {
        id: String(Date.now()),
        timestamp: new Date().toLocaleTimeString(),
        tag: 'RECON',
        text: `Target ${scanResult.domain} audited: HTTP ${scanResult.statusCode} in ${scanResult.latencyMs}ms (${scanResult.summary.endpointsCount} endpoints, ${scanResult.summary.anomaliesCount} findings)`,
      };
      setTerminalLogs((prev) => [...prev, auditLog]);

      // Refresh historical targets list from SQLite
      try {
        const targetsRes = await fetch('/api/targets');
        if (targetsRes.ok) {
          const targetsData = await targetsRes.json();
          if (Array.isArray(targetsData) && targetsData.length > 0) {
            setHistoricalTargets(targetsData);
          }
        }
      } catch {
        // ignore
      }

      setEngineStatus(
        `Audit réel terminé • ${scanResult.summary.endpointsCount} endpoints • Risque: ${scanResult.overallRisk} (CVSS ${scanResult.cvssScore})`
      );
      setIsAnalyzing(false);
      setCurrentView('analyse-web');
    } catch (err: any) {
      // Doctrine "zéro simulation" : un échec d'analyse doit être affiché comme
      // tel. L'ancien code affichait un faux succès ("Cartographie terminée •
      // 137 endpoints") même sur erreur backend — contre-productif pour un
      // outil de sécurité.
      console.error('Échec de l\'analyse réseau réelle:', err);
      setIsAnalyzing(false);
      setEngineStatus(`Échec de l'analyse : ${err?.message || 'erreur réseau'} — vérifiez la cible et le moteur backend`);
    }
  };

  // Trigger active test sequence
  const handleLaunchAttack = () => {
    setIsAuthModalOpen(true);
  };

  // Start confirmed active test
  // Doctrine « zéro simulation » : l'ancien code simulait une suite de tests
  // actifs via un setTimeout(4500ms) puis affichait « 3 vulnérabilités
  // confirmées » SANS AUCUN appel backend. C'était un mensonge dangereux dans
  // un outil de sécurité. En attendant l'implémentation d'une vraie API
  // `/api/tests/active/run` (exécutant de vraies sondes contrôlées), on
  // affiche honnêtement que la fonctionnalité n'est pas encore implémentée.
  const handleStartAttackConfirmed = () => {
    setIsAuthModalOpen(false);
    setEngineStatus('Tests actifs : fonctionnalité non configurée');
    setTerminalLogs((prev) => [
      ...prev,
      {
        id: String(Date.now()),
        timestamp: new Date().toLocaleTimeString(),
        tag: 'WARN',
        text: `Tests actifs non implémentés — aucune sonde lancée sur ${targetConfig.url}. La fonctionnalité sera disponible après l'ajout de l'API /api/tests/active/run.`,
      },
    ]);
    setCurrentView('tests-actifs-and-attaque');
  };

  const handleStopTest = () => {
    setIsTesting(false);
    setEngineStatus("Arrêté d'urgence par l'opérateur");
    setTerminalLogs((prev) => [
      ...prev,
      {
        id: String(Date.now()),
        timestamp: new Date().toLocaleTimeString(),
        tag: 'WARN',
        text: 'EMERGENCY STOP initiated by operator. Workers terminated cleanly.',
      },
    ]);
  };

  const handleSelectHistoricalTarget = (hist: HistoricalTarget) => {
    setTargetConfig((prev) => ({
      ...prev,
      url: hist.url,
    }));
    setEngineStatus(`Cible chargée : ${hist.domain}`);
  };

  const handleCommitLabFinding = (finding: Finding) => {
    setFindings((prev) => {
      const exists = prev.some((f) => f.id === finding.id || f.signature === finding.signature);
      if (exists) return prev;
      return [finding, ...prev];
    });
    setEngineStatus(`Preuve enregistrée : ${finding.title}`);
  };

  return (
    <div className="h-screen w-screen flex flex-col bg-[#0a0e18] text-[#dfe2f1] overflow-hidden select-none font-sans">
      {/* Persistent Desktop Header */}
      <Header
        targetConfig={targetConfig}
        setTargetConfig={setTargetConfig}
        onLaunchAnalysis={handleLaunchAnalysis}
        onLaunchAttack={handleLaunchAttack}
        isAnalyzing={isAnalyzing}
        isTesting={isTesting}
        onOpenSettings={() => setIsSettingsModalOpen(true)}
        onOpenPackaging={() => setIsPackagingModalOpen(true)}
      />

      {/* Main Workspace Frame */}
      <div className="flex-1 flex overflow-hidden pt-20 pb-6">
        {/* Module Navigation Sidebar */}
        <Sidebar
          currentView={currentView}
          onSelectView={setCurrentView}
          onOpenSettings={() => setIsSettingsModalOpen(true)}
          onOpenDocs={() => setIsDocsModalOpen(true)}
          onOpenPackaging={() => setIsPackagingModalOpen(true)}
          findingsCount={findings.length}
        />

        {/* Viewport Canvas (Adjusted for fixed 64px width sidebar) */}
        <main className="flex-1 ml-64 overflow-hidden flex flex-col bg-[#0a0e18]">
          {currentView === 'scanner-and-recon' && (
            <ScannerReconView
              targetConfig={targetConfig}
              setTargetConfig={setTargetConfig}
              onLaunchAnalysis={handleLaunchAnalysis}
              onLaunchAttack={handleLaunchAttack}
              onGoToLab={() => setCurrentView('laboratoire-attaques')}
              isAnalyzing={isAnalyzing}
              isTesting={isTesting}
              historicalTargets={historicalTargets}
              onSelectHistoricalTarget={handleSelectHistoricalTarget}
            />
          )}

          {currentView === 'analyse-web' && (
            <AnalyseWebView
              endpointsTree={endpointsTree}
              findings={findings}
              onTransferToAttack={() => {
                setCurrentView('tests-actifs-and-attaque');
                handleStartAttackConfirmed();
              }}
              onRescan={handleLaunchAnalysis}
              targetUrl={targetConfig.url}
            />
          )}

          {currentView === 'tests-actifs-and-attaque' && (
            <ActiveTestsView
              testFamilies={testFamilies}
              terminalLogs={terminalLogs}
              endpointsTree={endpointsTree}
              findings={findings}
              isTesting={isTesting}
              onStopTest={handleStopTest}
              onStartTest={handleStartAttackConfirmed}
              onGoToResults={() => setCurrentView('resultats-and-preuves')}
              onGoToLab={() => setCurrentView('laboratoire-attaques')}
              safeMode={safeMode}
              setSafeMode={setSafeMode}
            />
          )}

          {currentView === 'laboratoire-attaques' && (
            <SecurityLabView
              onCommitFindingToApp={handleCommitLabFinding}
              onGoToReport={() => setCurrentView('rapport-and-remediation')}
              onGoToResults={() => setCurrentView('resultats-and-preuves')}
            />
          )}

          {currentView === 'resultats-and-preuves' && (
            <ResultsEvidenceView
              findings={findings}
              onGoToReport={() => setCurrentView('rapport-and-remediation')}
            />
          )}

          {currentView === 'rapport-and-remediation' && (
            <ReportRemediationView targetConfig={targetConfig} findings={findings} />
          )}

          {currentView === 'wifi-and-reseau' && (
            <WifiReseauView
              onGoToLab={() => setCurrentView('laboratoire-wifi')}
              onGoToCours={() => setCurrentView('cours-and-notions')}
            />
          )}

          {currentView === 'cours-and-notions' && (
            <CoursNotionsView
              onGoToLab={() => setCurrentView('laboratoire-wifi')}
              onGoToWifi={() => setCurrentView('wifi-and-reseau')}
            />
          )}

          {currentView === 'laboratoire-wifi' && (
            <LaboratoireWifiView
              onCommitFindingToApp={handleCommitLabFinding}
              onGoToResults={() => setCurrentView('resultats-and-preuves')}
              onGoToCours={() => setCurrentView('cours-and-notions')}
            />
          )}

          {currentView === 'terminal-integre' && (
            <TerminalView />
          )}

          {currentView === 'dashboard' && (
            <DashboardView
              targetConfig={targetConfig}
              findings={findings}
              onSelectView={setCurrentView}
            />
          )}

          {currentView === 'reseau-local' && (
            <ReseauLocalView />
          )}

          {currentView === 'arsenal' && (
            <ArsenalView />
          )}

          {currentView === 'geomac' && (
            <GeoMacView />
          )}

          {currentView === 'core-manager' && (
            <CoreManagerView />
          )}

          {currentView === 'hid-attacks' && (
            <HidAttacksView />
          )}

          {currentView === 'usb-arsenal' && (
            <UsbArsenalView />
          )}

          {currentView === 'cameradar' && (
            <CameradarView />
          )}
        </main>
      </div>

      {/* Persistent Desktop Status Footer */}
      <Footer
        targetConfig={targetConfig}
        safeMode={safeMode}
        setSafeMode={setSafeMode}
        engineStatus={engineStatus}
        findingsCount={findings.length}
      />

      {/* Active Attack Authorization Modal */}
      <ActiveTestAuthModal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
        onConfirm={handleStartAttackConfirmed}
        targetConfig={targetConfig}
      />

      {/* Engine Settings Modal */}
      <SettingsModal
        isOpen={isSettingsModalOpen}
        onClose={() => setIsSettingsModalOpen(false)}
        operatorId={targetConfig.operatorId}
        setOperatorId={(id) => setTargetConfig((p) => ({ ...p, operatorId: id }))}
      />

      {/* Specifications & Doctrine Docs Modal */}
      <DocsModal
        isOpen={isDocsModalOpen}
        onClose={() => setIsDocsModalOpen(false)}
      />

      {/* Desktop Packaging & .EXE Installer Modal */}
      <DesktopPackagingModal
        isOpen={isPackagingModalOpen}
        onClose={() => setIsPackagingModalOpen(false)}
      />
    </div>
  );
}
