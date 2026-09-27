import React, { useState } from 'react';

interface DesktopPackagingModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const DesktopPackagingModal: React.FC<DesktopPackagingModalProps> = ({ isOpen, onClose }) => {
  const [activeTab, setActiveTab] = useState<'download' | 'specs' | 'scripts'>('download');
  const [isDownloading, setIsDownloading] = useState<boolean>(false);

  if (!isOpen) return null;

  const handleDownloadExe = () => {
    setIsDownloading(true);
    // Trigger direct download
    const link = document.createElement('a');
    link.href = '/api/desktop/download-installer';
    link.download = 'GuymaCyb-Setup-v1.0.0.exe';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    setTimeout(() => {
      setIsDownloading(false);
    }, 2000);
  };

  const handleDownloadPortable = () => {
    const link = document.createElement('a');
    link.href = '/api/desktop/download-portable';
    link.download = 'GuymaCyb-Portable-v1.0.0.zip';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-in fade-in duration-200 font-sans">
      <div className="bg-[#101524] border border-[#24314c] rounded-xl max-w-3xl w-full shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="bg-[#0a0e18] px-6 py-4 border-b border-[#24314c] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-[#3b82f6] to-[#1d4ed8] flex items-center justify-center shadow-lg shadow-blue-500/20">
              <span className="material-symbols-outlined text-white text-[20px]">desktop_windows</span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="font-mono text-sm font-bold text-[#dfe2f1] uppercase tracking-wider">
                  GUYMA CYB — PACKAGING INSTALLABLE (FICHIER .EXE)
                </h2>
                <span className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/30 text-[10px] font-mono font-bold">
                  v1.0.0 STABLE
                </span>
              </div>
              <p className="text-[11px] text-[#8c909f] mt-0.5">
                Distribution binaire autonome pour environnement Windows x64 (NSIS / Electron)
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-[#8c909f] hover:text-white p-1 rounded hover:bg-[#1b243b] transition-colors"
            type="button"
          >
            <span className="material-symbols-outlined text-[20px]">close</span>
          </button>
        </div>

        {/* Navigation Tabs */}
        <div className="flex items-center gap-2 px-6 pt-3 bg-[#0c101c] border-b border-[#1f2a40] text-xs font-mono">
          <button
            onClick={() => setActiveTab('download')}
            className={`pb-2.5 px-3 border-b-2 font-medium transition-colors flex items-center gap-1.5 ${
              activeTab === 'download'
                ? 'border-[#3b82f6] text-[#4cd7f6]'
                : 'border-transparent text-[#8c909f] hover:text-[#dfe2f1]'
            }`}
          >
            <span className="material-symbols-outlined text-[15px]">download</span>
            Téléchargement (.exe & Portable)
          </button>
          <button
            onClick={() => setActiveTab('specs')}
            className={`pb-2.5 px-3 border-b-2 font-medium transition-colors flex items-center gap-1.5 ${
              activeTab === 'specs'
                ? 'border-[#3b82f6] text-[#4cd7f6]'
                : 'border-transparent text-[#8c909f] hover:text-[#dfe2f1]'
            }`}
          >
            <span className="material-symbols-outlined text-[15px]">settings_system_daydream</span>
            Architecture & Spécifications
          </button>
          <button
            onClick={() => setActiveTab('scripts')}
            className={`pb-2.5 px-3 border-b-2 font-medium transition-colors flex items-center gap-1.5 ${
              activeTab === 'scripts'
                ? 'border-[#3b82f6] text-[#4cd7f6]'
                : 'border-transparent text-[#8c909f] hover:text-[#dfe2f1]'
            }`}
          >
            <span className="material-symbols-outlined text-[15px]">code</span>
            Scripts Electron & NSIS
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto flex-1 space-y-5 text-xs text-[#c2c6d6]">
          {activeTab === 'download' && (
            <div className="space-y-5">
              {/* Primary Download Card */}
              <div className="p-5 rounded-xl bg-gradient-to-br from-[#17233d] to-[#0d1627] border border-[#2b4169] shadow-xl relative overflow-hidden">
                <div className="absolute top-0 right-0 p-4 opacity-10">
                  <span className="material-symbols-outlined text-[140px] text-blue-400">shield</span>
                </div>

                <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 text-[10px] font-mono font-bold border border-emerald-500/30">
                        RECOMMANDÉ POUR WINDOWS
                      </span>
                      <span className="text-[#8c909f] font-mono text-[11px]">x86_64 / x64</span>
                    </div>
                    <h3 className="text-base font-bold text-white font-mono">
                      GuymaCyb-Setup-v1.0.0.exe
                    </h3>
                    <p className="text-[#a0aec0] text-xs max-w-lg leading-relaxed">
                      Programme d'installation Windows autonome tout-en-un (NSIS). Inclut le moteur Guyma Cyb, la base de données SQLite locale, l'interface graphique native et l'environnement d'exécution sans pré-requis.
                    </p>
                    <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px] text-[#8c909f] font-mono">
                      <span className="flex items-center gap-1">
                        <span className="material-symbols-outlined text-[13px] text-[#4cd7f6]">verified</span>
                        Signé Guyma Cyb Security
                      </span>
                      <span>•</span>
                      <span>Taille : ~84 Mo</span>
                      <span>•</span>
                      <span>Windows 10 / 11 / Server</span>
                    </div>
                  </div>

                  <div className="shrink-0 flex flex-col items-stretch gap-2 min-w-[200px]">
                    <button
                      onClick={handleDownloadExe}
                      disabled={isDownloading}
                      className="px-5 py-3 rounded-lg bg-gradient-to-r from-[#2563eb] to-[#1d4ed8] hover:from-[#3b82f6] hover:to-[#2563eb] text-white font-mono font-bold text-xs shadow-lg shadow-blue-600/30 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                    >
                      <span className="material-symbols-outlined text-[18px]">
                        {isDownloading ? 'sync' : 'download'}
                      </span>
                      {isDownloading ? 'Téléchargement...' : 'Télécharger (.exe)'}
                    </button>
                    <span className="text-[10px] text-center text-[#8c909f] font-mono">
                      Installation en 1 clic
                    </span>
                  </div>
                </div>
              </div>

              {/* Alternative Download Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Portable ZIP */}
                <div className="p-4 rounded-lg bg-[#0e1424] border border-[#1f2c47] flex flex-col justify-between">
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-white text-xs flex items-center gap-1.5">
                        <span className="material-symbols-outlined text-[#f59e0b] text-[16px]">folder_zip</span>
                        Guyma Cyb Portable (.zip)
                      </span>
                      <span className="text-[10px] font-mono text-[#8c909f]">Sans installation</span>
                    </div>
                    <p className="text-[11px] text-[#8c909f] leading-normal">
                      Archive portable prête à lancer depuis une clé USB ou un disque externe sans modifier la base de registre Windows.
                    </p>
                  </div>
                  <button
                    onClick={handleDownloadPortable}
                    className="mt-4 px-3 py-2 rounded bg-[#172033] hover:bg-[#202b44] text-[#c2c6d6] hover:text-white border border-[#2b3a5a] text-xs font-mono font-medium transition-colors flex items-center justify-center gap-1.5"
                  >
                    <span className="material-symbols-outlined text-[14px]">file_download</span>
                    Télécharger Portable (.zip)
                  </button>
                </div>

                {/* SQLite Core DB Export */}
                <div className="p-4 rounded-lg bg-[#0e1424] border border-[#1f2c47] flex flex-col justify-between">
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-white text-xs flex items-center gap-1.5">
                        <span className="material-symbols-outlined text-[#10b981] text-[16px]">database</span>
                        Base SQLite (shadow_core.db)
                      </span>
                      <span className="text-[10px] font-mono text-emerald-400">Persistance locale</span>
                    </div>
                    <p className="text-[11px] text-[#8c909f] leading-normal">
                      Export direct du fichier binaire SQLite contenant tous vos scans, cibles d'audit et résultats de vulnérabilité.
                    </p>
                  </div>
                  <a
                    href="/api/database/export"
                    download="shadow_core.db"
                    className="mt-4 px-3 py-2 rounded bg-[#172033] hover:bg-[#202b44] text-[#c2c6d6] hover:text-white border border-[#2b3a5a] text-xs font-mono font-medium transition-colors flex items-center justify-center gap-1.5"
                  >
                    <span className="material-symbols-outlined text-[14px]">database</span>
                    Exporter shadow_core.db
                  </a>
                </div>
              </div>

              {/* Instructions post installation */}
              <div className="p-3.5 rounded-lg bg-[#0c101c] border border-[#1b253b] text-[11px] space-y-1 font-mono text-[#8c909f]">
                <div className="text-[#dfe2f1] font-semibold flex items-center gap-1.5">
                  <span className="material-symbols-outlined text-[14px] text-[#3b82f6]">info</span>
                  Guide de démarrage rapide sur Windows :
                </div>
                <ol className="list-decimal list-inside space-y-0.5 text-[#a0aec0] pl-1">
                  <li>Téléchargez <strong className="text-white">GuymaCyb-Setup-v1.0.0.exe</strong> en cliquant sur le bouton principal.</li>
                  <li>Double-cliquez sur le fichier pour lancer l'assistant d'installation NSIS.</li>
                  <li>Une icône de raccourci <strong className="text-white">Guyma Cyb</strong> sera créée sur votre Bureau.</li>
                  <li>Le logiciel démarre instantanément avec SQLite embarqué, sans dépendance externe.</li>
                </ol>
              </div>
            </div>
          )}

          {activeTab === 'specs' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="p-3 rounded-lg bg-[#0e1424] border border-[#1f2c47]">
                  <span className="text-[#8c909f] text-[10px] uppercase font-mono block">Moteur d'Exécution</span>
                  <span className="text-white font-mono font-bold text-xs mt-1 block">Electron v30 + Node.js LTS</span>
                  <span className="text-[10px] text-[#8c909f] mt-1 block">Rendu matériel GPU natif Chromium</span>
                </div>
                <div className="p-3 rounded-lg bg-[#0e1424] border border-[#1f2c47]">
                  <span className="text-[#8c909f] text-[10px] uppercase font-mono block">Base de Données Locale</span>
                  <span className="text-emerald-400 font-mono font-bold text-xs mt-1 block">SQLite Embedded (sql.js)</span>
                  <span className="text-[10px] text-[#8c909f] mt-1 block">shadow_core.db sur disque local</span>
                </div>
                <div className="p-3 rounded-lg bg-[#0e1424] border border-[#1f2c47]">
                  <span className="text-[#8c909f] text-[10px] uppercase font-mono block">Type d'Exécutable</span>
                  <span className="text-[#4cd7f6] font-mono font-bold text-xs mt-1 block">Win32 PE64 Portable</span>
                  <span className="text-[10px] text-[#8c909f] mt-1 block">NSIS Modern Installer Package</span>
                </div>
              </div>

              <div className="p-4 rounded-lg bg-[#0a0e18] border border-[#1b253b] space-y-3 font-mono text-xs">
                <h4 className="text-white font-bold flex items-center gap-2">
                  <span className="material-symbols-outlined text-[16px] text-blue-400">security</span>
                  Doctrines d'Exécution et Sécurité de Guyma Cyb Desktop :
                </h4>
                <div className="space-y-2 text-[#8c909f] text-[11px] leading-relaxed">
                  <div className="flex items-start gap-2">
                    <span className="text-emerald-400">✓</span>
                    <span><strong className="text-white">Zéro dépendance réseau externe :</strong> L'application fonctionne 100% hors-ligne pour la persistance et l'analyse, seule la cible auditée est interrogée.</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-emerald-400">✓</span>
                    <span><strong className="text-white">Stockage persistant SQLite :</strong> Tous les audits, résultats et simulations du Cyber Range sont archivés dans le fichier local <code className="text-[#4cd7f6]">shadow_core.db</code>.</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-emerald-400">✓</span>
                    <span><strong className="text-white">Isolation des processus :</strong> Le moteur d'analyse réseau opère dans un sous-processus isolé garantissant une haute stabilité.</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'scripts' && (
            <div className="space-y-4">
              <div>
                <span className="text-xs font-mono font-bold text-white block mb-1">
                  1. Script de compilation autonome Windows (desktop/build-windows-exe.bat)
                </span>
                <pre className="p-3 rounded-lg bg-[#0a0e18] border border-[#1b253b] text-[#4cd7f6] font-mono text-[11px] overflow-x-auto">
{`@echo off
echo [GUYMA CYB] Starting Desktop Packaging Pipeline...
call npm run build
npx electron-builder --win nsis --x64 --config.productName="Guyma Cyb"
echo [SUCCESS] Binary available at: dist_electron/GuymaCyb-Setup-v1.0.0.exe`}
                </pre>
              </div>

              <div>
                <span className="text-xs font-mono font-bold text-white block mb-1">
                  2. Lanceur Electron Principal (desktop/electron-main.cjs)
                </span>
                <pre className="p-3 rounded-lg bg-[#0a0e18] border border-[#1b253b] text-[#c2c6d6] font-mono text-[11px] overflow-x-auto">
{`const { app, BrowserWindow } = require('electron');
const path = require('path');

function createWindow() {
  const win = new BrowserWindow({
    width: 1360,
    height: 860,
    title: 'Guyma Cyb Desktop v1.0.0',
    backgroundColor: '#0a0e18'
  });
  win.loadURL('http://localhost:3000');
}
app.whenReady().then(createWindow);`}
                </pre>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="bg-[#0a0e18] px-6 py-3 border-t border-[#24314c] flex items-center justify-between font-mono text-xs">
          <div className="flex items-center gap-2 text-[#8c909f]">
            <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
            <span>Moteur : Guyma Cyb Core v1.0.0</span>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 rounded bg-[#1f293d] hover:bg-[#2c3a54] text-white font-medium transition-colors"
          >
            Fermer
          </button>
        </div>
      </div>
    </div>
  );
};
