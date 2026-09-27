// setup-preload.cjs — Preload du wizard de premier lancement.
// Expose les canaux IPC au renderer (wizard HTML) via contextBridge.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('guymacybSetup', {
  // Détection de l'état actuel (WSL, outils, Rust)
  detectAll: () => ipcRenderer.invoke('setup:detect-all'),

  // Installer WSL (Windows Subsystem for Linux) — requiert élévation UAC
  installWsl: () => ipcRenderer.invoke('setup:install-wsl'),

  // Installer les outils Linux manquants dans WSL (apt-get)
  installTools: () => ipcRenderer.invoke('setup:install-tools'),

  // Lancer l'application principale (marquer setup terminé + ouvrir fenêtre principale)
  launchApp: () => ipcRenderer.invoke('setup:launch-app'),

  // Sauter le wizard (l'utilisateur veut configurer plus tard)
  skipWizard: () => ipcRenderer.invoke('setup:skip'),

  // Recevoir les logs en streaming (progression install)
  onProgress: (callback) => {
    const handler = (_event, line) => callback(line);
    ipcRenderer.on('setup:progress', handler);
    return () => ipcRenderer.removeListener('setup:progress', handler);
  },
});
