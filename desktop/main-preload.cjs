// Guyma Cyb — Preload de la fenêtre principale
// ---------------------------------------------
// Expose une surface IPC minimale et sécurisée (contextBridge) pour les
// contrôles de fenêtre natifs utilisés par le Header de l'application React :
//   window.guymacybWindow.minimize() / maximize() / close() / isFullscreen()
// ainsi que l'ouverture à la demande de l'assistant de configuration (WSL +
// outils Linux) depuis la vue « Core Manager » :
//   window.guymacybWindow.openSetupWizard()
// Aucun accès Node n'est exposé au renderer (contextIsolation: true, sandbox: true).
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('guymacybWindow', {
  minimize: () => ipcRenderer.invoke('window:minimize'),
  maximize: () => ipcRenderer.invoke('window:maximize'),
  close: () => ipcRenderer.invoke('window:close'),
  /** Retourne true si la fenêtre est en plein écran. */
  isFullscreen: () => ipcRenderer.invoke('window:is-fullscreen'),
  /**
   * Ouvre l'assistant de configuration à la demande (fenêtre du wizard).
   * Utilisé par la vue « Core Manager » pour installer WSL + les outils
   * Linux sans avoir à relancer l'application. L'app continue de tourner :
   * le wizard se contente de configurer, puis se ferme.
   */
  openSetupWizard: () => ipcRenderer.invoke('setup:open-wizard'),
});
