// Guyma Cyb — Preload de la fenêtre principale
// ---------------------------------------------
// Expose une surface IPC minimale et sécurisée (contextBridge) pour les
// contrôles de fenêtre natifs utilisés par le Header de l'application React :
//   window.guymacybWindow.minimize() / maximize() / close() / isFullscreen()
// Aucun accès Node n'est exposé au renderer (contextIsolation: true, sandbox: true).
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('guymacybWindow', {
  minimize: () => ipcRenderer.invoke('window:minimize'),
  maximize: () => ipcRenderer.invoke('window:maximize'),
  close: () => ipcRenderer.invoke('window:close'),
  /** Retourne true si la fenêtre est en plein écran. */
  isFullscreen: () => ipcRenderer.invoke('window:is-fullscreen'),
});
