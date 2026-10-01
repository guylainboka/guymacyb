// setup-preload.cjs — Preload du Desktop Installer V2 (design maquettes).
// Expose les canaux IPC au renderer (wizard HTML) via contextBridge.
// Surface minimale sans paramètre arbitraire (audit SEC-AUDIT-1 : sandbox OK,
// seuls contextBridge/ipcRenderer sont utilisés — fonctionne en sandbox:true).
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('guymacybSetup', {
  // ——— Détection réelle de l'état (WSL, distro, outils, Rust, node) ———
  detectAll: () => ipcRenderer.invoke('setup:detect-all'),

  // ——— Inventaire matériel réel (os.totalmem/freemem/cpus du process main) ———
  getSystem: () => ipcRenderer.invoke('setup:get-system'),

  // ——— État de la base SQLite (chemin, taille, droit d'écriture, compteurs
  //      réels si le moteur tourne — la sonde HTTP est faite par le MAIN) ———
  getDbStatus: () => ipcRenderer.invoke('setup:db-status'),

  // ——— Initialisation réelle de la base (répertoire + schéma via le moteur
  //      s'il tourne ; réponse honnête sinon) ———
  initDb: () => ipcRenderer.invoke('setup:init-db'),

  // ——— Persistance de la configuration : guymacyb-setup.json + génération
  //      réelle de %USERPROFILE%\.wslconfig (mémoire / mode réseau) ———
  saveConfig: (cfg) => ipcRenderer.invoke('setup:save-config', cfg),

  // ——— Lancement automatique au démarrage Windows (app.setLoginItemSettings) ———
  setAutoLaunch: (enabled) => ipcRenderer.invoke('setup:set-autolaunch', Boolean(enabled)),

  // ——— Installation WSL (élévation UAC) et des outils Linux (apt) ———
  installWsl: () => ipcRenderer.invoke('setup:install-wsl'),
  installTools: () => ipcRenderer.invoke('setup:install-tools'),

  // ——— Entrée dans l'application / report de la configuration ———
  launchApp: () => ipcRenderer.invoke('setup:launch-app'),
  skipWizard: () => ipcRenderer.invoke('setup:skip'),

  // ——— Streaming des logs d'installation (progression apt/wsl) ———
  onProgress: (callback) => {
    const handler = (_event, line) => callback(line);
    ipcRenderer.on('setup:progress', handler);
    return () => ipcRenderer.removeListener('setup:progress', handler);
  },

  // ——— Contrôles de fenêtre (wizard frameless — barre de titre custom) ———
  minimizeWindow: () => ipcRenderer.invoke('setup-window:minimize'),
  maximizeWindow: () => ipcRenderer.invoke('setup-window:maximize'),
  closeWindow: () => ipcRenderer.invoke('setup-window:close'),
});
