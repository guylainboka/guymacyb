// Guyma Cyb - Desktop Application Launcher (Electron Main Process)
// Package: Guyma Cyb v1.0.0
// Target: Windows x64 (.exe) / Linux / macOS

const { app, BrowserWindow, Menu, dialog, shell } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let mainWindow = null;
let serverProcess = null;

const SERVER_PORT = 3000;

function startBackendServer() {
  const isDev = process.env.NODE_ENV === 'development';
  if (!isDev) {
    // In production bundled .exe, start the internal Express server
    const serverScript = path.join(__dirname, 'server.js');
    serverProcess = spawn(process.execPath, [serverScript], {
      env: { ...process.env, PORT: String(SERVER_PORT) },
      stdio: 'ignore',
    });
  }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1360,
    height: 860,
    minWidth: 1024,
    minHeight: 700,
    title: 'Guyma Cyb Desktop v1.0.0',
    backgroundColor: '#0a0e18',
    frame: true,
    autoHideMenuBar: false,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
    },
  });

  const appUrl = `http://localhost:${SERVER_PORT}`;
  
  // Wait for server to boot then load URL
  setTimeout(() => {
    mainWindow.loadURL(appUrl).catch(() => {
      setTimeout(() => mainWindow.loadURL(appUrl), 1500);
    });
  }, 1000);

  // Open external links in user default browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('http:') || url.startsWith('https:')) {
      shell.openExternal(url);
    }
    return { action: 'deny' };
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  startBackendServer();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (serverProcess) {
    serverProcess.kill();
  }
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
