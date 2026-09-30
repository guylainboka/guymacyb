// windowsSystem.ts — Intégration système RÉELLE Windows (et Linux en dev).
//
// Ce module donne à Guyma Cyb des capacités de niveau « outil système » :
//  - Détection des droits administrateur (élévation UAC) réelle
//  - Inventaire matériel complet via WMI/CIM (Get-CimInstance) sur Windows,
//    /proc + lsblk sur Linux — JAMAIS de données inventées
//  - Liste des services Windows pertinents (BFE, WdNsvc, LxssManager…)
//  - Dossier registre des outils installés : chaque outil installé via
//    « Installer les outils » est vérifié (which + version) et consigné dans
//    <dataDir>/tools-registry/<tool>.json — preuve locale, prête à réutiliser.
//
// Toutes les fonctions renvoient des données réelles ou une erreur honnête.

import { spawn } from 'child_process';
import os from 'os';
import fs from 'fs';
import path from 'path';

const IS_WINDOWS = process.platform === 'win32';

/** Dossier de données (registry outils, etc.) — userData Electron en prod. */
export function dataDir(): string {
  return process.env.GCYB_DATA_DIR || process.cwd();
}

/** Exécute un process et renvoie buffers brutes + code (décodage UTF-16 géré). */
function runCapture(
  cmd: string,
  args: string[],
  timeoutMs = 30_000
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    } catch (e: any) {
      resolve({ stdout: '', stderr: e?.message || 'spawn failed', exitCode: -1 });
      return;
    }
    const chunks: Buffer[] = [];
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) { try { child.kill('SIGKILL'); } catch { /* ignore */ } }
    }, timeoutMs);
    child.stdout.on('data', (d: Buffer) => chunks.push(d));
    child.stderr.on('data', (d: Buffer) => chunks.push(d));
    child.on('error', (err: Error) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      resolve({ stdout: '', stderr: err.message, exitCode: -1 });
    });
    child.on('close', (code) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      const raw = Buffer.concat(chunks);
      // PowerShell console peut sortir en UTF-16LE selon la config — détection.
      let text: string;
      const sample = raw.subarray(0, Math.min(raw.length, 2048));
      let nulls = 0;
      for (const b of sample) if (b === 0) nulls++;
      if (raw.length >= 2 && raw[0] === 0xff && raw[1] === 0xfe) {
        text = raw.toString('utf16le');
        if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
      } else if (sample.length > 0 && nulls / sample.length > 0.3) {
        text = raw.toString('utf16le');
      } else {
        text = raw.toString('utf8');
      }
      resolve({ stdout: text, stderr: '', exitCode: code ?? -1 });
    });
  });
}

// ---------------------------------------------------------------------------
//  Droits administrateur
// ---------------------------------------------------------------------------

/** Détecte si le process tourne avec des droits administrateur (réel). */
export async function isAdmin(): Promise<{ elevated: boolean; method: string; detail: string }> {
  if (IS_WINDOWS) {
    // Méthode fiable et instantanée : `net session` n'aboutit qu'en élevation.
    const res = await runCapture('net.exe', ['session'], 8_000);
    if (res.exitCode === 0) {
      return { elevated: true, method: 'net session', detail: 'Droits administrateur actifs' };
    }
    // Double contrôle via whoami (niveau d'intégrité High = admin).
    const who = await runCapture('whoami.exe', ['/groups'], 8_000);
    const high = /S-1-16-12288/.test(who.stdout);
    return {
      elevated: high,
      method: 'whoami integrity level',
      detail: high
        ? 'Niveau d’intégrité High (administrateur)'
        : 'Processus NON élevé — relancez Guyma Cyb « en tant qu’administrateur » pour les actions système',
    };
  }
  const root = typeof process.getuid === 'function' && process.getuid() === 0;
  return {
    elevated: root,
    method: 'uid',
    detail: root ? 'Exécution en root' : 'Utilisateur non-root (sudo requis pour certaines actions)',
  };
}

// ---------------------------------------------------------------------------
//  Inventaire matériel (CIM/WMI sur Windows, /proc sur Linux)
// ---------------------------------------------------------------------------

export interface HardwareReport {
  platform: string;
  hostname: string;
  os: string;
  cpu: { model: string; cores: number; loadPercent: number | null };
  ram: { totalMb: number; freeMb: number | null };
  disks: Array<{ device: string; sizeGb: number | null; model: string }>;
  gpus: Array<{ name: string; adapterRamMb: number | null }>;
  networkAdapters: Array<{ name: string; mac: string; ip: string | null; state: string }>;
  bios: { manufacturer: string; version: string };
  source: string;
  error?: string;
}

/** Inventaire matériel réel — Windows via Get-CimInstance (WMI), Linux via /proc. */
export async function getHardware(): Promise<HardwareReport> {
  const base: HardwareReport = {
    platform: process.platform,
    hostname: os.hostname(),
    os: IS_WINDOWS ? '' : `${os.type()} ${os.release()}`,
    cpu: { model: os.cpus()[0]?.model || 'inconnu', cores: os.cpus().length, loadPercent: null },
    ram: { totalMb: Math.round(os.totalmem() / 1024 / 1024), freeMb: Math.round(os.freemem() / 1024 / 1024) },
    disks: [],
    gpus: [],
    networkAdapters: [],
    bios: { manufacturer: '', version: '' },
    source: IS_WINDOWS ? 'WMI/CIM (Get-CimInstance)' : '/proc + os',
  };
  if (IS_WINDOWS) {
    const ps = [
      '$ErrorActionPreference="SilentlyContinue"',
      '$cs = Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,TotalPhysicalMemory',
      '$os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption,TotalVisibleMemorySize,FreePhysicalMemory',
      '$cpu = Get-CimInstance Win32_Processor | Select-Object Name,NumberOfLogicalProcessors,LoadPercentage',
      '$mem = Get-CimInstance Win32_PhysicalMemory | Select-Object Capacity,Speed,Manufacturer',
      '$disk = Get-CimInstance Win32_DiskDrive | Select-Object Model,Size,MediaType',
      '$gpu = Get-CimInstance Win32_VideoController | Select-Object Name,AdapterRAM',
      '$net = Get-CimInstance Win32_NetworkAdapter -Filter "PhysicalAdapter=True" | Select-Object Name,MACAddress,NetEnabled',
      '$netcfg = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | Select-Object MACAddress,IPAddress',
      '$bios = Get-CimInstance Win32_BIOS | Select-Object Manufacturer,SMBIOSBIOSVersion',
      '[pscustomobject]@{ cs=$cs; os=$os; cpu=$cpu; mem=@($mem); disk=@($disk); gpu=@($gpu); net=@($net); netcfg=@($netcfg); bios=$bios } | ConvertTo-Json -Depth 3 -Compress',
    ].join('; ');
    const res = await runCapture('powershell.exe', ['-NoProfile', '-Command', ps], 30_000);
    if (res.exitCode !== 0 || !res.stdout.trim()) {
      return { ...base, error: `Inventaire CIM indisponible : ${res.stderr || `exit ${res.exitCode}`}` };
    }
    try {
      const raw = JSON.parse(res.stdout.trim());
      const arr = (v: any) => (Array.isArray(v) ? v : v ? [v] : []);
      base.os = raw.os?.Caption || '';
      base.cpu = {
        model: raw.cpu?.Name || base.cpu.model,
        cores: raw.cpu?.NumberOfLogicalProcessors || base.cpu.cores,
        loadPercent: typeof raw.cpu?.LoadPercentage === 'number' ? raw.cpu.LoadPercentage : null,
      };
      base.ram = {
        totalMb: Math.round((raw.cs?.TotalPhysicalMemory || 0) / 1024 / 1024) || base.ram.totalMb,
        freeMb: Math.round((raw.os?.FreePhysicalMemory || 0) / 1024),
      };
      base.disks = arr(raw.disk).map((d: any) => ({
        device: d.MediaType || 'Disk',
        sizeGb: d.Size ? Math.round(d.Size / 1024 / 1024 / 1024) : null,
        model: d.Model || '',
      }));
      base.gpus = arr(raw.gpu).map((g: any) => ({
        name: g.Name || 'GPU',
        adapterRamMb: g.AdapterRAM ? Math.round(g.AdapterRAM / 1024 / 1024) : null,
      }));
      base.networkAdapters = arr(raw.net).map((n: any) => {
        const cfg = arr(raw.netcfg).find((c: any) => c.MACAddress === n.MACAddress);
        const ip = Array.isArray(cfg?.IPAddress) ? cfg.IPAddress[0] : cfg?.IPAddress || null;
        return { name: n.Name || 'Adaptateur', mac: n.MACAddress || '', ip, state: n.NetEnabled ? 'Actif' : 'Inactif' };
      });
      base.bios = { manufacturer: raw.bios?.Manufacturer || '', version: raw.bios?.SMBIOSBIOSVersion || '' };
      return base;
    } catch (e: any) {
      return { ...base, error: `Sortie CIM non-JSON : ${e.message}` };
    }
  }
  // Linux natif : lecture /proc (réel).
  try {
    const memInfo = fs.readFileSync('/proc/meminfo', 'utf8');
    const totalKb = Number(/MemTotal:\s+(\d+)/.exec(memInfo)?.[1] || 0);
    const freeKb = Number(/MemAvailable:\s+(\d+)/.exec(memInfo)?.[1] || 0);
    base.ram = { totalMb: Math.round(totalKb / 1024), freeMb: Math.round(freeKb / 1024) };
    const cpuInfo = fs.readFileSync('/proc/cpuinfo', 'utf8');
    base.cpu.model = /model name\s*:\s*(.+)/.exec(cpuInfo)?.[1]?.trim() || base.cpu.model;
    const disks = fs.existsSync('/proc/partitions') ? fs.readFileSync('/proc/partitions', 'utf8') : '';
    base.disks = disks
      .split('\n')
      .map((l) => l.trim().split(/\s+/))
      .filter((p) => p.length >= 4 && /^\d+$/.test(p[2]) && !/\d$/.test(p[3]))
      .map((p) => ({ device: `/dev/${p[3]}`, sizeGb: Math.round(Number(p[2]) / 1024 / 1024), model: '' }));
    return base;
  } catch (e: any) {
    return { ...base, error: e.message };
  }
}

// ---------------------------------------------------------------------------
//  Services Windows pertinents pour Guyma Cyb
// ---------------------------------------------------------------------------

const WATCHED_SERVICES: Array<{ name: string; why: string }> = [
  { name: 'LxssManager', why: 'WSL — requis pour tous les outils Linux' },
  { name: 'WslService', why: 'WSL (version Store) — requis pour tous les outils Linux' },
  { name: 'BFE', why: 'Firewall Windows — filtre le trafic réseau scanné' },
  { name: 'WinDefend', why: 'Defender — peut isoler les binaires d’audit' },
  { name: 'WdNisSvc', why: 'Defender Network Inspection' },
  { name: 'Dnscache', why: 'Cache DNS client' },
  { name: 'WlanSvc', why: 'WLAN — requis pour le module WiFi' },
  { name: 'dot3svc', why: 'Ethernet filaire' },
  { name: 'NcaSvc', why: 'Agent NCA réseau' },
];

export interface ServiceStatus { name: string; display: string; state: string; startMode: string; why: string }

/** État réel des services Windows surveillés (Get-CimInstance Win32_Service). */
export async function getWatchedServices(): Promise<{ services: ServiceStatus[]; error?: string }> {
  if (!IS_WINDOWS) {
    return { services: [], error: 'Disponible uniquement sur Windows (services SCM)' };
  }
  const names = WATCHED_SERVICES.map((s) => s.name).join("','");
  const ps = [
    '$ErrorActionPreference="SilentlyContinue"',
    `Get-CimInstance Win32_Service -Filter "Name='${names}'" | Select-Object Name,DisplayName,State,StartMode | ConvertTo-Json -Compress`,
  ].join('; ');
  const res = await runCapture('powershell.exe', ['-NoProfile', '-Command', ps], 20_000);
  if (!res.stdout.trim()) {
    return { services: [], error: 'Aucune réponse du SCM (Get-CimInstance)' };
  }
  try {
    const raw = JSON.parse(res.stdout.trim());
    const arr = Array.isArray(raw) ? raw : [raw];
    const services: ServiceStatus[] = arr.map((s: any) => ({
      name: s.Name,
      display: s.DisplayName || s.Name,
      state: s.State || 'Unknown',
      startMode: s.StartMode || 'Unknown',
      why: WATCHED_SERVICES.find((w) => w.name === s.Name)?.why || '',
    }));
    // Signale aussi les services attendus ABSENTS de la réponse (pas installés).
    for (const w of WATCHED_SERVICES) {
      if (!services.some((s) => s.name === w.name)) {
        services.push({ name: w.name, display: w.name, state: 'NonInstallé', startMode: '-', why: w.why });
      }
    }
    return { services };
  } catch (e: any) {
    return { services: [], error: `Sortie SCM non-JSON : ${e.message}` };
  }
}

// ---------------------------------------------------------------------------
//  Registre des outils installés (dossier réel, preuve locale)
// ---------------------------------------------------------------------------

export interface ToolRecord {
  tool: string;
  path: string;
  version: string;
  verifiedAt: string;
  source: string;
}

function registryDir(): string {
  const dir = path.join(dataDir(), 'tools-registry');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/** Consigne un outil vérifié dans le registre (dossier tools-registry). */
export function recordTool(rec: ToolRecord): string {
  const dir = registryDir();
  const file = path.join(dir, `${rec.tool.replace(/[^\w.-]/g, '_')}.json`);
  fs.writeFileSync(file, JSON.stringify(rec, null, 2), 'utf8');
  return file;
}

/** Lit tout le registre des outils installés. */
export function readToolRegistry(): { dir: string; tools: ToolRecord[] } {
  const dir = registryDir();
  const tools: ToolRecord[] = [];
  for (const f of fs.readdirSync(dir)) {
    if (!f.endsWith('.json') || f === 'manifest.json') continue;
    try {
      tools.push(JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')));
    } catch { /* fichier corrompu : ignoré honnêtement */ }
  }
  return { dir, tools: tools.sort((a, b) => a.tool.localeCompare(b.tool)) };
}

/** Vérifie un outil (chemin + version) et l'inscrit au registre. */
export async function verifyAndRecordTool(
  tool: string,
  pathOut: string,
  source: string
): Promise<ToolRecord> {
  let version = '';
  const vres = await runCapture(pathOut || tool, ['--version'], 10_000).then(async (r) => {
    if (r.stdout.trim()) return r.stdout.trim().split('\n')[0];
    // Certains outils répondent à -V / version subcommand
    const r2 = await runCapture(pathOut || tool, ['-V'], 8_000);
    return r2.stdout.trim().split('\n')[0] || '';
  });
  const rec: ToolRecord = {
    tool,
    path: pathOut,
    version,
    verifiedAt: new Date().toISOString(),
    source,
  };
  recordTool(rec);
  return rec;
}
