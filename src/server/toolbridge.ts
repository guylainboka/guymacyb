// toolbridge.ts — Pont entre le backend Express et les moteurs d'analyse externes.
//
// Deux familles de moteurs :
//  1. Noyau Rust `shadowscan-core` (scan, recon, headers) — binaire compilé.
//  2. Scripts Linux de sécurité (security-scripts/*.sh) — un par outil.
//
// Toutes les fonctions renvoient du JSON déjà parsé (objet). En cas d'erreur,
// elles renvoient `{ error: string }` au lieu de throw — le caller peut renvoyer
// directement au client.

import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, '../..');
const CORE_BIN =
  process.env.SHADOWSCAN_CORE_PATH ||
  path.join(PROJECT_ROOT, 'shadowscan-core/target/release/shadowscan-core');
const SCRIPTS_DIR =
  process.env.SECURITY_SCRIPTS_DIR || path.join(PROJECT_ROOT, 'security-scripts');

/** Options communes pour exécuter un processus enfant. */
interface ExecOptions {
  /** Délai max en ms (défaut 60s). */
  timeoutMs?: number;
  /** Données à écrire sur stdin (string). */
  stdin?: string;
}

/** Exécute une commande et renvoie { stdout, stderr, exitCode }. */
async function exec(
  cmd: string,
  args: string[],
  opts: ExecOptions = {}
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const timeoutMs = opts.timeoutMs ?? 60_000;
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      cwd: PROJECT_ROOT,
      env: { ...process.env, LANG: 'C.UTF-8' },
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        try { child.kill('SIGKILL'); } catch {}
        resolve({ stdout, stderr: stderr + '\n[TIMEOUT]', exitCode: 124 });
      }
    }, timeoutMs);

    child.stdout.on('data', (d) => (stdout += d.toString()));
    child.stderr.on('data', (d) => (stderr += d.toString()));
    if (opts.stdin !== undefined) {
      child.stdin.write(opts.stdin);
    }
    child.stdin.end();

    child.on('error', (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve({ stdout, stderr: stderr + '\n' + err.message, exitCode: -1 });
      }
    });
    child.on('close', (code) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve({ stdout, stderr, exitCode: code ?? -1 });
      }
    });
  });
}

/** Exécute une commande et parse stdout comme JSON. Renvoie { error } si échec. */
async function execJson<T = any>(
  cmd: string,
  args: string[],
  opts: ExecOptions = {}
): Promise<T> {
  const res = await exec(cmd, args, opts);
  const raw = res.stdout.trim();
  if (!raw) {
    return {
      error: `Aucune sortie de ${cmd}. stderr: ${res.stderr.slice(-500)}`,
    } as any;
  }
  try {
    return JSON.parse(raw) as T;
  } catch {
    // L'outil a peut-être imprimé du texte avant le JSON ; tenter d'extraire
    // la dernière ligne qui ressemble à du JSON.
    const lines = raw.split('\n');
    for (let i = lines.length - 1; i >= 0; i--) {
      const line = lines[i].trim();
      if (line.startsWith('{') || line.startsWith('[')) {
        try {
          return JSON.parse(line) as T;
        } catch {}
      }
    }
    return {
      error: `Sortie non-JSON de ${cmd}: ${raw.slice(0, 500)}`,
    } as any;
  }
}

// ============================================================
//  Noyau Rust `shadowscan-core`
// ============================================================

export interface CoreScanResult {
  scanId: string;
  targetUrl: string;
  domain: string;
  statusCode: number;
  statusText: string;
  latencyMs: number;
  headers: Record<string, string>;
  tls: { protocol: string; isHttps: boolean; grade: string; details: string };
  technologies: string[];
  endpoints: any[];
  findings: any[];
  overallRisk: string;
  cvssScore: number;
  summary: {
    endpointsCount: number;
    apiRoutesCount: number;
    technologiesCount: number;
    anomaliesCount: number;
  };
  error?: string;
}

export async function coreScan(
  url: string,
  scope: 'strict' | 'wildcard',
  operatorId: string
): Promise<CoreScanResult> {
  if (!fs.existsSync(CORE_BIN)) {
    return {
      error: `Noyau Rust introuvable à ${CORE_BIN}. Compilez avec : cd shadowscan-core && cargo build --release`,
    } as any;
  }
  return execJson<CoreScanResult>(
    CORE_BIN,
    ['scan', '--url', url, '--scope', scope, '--operator', operatorId],
    { timeoutMs: 30_000 }
  );
}

export async function coreRecon(url: string): Promise<any> {
  if (!fs.existsSync(CORE_BIN)) {
    return { error: `Noyau Rust introuvable à ${CORE_BIN}.` };
  }
  return execJson(CORE_BIN, ['recon', '--url', url], { timeoutMs: 30_000 });
}

export async function coreHeaders(url: string): Promise<any> {
  if (!fs.existsSync(CORE_BIN)) {
    return { error: `Noyau Rust introuvable à ${CORE_BIN}.` };
  }
  return execJson(CORE_BIN, ['headers', '--url', url], { timeoutMs: 20_000 });
}

// ============================================================
//  Scripts Linux de sécurité (security-scripts/*.sh)
// ============================================================

function scriptPath(name: string): string {
  return path.join(SCRIPTS_DIR, name);
}

/** Wrapper générique : exécute un script .sh et renvoie son JSON. */
async function runScript(
  scriptName: string,
  args: string[] = [],
  timeoutMs = 60_000
): Promise<any> {
  const sp = scriptPath(scriptName);
  if (!fs.existsSync(sp)) {
    return { error: `Script introuvable: ${scriptName}`, tool: scriptName.replace('.sh', '') };
  }
  return execJson('bash', [sp, ...args], { timeoutMs });
}

export const toolNmap = (url: string, ports?: string) =>
  runScript('nmap-scan.sh', [url, ...(ports ? ['--ports', ports] : [])], 90_000);

export const toolNikto = (url: string) =>
  runScript('nikto-scan.sh', [url], 90_000);

export const toolWhatweb = (url: string) =>
  runScript('whatweb-scan.sh', [url], 30_000);

export const toolDirbrute = (url: string, wordlist?: string) =>
  runScript('dirbrute.sh', [url, ...(wordlist ? ['--wordlist', wordlist] : [])], 120_000);

export const toolDnsrecon = (url: string) =>
  runScript('dnsrecon.sh', [url], 30_000);

export const toolSslAudit = (url: string, port?: string) =>
  runScript('ssl-audit.sh', [url, ...(port ? ['--port', port] : [])], 40_000);

export const toolPing = (url: string, count?: string) =>
  runScript('ping-probe.sh', [url, ...(count ? ['--count', count] : [])], 40_000);

export const toolMtr = (url: string, count?: string) =>
  runScript('mtr-trace.sh', [url, ...(count ? ['--count', count] : [])], 60_000);

export const toolNetcat = (url: string, port?: string, data?: string) =>
  runScript(
    'netcat-probe.sh',
    [url, ...(port ? ['--port', port] : []), ...(data ? ['--data', data] : [])],
    15_000
  );

export const toolIperf3 = (
  server: string,
  opts: { port?: string; udp?: boolean; time?: string; reverse?: boolean }
) => {
  const args = [server];
  if (opts.port) args.push('--port', opts.port);
  if (opts.udp) args.push('--udp');
  if (opts.time) args.push('--time', opts.time);
  if (opts.reverse) args.push('--reverse');
  return runScript('iperf3-client.sh', args, 120_000);
};

// ============================================================
//  Installation / vérification des outils
// ============================================================

export async function checkInstalledTools(): Promise<{
  available: string[];
  missing: string[];
}> {
  const res = await exec('bash', [scriptPath('install-tools.sh'), '--check'], {
    timeoutMs: 15_000,
  });
  // Le script imprime des lignes colorées "[  OK  ] tool -> path" et "[ WARN ] tool".
  // On strip les codes ANSI avant de parser.
  const stripAnsi = (s: string) =>
    s.replace(/\x1b\[[0-9;]*m/g, '');
  const output = stripAnsi(res.stdout + res.stderr);
  const available: string[] = [];
  const missing: string[] = [];
  for (const line of output.split('\n')) {
    const mOk = line.match(/\[\s*OK\s*\]\s+(\S+)/);
    const mWarn = line.match(/\[\s*WARN\s*\]\s+(\S+)/);
    if (mOk) available.push(mOk[1]);
    if (mWarn) missing.push(mWarn[1]);
  }
  return { available, missing };
}
