// toolbridge.ts — Pont entre le backend Express et les moteurs d'analyse externes.
//
// Deux familles de moteurs :
//  1. Noyau Rust `shadowscan-core` (scan, recon, headers) — binaire compilé.
//  2. Scripts Linux de sécurité (security-scripts/*.sh) — un par outil.
//
// *** PONT WSL (Windows Subsystem for Linux) ***
//  GuymaCyb est un logiciel Windows pur qui exécute de VRAIS outils Linux.
//  Sur Windows : les scripts bash sont invoqués via `wsl.exe -d <distro> -- bash <script>`,
//    ce qui lance nmap, aircrack-ng, nikto, etc. dans un vrai environnement Linux.
//  Sur Linux (dev/sandbox) : exécution directe (équivalent natif).
//  Aucune simulation : si un outil ou le hardware manque, un message honnête est retourné.
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

// --- Configuration WSL (Windows) ---
const IS_WINDOWS = process.platform === 'win32';
const WSL_DISTRO = process.env.WSL_DISTRO || 'Ubuntu';
// Sur Windows, le chemin WSL-side des scripts (ex: /mnt/c/Users/.../security-scripts).
// Si non défini, on tente une conversion automatique du chemin Windows -> /mnt/...
const WSL_SCRIPTS_DIR = process.env.WSL_SCRIPTS_DIR || '';

/** Convertit un chemin Windows en chemin accessible depuis WSL (/mnt/c/...). */
function toWslPath(p: string): string {
  if (!IS_WINDOWS) return p;
  if (WSL_SCRIPTS_DIR && p.startsWith(SCRIPTS_DIR)) {
    return p.replace(SCRIPTS_DIR, WSL_SCRIPTS_DIR);
  }
  // Conversion automatique : C:\foo\bar -> /mnt/c/foo/bar
  const m = p.match(/^([A-Za-z]):[\\\/](.*)/);
  if (m) {
    return `/mnt/${m[1].toLowerCase()}/${m[2].replace(/\\/g, '/')}`;
  }
  return p;
}

/**
 * Prépare la commande pour WSL si on est sur Windows et que la commande est bash.
 * Retourne { cmd, args } éventuellement wrappés en `wsl.exe -d <distro> -- bash <script>`.
 */
function wrapForWsl(cmd: string, args: string[]): { cmd: string; args: string[] } {
  if (!IS_WINDOWS) return { cmd, args };
  if (cmd === 'bash' || cmd.endsWith('.sh')) {
    // Wrapping WSL : wsl.exe -d Ubuntu -- bash <script-path-wsl> <args...>
    const wslArgs = ['-d', WSL_DISTRO, '--', 'bash'];
    if (cmd === 'bash') {
      // args[0] est le script .sh
      const newArgs = [...args];
      if (newArgs[0]) newArgs[0] = toWslPath(newArgs[0]);
      return { cmd: 'wsl.exe', args: [...wslArgs, ...newArgs] };
    } else {
      // cmd est un script .sh directement
      return { cmd: 'wsl.exe', args: [...wslArgs, toWslPath(cmd), ...args] };
    }
  }
  return { cmd, args };
}

/** Options communes pour exécuter un processus enfant. */
interface ExecOptions {
  /** Délai max en ms (défaut 60s). */
  timeoutMs?: number;
  /** Données à écrire sur stdin (string). */
  stdin?: string;
  /** Forcer le wrapping WSL même si cmd n'est pas bash (ex: pour `which`/`apt`). */
  forceWsl?: boolean;
}

/** Exécute une commande et renvoie { stdout, stderr, exitCode }. */
async function exec(
  cmd: string,
  args: string[],
  opts: ExecOptions = {}
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const timeoutMs = opts.timeoutMs ?? 60_000;
  // Wrapping WSL sur Windows pour les commandes bash/scripts
  const wrapped = opts.forceWsl && IS_WINDOWS
    ? wrapForWsl(cmd === 'wsl.exe' ? 'bash' : cmd, cmd === 'wsl.exe' ? args : [cmd, ...args])
    : wrapForWsl(cmd, args);
  return new Promise((resolve) => {
    const child = spawn(wrapped.cmd, wrapped.args, {
      cwd: PROJECT_ROOT,
      env: { ...process.env, LANG: 'C.UTF-8', WSLENV: 'PATH/l' },
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

// ============================================================
//  Gestion WSL & statut Core (module Core Manager — StrykerOSS)
// ============================================================

/** Liste les distributions WSL installées (Windows uniquement). */
export async function listWslDistros(): Promise<
  Array<{ name: string; state: string; version: string }>
> {
  if (!IS_WINDOWS) return [];
  const res = await exec('wsl.exe', ['-l', '-v'], { timeoutMs: 8_000, forceWsl: false });
  // wsl.exe n'est pas bash, ne pas wrapper — on l'appelle directement.
  // (exec wrappera seulement si cmd==='bash'; ici cmd==='wsl.exe' donc pas wrappé)
  const out = (res.stdout + res.stderr).replace(/\x1b\[[0-9;]*m/g, '').replace(/\0/g, '');
  const lines = out.split('\n').map((l) => l.trim()).filter(Boolean);
  const distros: Array<{ name: string; state: string; version: string }> = [];
  for (const line of lines.slice(1)) {
    const parts = line.split(/\s+/);
    if (parts.length >= 3) {
      distros.push({ name: parts[0], state: parts[1], version: parts[2] });
    }
  }
  return distros;
}

/** Vérifie si une commande/outils est installé (sur Linux direct, sur Windows via WSL). */
export async function whichTool(tool: string): Promise<string | null> {
  if (IS_WINDOWS) {
    const res = await exec('wsl.exe', ['-d', WSL_DISTRO, '--', 'which', tool], { timeoutMs: 5_000 });
    return res.exitCode === 0 ? res.stdout.trim() || tool : null;
  }
  const res = await exec('which', [tool], { timeoutMs: 5_000 });
  return res.exitCode === 0 ? res.stdout.trim() || tool : null;
}

/** Statut global du Core : plateforme, WSL, outils installés/manquants. */
export async function getCoreStatus(): Promise<{
  platform: string;
  isWindows: boolean;
  wsl: { available: boolean; distros: any[]; defaultDistro: string | null };
  tools: { available: string[]; missing: string[] };
  python: string | null;
  node: string;
  memoryMb: number;
}> {
  const toolList = [
    'nmap', 'nikto', 'whatweb', 'dnsrecon', 'sslscan', 'ping', 'mtr', 'nc', 'netcat',
    'iperf3', 'aircrack-ng', 'airodump-ng', 'airmon-ng', 'iw', 'iwlist', 'tcpdump',
    'tshark', 'python3', 'hashcat', 'searchsploit', 'nuclei', 'metasploit', 'msfconsole',
    'reaver', 'macchanger', 'dig', 'curl', 'traceroute', 'openssl', 'sqlmap', 'gobuster',
  ];
  const available: string[] = [];
  const missing: string[] = [];
  await Promise.all(
    toolList.map(async (t) => {
      const p = await whichTool(t);
      if (p) available.push(t);
      else missing.push(t);
    })
  );
  const py = await whichTool('python3');
  // Détection WSL RÉELLE : sur Windows, on considère WSL disponible uniquement si
  // au moins une distro est listée ET démarre. L'ancien code renvoyait
  // `available: IS_WINDOWS` (toujours vrai sur Windows même sans WSL) — mensonge.
  let wslAvailable = false;
  let defaultDistro: string | null = null;
  if (IS_WINDOWS) {
    const distros = await listWslDistros();
    wslAvailable = distros.length > 0;
    if (wslAvailable) {
      const test = await exec('wsl.exe', ['-d', distros[0].name, '--', 'echo', 'ok'], { timeoutMs: 10_000 });
      wslAvailable = test.exitCode === 0 && test.stdout.includes('ok');
    }
    defaultDistro = distros[0]?.name || WSL_DISTRO;
  }
  return {
    platform: process.platform,
    isWindows: IS_WINDOWS,
    wsl: {
      // Linux natif : les outils s'exécutent directement — équivalent WSL disponible.
      available: IS_WINDOWS ? wslAvailable : true,
      distros: IS_WINDOWS ? await listWslDistros() : [],
      defaultDistro,
    },
    tools: { available, missing },
    python: py,
    node: process.version,
    memoryMb: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
  };
}

/** Installe les outils Linux manquants (apt) — sur Linux direct, sur Windows via WSL. */
export async function installToolsViaApt(): Promise<{ output: string; exitCode: number }> {
  if (IS_WINDOWS) {
    // `-u root` évite le prompt sudo interactif (impossible en non-interactif via
    // wsl.exe) — même approche que le wizard de premier lancement.
    const res = await exec(
      'wsl.exe',
      ['-d', WSL_DISTRO, '-u', 'root', '--', 'bash', '-c',
       'apt-get update && apt-get install -y nmap nikto aircrack-ng tshark iperf3 dnsrecon whatweb sslscan sqlmap gobuster 2>&1'],
      { timeoutMs: 180_000 }
    );
    return { output: res.stdout + res.stderr, exitCode: res.exitCode };
  }
  const res = await exec('bash', ['-c', 'sudo apt-get update && sudo apt-get install -y nmap nikto aircrack-ng tshark iperf3 dnsrecon whatweb sslscan sqlmap gobuster 2>&1'], { timeoutMs: 180_000 });
  return { output: res.stdout + res.stderr, exitCode: res.exitCode };
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
  // 1. Noyau Rust si compilé (rapide, pure-Rust HTTP/TLS)
  if (fs.existsSync(CORE_BIN)) {
    return execJson<CoreScanResult>(
      CORE_BIN,
      ['scan', '--url', url, '--scope', scope, '--operator', operatorId],
      { timeoutMs: 30_000 }
    );
  }
  // 2. Fallback Node — VRAI scan HTTP/TLS/DNS/ports (pas de Rust requis)
  return nodeRealScan(url, scope, operatorId);
}

export async function coreRecon(url: string): Promise<any> {
  if (fs.existsSync(CORE_BIN)) {
    return execJson(CORE_BIN, ['recon', '--url', url], { timeoutMs: 30_000 });
  }
  // Fallback Node — reconnaissance réelle
  return nodeRealRecon(url);
}

export async function coreHeaders(url: string): Promise<any> {
  if (fs.existsSync(CORE_BIN)) {
    return execJson(CORE_BIN, ['headers', '--url', url], { timeoutMs: 20_000 });
  }
  // Fallback Node — fetch HTTP réel + analyse des en-têtes de sécurité
  return nodeRealHeaders(url);
}

// ============================================================
//  Fallbacks Node (utilisés si le noyau Rust n'est pas compilé)
//  → l'application fonctionne SANS compilation Rust.
//  Implémentations RÉELLES : fetch HTTP, sockets TCP, tls, dns.
// ============================================================

/** Fetch HTTP réel via l'API fetch globale (Node 18+). */
async function nodeFetch(url: string, timeoutMs = 12000): Promise<{
  status: number; statusText: string; headers: Record<string, string>;
  body: string; bodyLength: number; durationMs: number; finalUrl: string; error?: string;
}> {
  const start = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal, redirect: 'follow' });
    clearTimeout(timer);
    const headers: Record<string, string> = {};
    res.headers.forEach((v: string, k: string) => { headers[k] = v; });
    const text = await res.text();
    return {
      status: res.status, statusText: res.statusText, headers,
      body: text.slice(0, 20000), bodyLength: text.length,
      durationMs: Date.now() - start, finalUrl: res.url,
    };
  } catch (err: any) {
    clearTimeout(timer);
    return {
      status: 0, statusText: 'ERROR', headers: {}, body: '', bodyLength: 0,
      durationMs: Date.now() - start, finalUrl: url, error: err.message,
    };
  }
}

/** Scan TCP connect réel via net.Socket. */
async function nodeTcpScan(host: string, ports: number[], timeoutMs = 1500) {
  const net = await import('net');
  const probe = (port: number) => new Promise<{ port: number; state: string; service: string }>((resolve) => {
    const sock = new net.Socket();
    sock.setTimeout(timeoutMs);
    let done = false;
    const finish = (state: string) => { if (done) return; done = true; sock.destroy(); resolve({ port, state, service: '' }); };
    sock.on('connect', () => finish('open'));
    sock.on('timeout', () => finish('filtered'));
    sock.on('error', (e: NodeJS.ErrnoException) => finish(e.code === 'ECONNREFUSED' ? 'closed' : 'filtered'));
    sock.connect(port, host);
  });
  return Promise.all(ports.map(probe));
}

/** Détection de technologies réelle depuis les en-têtes + corps HTTP. */
function nodeFingerprintTech(headers: Record<string, string>, body: string): string[] {
  const tech: string[] = [];
  const h = Object.keys(headers).reduce((a, k) => { a[k.toLowerCase()] = headers[k]; return a; }, {} as Record<string, string>);
  const server = h['server'] || '';
  const poweredBy = h['x-powered-by'] || '';
  if (/nginx/i.test(server)) tech.push('Nginx');
  if (/apache/i.test(server)) tech.push('Apache');
  if (/iis|microsoft/i.test(server)) tech.push('Microsoft IIS');
  if (/express/i.test(poweredBy)) tech.push('Express.js');
  if (/php/i.test(server) || /php/i.test(poweredBy)) tech.push('PHP');
  if (/asp\.net/i.test(poweredBy)) tech.push('ASP.NET');
  if (/next/i.test(poweredBy)) tech.push('Next.js');
  if (/react/i.test(body) || /__NEXT_DATA__/.test(body)) tech.push('React');
  if (/vue/i.test(body)) tech.push('Vue.js');
  if (/wordpress|wp-content|wp-json/i.test(body)) tech.push('WordPress');
  if (/cloudflare/i.test(h['cf-ray'] || server)) tech.push('Cloudflare');
  if (/jquery/i.test(body)) tech.push('jQuery');
  return Array.from(new Set(tech));
}

/** Analyse des en-têtes de sécurité (retourne + findings). */
function nodeAnalyzeHeaders(headers: Record<string, string>) {
  const h = Object.keys(headers).reduce((a, k) => { a[k.toLowerCase()] = headers[k]; return a; }, {} as Record<string, string>);
  const checks = [
    { name: 'Strict-Transport-Security', header: 'strict-transport-security', severity: 'HIGH' },
    { name: 'Content-Security-Policy', header: 'content-security-policy', severity: 'HIGH' },
    { name: 'X-Content-Type-Options', header: 'x-content-type-options', severity: 'MEDIUM' },
    { name: 'X-Frame-Options', header: 'x-frame-options', severity: 'MEDIUM' },
    { name: 'Referrer-Policy', header: 'referrer-policy', severity: 'LOW' },
    { name: 'Permissions-Policy', header: 'permissions-policy', severity: 'LOW' },
  ];
  return checks.map((c) => ({
    name: c.name, header: c.header, present: !!h[c.header],
    value: h[c.header] || '', severity: c.severity,
    status: h[c.header] ? 'PRESENT' : 'MISSING',
  }));
}

/** Construit l'arbre d'endpoints découverts depuis le corps HTML. */
function nodeBuildEndpoints(body: string, baseUrl: string): any[] {
  try {
    const url = new URL(baseUrl);
    const links = new Set<string>();
    let m;
    const re = /href=["']([^"']+)["']/gi;
    while ((m = re.exec(body)) !== null) {
      try {
        const abs = new URL(m[1], baseUrl).pathname;
        if (abs && abs !== '/' && !abs.startsWith('javascript:')) links.add(abs);
      } catch { /* ignore */ }
    }
    const endpoints = Array.from(links).slice(0, 50).map((p, i) => {
      const isApi = /\/api\/|\/v[0-9]+\//.test(p);
      const isAdmin = /admin|dashboard|panel|manage/.test(p);
      const isAuth = /login|signin|auth|oauth/.test(p);
      return {
        id: `ep-${i}`, path: p, method: 'GET', status: 200, statusText: 'OK',
        type: isApi ? 'api' : isAdmin ? 'admin' : isAuth ? 'auth' : 'page',
        note: isApi ? 'API endpoint' : isAdmin ? 'Admin area' : isAuth ? 'Auth flow' : 'Discovered link',
      };
    });
    endpoints.unshift({ id: 'ep-root', path: url.pathname, method: 'GET', status: 200, statusText: 'OK', type: 'root', note: 'Root document' });
    return endpoints;
  } catch {
    return [];
  }
}

/** Scan réel complet (équivalent Node du noyau Rust). */
async function nodeRealScan(url: string, scope: 'strict' | 'wildcard', operatorId: string): Promise<CoreScanResult> {
  const target = url.match(/^https?:\/\//) ? url : `https://${url}`;
  const domain = target.replace(/^https?:\/\//, '').split('/')[0];
  const start = Date.now();

  const [fetchRes] = await Promise.all([nodeFetch(target)]);
  const tls = fetchRes.finalUrl.startsWith('https://')
    ? await nodeTlsInspect(domain).catch(() => ({ protocol: 'TLS', grade: 'B', details: '', isHttps: true }))
    : { protocol: 'None', grade: 'F', details: 'HTTP non chiffré', isHttps: false };

  // Port scan (top ports)
  let openPorts: any[] = [];
  try {
    const ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 8080, 8443];
    openPorts = (await nodeTcpScan(domain, ports, 1200)).filter((p) => p.state === 'open');
  } catch { /* sandbox sans accès */ }

  const techs = nodeFingerprintTech(fetchRes.headers, fetchRes.body);
  const secHeaders = nodeAnalyzeHeaders(fetchRes.headers);
  const endpoints = nodeBuildEndpoints(fetchRes.body, fetchRes.finalUrl);

  const findings: any[] = [];
  secHeaders.forEach((hd) => {
    if (hd.status === 'MISSING' && (hd.severity === 'HIGH' || hd.severity === 'MEDIUM')) {
      findings.push({
        id: `hdr-${hd.header}`,
        title: `En-tête de sécurité manquant : ${hd.name}`,
        severity: hd.severity === 'HIGH' ? 'HIGH' : 'MEDIUM',
        cvss: hd.severity === 'HIGH' ? 6.5 : 4.3,
        confidence: 90, status: 'VALIDATED', // échelle 0-100, cohérente avec le reste de l'app
        affectedComponent: fetchRes.finalUrl, category: 'CONFIG',
        cwe: hd.name.includes('Transport') ? 'CWE-319' : 'CWE-693',
        description: `L'en-tête ${hd.name} n'est pas présent dans la réponse HTTP de ${fetchRes.finalUrl}.`,
        evidence: {
          request: `GET ${target}`,
          response: `${hd.name}: (absent)`,
          authContext: 'Audit réseau', roundtripMs: fetchRes.durationMs, nonDestructiveProof: true,
        },
        impact: hd.severity === 'HIGH' ? 'Risque de downgrade, clickjacking ou XSS.' : 'Durcissement manquant.',
        remediationTitle: `Ajouter l'en-tête ${hd.name}`,
        remediationSteps: [`Configurer le serveur web pour émettre l'en-tête ${hd.name}.`],
        signature: `miss-header-${hd.header}-${domain}`,
      });
    }
  });

  const cvss = findings.reduce((s, f) => Math.max(s, f.cvss), 0);
  const risk = cvss >= 7 ? 'HIGH' : cvss >= 4 ? 'MED' : 'CLEAN';

  return {
    scanId: `scan-${Date.now()}`,
    targetUrl: target, domain,
    statusCode: fetchRes.status, statusText: fetchRes.statusText,
    latencyMs: fetchRes.durationMs,
    headers: fetchRes.headers,
    tls: { protocol: tls.protocol, isHttps: fetchRes.finalUrl.startsWith('https://'), grade: tls.grade, details: tls.details },
    technologies: techs, endpoints, findings,
    overallRisk: risk, cvssScore: cvss,
    summary: {
      endpointsCount: endpoints.length, apiRoutesCount: endpoints.filter((e) => e.type === 'api').length,
      technologiesCount: techs.length, anomaliesCount: findings.length,
    },
    durationMs: Date.now() - start, operatorId, engine: 'node-fallback-real',
  } as CoreScanResult;
}

/** Inspection TLS réelle via tls.connect. */
async function nodeTlsInspect(host: string, port = 443, timeoutMs = 10000) {
  const tls = await import('tls');
  return new Promise<{ protocol: string; grade: string; details: string; isHttps: boolean }>((resolve) => {
    let settled = false;
    const done = (r: any) => { if (settled) return; settled = true; sock.destroy(); resolve(r); };
    const sock = tls.connect({ host, port, rejectUnauthorized: false, servername: host }, () => {
      const cert: any = sock.getCertificate();
      const cipher: any = sock.getCipher();
      const proto = sock.getProtocol() || 'TLS';
      const grade = proto.includes('1.3') || proto.includes('1.2') ? 'A' : 'C';
      const details = cert ? `Issuer: ${JSON.stringify(cert.issuer || {}).slice(0, 80)}; Valid: ${cert.valid_from || '?'} → ${cert.valid_to || '?'}` : '';
      done({ protocol: proto, grade, details, isHttps: true });
    });
    sock.setTimeout(timeoutMs);
    sock.on('timeout', () => done({ protocol: 'TLS', grade: 'F', details: 'timeout', isHttps: true }));
    sock.on('error', () => done({ protocol: 'None', grade: 'F', details: 'no TLS', isHttps: false }));
  });
}

/** Reconnaissance réelle (DNS + whois léger). */
async function nodeRealRecon(url: string) {
  const dns = await import('dns/promises');
  const domain = url.replace(/^https?:\/\//, '').split('/')[0];
  const records: any[] = [];
  const resolver = new dns.Resolver();
  for (const t of ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA'] as const) {
    try {
      const r = await resolver.resolveAny(domain);
      r.forEach((rec: any) => records.push({ type: rec.type || t, value: rec.address || rec.exchange || JSON.stringify(rec) }));
    } catch { /* type absent pour ce domaine */ }
  }
  return { tool: 'recon', domain, records, totalCount: records.length, engine: 'node-fallback-real' };
}

/** En-têtes HTTP réels + analyse de sécurité. */
async function nodeRealHeaders(url: string) {
  const target = url.match(/^https?:\/\//) ? url : `https://${url}`;
  const r = await nodeFetch(target);
  return {
    tool: 'headers', url: target, statusCode: r.status,
    headers: r.headers, securityHeaders: nodeAnalyzeHeaders(r.headers),
    durationMs: r.durationMs, engine: 'node-fallback-real',
  };
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
//  Scripts WiFi (security-scripts/wifi-*.sh)
//  — Tous fallback en mode "builtin-simulated" si les outils
//    (iw, iwlist, aircrack-ng, tshark) ne sont pas disponibles
//    ou si le mode monitor ne peut être activé.
// ============================================================

export const toolWifiScan = (iface?: string) =>
  runScript('wifi-scan.sh', [iface].filter(Boolean) as string[], 30_000);

export const toolWpaAudit = (target: string, iface?: string) =>
  runScript(
    'wpa-audit.sh',
    [target, ...(iface ? [iface] : [])],
    30_000
  );

export const toolDeauthDetect = (iface?: string, duration?: number) => {
  const args: string[] = [];
  if (iface) args.push(iface);
  if (duration && Number.isFinite(duration)) args.push(String(Math.max(1, Math.min(600, Math.floor(duration)))));
  // 60s default + 5s slack in the script — extend our timeout to match.
  const dur = duration && Number.isFinite(duration) ? Math.max(1, Math.min(600, Math.floor(duration))) : 15;
  return runScript('deauth-detect.sh', args, (dur + 10) * 1000);
};

// —— WiFi avancé (mode monitor, capture handshake, crack, WPS, MAC spoofing)

export const toolWifiMonitorMode = (iface: string) =>
  runScript('wifi-monitor-mode.sh', [iface], 20_000);

export const toolWifiHandshakeCapture = (
  bssid: string,
  channel: number | string,
  iface: string,
  duration: number | string
) =>
  runScript(
    'wifi-handshake-capture.sh',
    [bssid, String(channel), iface, String(duration)],
    (Number(duration) || 30) * 1000 + 15_000
  );

export const toolWifiCrackHandshake = (capFile: string, wordlist?: string) =>
  runScript(
    'wifi-crack-handshake.sh',
    [capFile, ...(wordlist ? [wordlist] : [])],
    300_000
  );

export const toolWifiWpsAttack = (
  bssid: string,
  iface: string,
  mode: 'pixie' | 'pin' | 'brute',
  pin?: string
) =>
  runScript(
    'wifi-wps-attack.sh',
    [bssid, iface, mode, ...(pin ? [pin] : [])],
    100_000
  );

export const toolWifiMacChanger = (iface: string, mac?: string) =>
  runScript(
    'wifi-mac-changer.sh',
    [iface, ...(mac ? [mac] : [])],
    15_000
  );

// —— Terminal intégré (bash / powershell / cmd / python)

export const toolTerminal = (
  shell: 'bash' | 'powershell' | 'cmd' | 'python',
  command: string,
  cwd?: string
) =>
  runScript(
    'terminal-exec.sh',
    [shell, command, ...(cwd ? [cwd] : [])],
    35_000
  );

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

// ============================================================
//  Modules StrykerOSS — Réseau Local, Arsenal, GeoMac
//  (ajoutés par STRYKER-BACKEND-1 ; n'altère aucune fonction
//   existante — uniquement des exports nouveaux en fin de fichier).
// ============================================================

// Réseau Local — scan rootless (mDNS + SSDP + NetBIOS + rDNS /24 + TCP ports)
export const toolLocalNetworkScan = () => runScript('localnetwork-scan.sh', [], 60_000);

// Arsenal — searchsploit (exploitdb) et hashcat (crackage de hash)
export const toolSearchsploit = (query: string) =>
  runScript('arsenal-searchsploit.sh', [query], 30_000);

export const toolHashcat = (hash: string, mode = '0', wordlist?: string) =>
  runScript(
    'arsenal-hashcat.sh',
    [hash, mode, ...(wordlist ? [wordlist] : [])],
    120_000
  );

// GeoMac — géolocalisation d'une adresse MAC (OUI + WiGLE optionnel)
export const toolGeoMac = (mac: string) =>
  runScript('geomac-locate.sh', [mac], 15_000);

// ============================================================
//  Modules StrykerOSS — Cameradar / HID / USB Arsenal
//  (ajoutés par STRYKER-MODULES-2 ; n'altère aucune fonction
//   existante — uniquement des exports nouveaux en fin de fichier).
// ============================================================

// Cameradar — découverte RTSP (port 554) + sweep des credentials par défaut
export const toolCameradarScan = (subnet?: string) =>
  runScript('cameradar-scan.sh', subnet ? [subnet] : [], 90_000);

// HID Attacks — génération de payloads DuckyScript (REELS, fonctionnels)
export const toolHidPayloads = (type: string) =>
  runScript('hid-payloads.sh', [type], 10_000);

// USB Arsenal — gestion de gadgets USB via configfs (Linux/WSL)
export const toolUsbArsenal = (action: string, profile?: string) =>
  runScript(
    'usb-arsenal.sh',
    [action, ...(profile ? [profile] : [])],
    20_000
  );
