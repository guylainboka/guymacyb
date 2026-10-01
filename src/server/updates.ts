// updates.ts — Centre de mises à jour RÉELLES pour Guyma Cyb (V2).
//
// Doctrine « zéro invention » — comme le reste du projet :
//  1. Mise à jour du LOGICIEL : interrogation de l'API GitHub Releases du dépôt
//     guylainboka/guymacyb (donnée publique réelle). Comparaison de version côté
//     serveur. Si l'API est injoignable (hors-ligne, rate-limit), on renvoie une
//     ERREUR honnête — jamais un état fabriqué.
//  2. Mise à jour des OUTILS Linux : `apt-get update` (rafraîchit réellement les
//     métadonnées des dépôts) puis `apt-cache policy <paquets>` — lecture réelle
//     des versions « Installed » / « Candidate ». Un paquet est « upgradable »
//     uniquement si Candidate diffère d'Installed et est numériquement supérieur.
//  3. Application (UNE seule action) : `apt-get install -y <paquets>` — met à
//     jour les paquets périmés ET installe les manquants en une seule commande.
//
// Aucune donnée simulée, aucun cache mensonger : les états d'erreur sont
// affichés tels quels à l'utilisateur.

import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { getWslState, runInDistro, IS_WINDOWS } from './wsl';

interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/** Exécution bash directe (Linux natif) — même sémantique que runInDistro. */
function execNative(cmd: string, timeoutMs: number): Promise<ExecResult> {
  return new Promise((resolve) => {
    const proc = spawn('bash', ['-c', cmd], { timeout: timeoutMs });
    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (d) => { stdout += d; });
    proc.stderr.on('data', (d) => { stderr += d; });
    proc.on('error', (e) => resolve({ stdout, stderr: stderr + e.message, exitCode: -1 }));
    proc.on('close', (code) => resolve({ stdout, stderr, exitCode: code ?? -1 }));
  });
}

/** Exécute une commande apt : dans le distro WSL (Windows) ou en natif (Linux). */
async function runApt(cmd: string, timeoutMs: number): Promise<ExecResult> {
  if (IS_WINDOWS) {
    return runInDistro(['bash', '-c', cmd], { user: 'root', timeoutMs });
  }
  // Linux natif : apt-get a besoin de root (comme installToolsViaApt qui utilise
  // sudo). sudo -n échoue IMMÉDIATEMENT et honnêtement si un mot de passe serait
  // requis (pas de prompt interactif possible via spawn sans TTY).
  const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  const finalCmd = isRoot ? cmd : cmd.replace(/^(DEBIAN_FRONTEND=\S+ )?/, '$1sudo -n ');
  return execNative(finalCmd, timeoutMs);
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, '../..');

const GITHUB_REPO = 'guylainboka/guymacyb';
const GITHUB_API = `https://api.github.com/repos/${GITHUB_REPO}/releases/latest`;
const HTTP_TIMEOUT_MS = 10_000;
/** apt-get update + apt-cache policy dans le distro — généreux (démarrage à froid). */
const APT_CHECK_TIMEOUT_MS = 120_000;
/** apt-get install des mises à jour — comme installToolsViaApt (10 min). */
const APT_APPLY_TIMEOUT_MS = 600_000;
/** Durée de validité du cache mémoire (évite de marteler apt-get update). */
const CACHE_TTL_MS = 5 * 60 * 1000;

// Liste de paquets alignée sur APT_PACKAGES (wizard) et PACKAGES
// (installToolsViaApt) — même référence unique pour éviter toute divergence.
export const APT_PACKAGES = [
  'nmap', 'nikto', 'whatweb', 'aircrack-ng', 'tshark', 'iperf3',
  'dnsrecon', 'sslscan', 'sqlmap', 'gobuster', 'hashcat', 'exploitdb',
  'reaver', 'macchanger', 'wireless-tools', 'iw',
] as const;

// ---------------------------------------------------------------------------
//  Types publics (contractuel avec le frontend)
// ---------------------------------------------------------------------------

export interface AppReleaseAsset {
  name: string;
  size: number;
  downloadUrl: string;
}

export interface AppUpdateInfo {
  current: string;
  latest: string | null;
  updateAvailable: boolean;
  releaseUrl: string | null;
  releaseName: string | null;
  publishedAt: string | null;
  notes: string | null;
  asset: AppReleaseAsset | null;
  checkedAt: string;
  /** Erreur honnête (hors-ligne, rate-limit GitHub…) — null si OK. */
  error: string | null;
}

export type ToolAction = 'none' | 'upgrade' | 'install';

export interface ToolPackageStatus {
  package: string;
  /** Version installée — null si le paquet est absent. */
  installed: string | null;
  /** Version candidate (dépôts apt) — null si inconnue. */
  candidate: string | null;
  action: ToolAction;
}

export interface ToolsUpdateInfo {
  platform: string;
  isWindows: boolean;
  /** Distribution WSL utilisée (null si aucune / Linux natif). */
  distro: string | null;
  packages: ToolPackageStatus[];
  upgradable: string[];
  missing: string[];
  checkedAt: string;
  /** Erreur honnête (pas de distro, apt indisponible…) — null si OK. */
  error: string | null;
}

export interface ApplyToolsResult {
  output: string;
  exitCode: number;
  /** Paquets réellement passés à apt-get install. */
  applied: string[];
  /** Message si rien à faire. */
  skipped?: string;
}

// ---------------------------------------------------------------------------
//  Version courante du logiciel
// ---------------------------------------------------------------------------

/**
 * Version du logiciel : env GCYB_VERSION (posée par electron-main en prod),
 * sinon package.json du projet (dev/sandbox). Jamais inventée : si aucune
 * source n'est disponible, « inconnue ».
 */
export function currentAppVersion(): string {
  if (process.env.GCYB_VERSION) return process.env.GCYB_VERSION;
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, 'package.json'), 'utf8'));
    if (typeof pkg?.version === 'string' && pkg.version) return pkg.version;
  } catch { /* package.json absent (bundle déplacé) — source suivante */ }
  return 'inconnue';
}

/**
 * Compare deux versions de type semble-semver / Debian (« 2.0.0 », « 7.94+dfsg-1 »).
 * Renvoie >0 si a>b, <0 si a<b, 0 si numériquement égales.
 * - Epoch Debian (« 1:7.94 ») ignoré pour la comparaison numérique principale.
 * - Segments numériques comparés ; à égalité numérique, comparaison lexicographique
 *   du suffixe (couvre les bumps de révision Debian : -1 → -2, +dfsg → +dfsg-1build1).
 */
export function compareVersions(a: string, b: string): number {
  const stripEpoch = (v: string) => v.replace(/^\d+:/, '');
  const na = stripEpoch(a).match(/\d+/g)?.map(Number) ?? [];
  const nb = stripEpoch(b).match(/\d+/g)?.map(Number) ?? [];
  const len = Math.max(na.length, nb.length);
  for (let i = 0; i < len; i++) {
    const x = na[i] ?? 0;
    const y = nb[i] ?? 0;
    if (x !== y) return x - y;
  }
  const sa = stripEpoch(a);
  const sb = stripEpoch(b);
  return sa === sb ? 0 : sa > sb ? 1 : -1;
}

// ---------------------------------------------------------------------------
//  1) Mise à jour du LOGICIEL — GitHub Releases (donnée publique réelle)
// ---------------------------------------------------------------------------

let appCache: AppUpdateInfo | null = null;
let appCacheAt = 0;

export function invalidateUpdateCaches(): void {
  appCache = null;
  appCacheAt = 0;
  toolsCache = null;
  toolsCacheAt = 0;
}

export async function getAppUpdateInfo(force = false): Promise<AppUpdateInfo> {
  const checkedAt = new Date().toISOString();
  if (!force && appCache && Date.now() - appCacheAt < CACHE_TTL_MS) return appCache;

  const current = currentAppVersion();
  const fail = (error: string): AppUpdateInfo => ({
    current, latest: null, updateAvailable: false, releaseUrl: null,
    releaseName: null, publishedAt: null, notes: null, asset: null, checkedAt, error,
  });

  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), HTTP_TIMEOUT_MS);
    const res = await fetch(GITHUB_API, {
      headers: {
        'User-Agent': 'GuymaCyb-Desktop-Updater',
        'Accept': 'application/vnd.github+json',
      },
      signal: ctrl.signal,
    });
    clearTimeout(t);
    if (res.status === 403 || res.status === 429) {
      return fail('GitHub a refusé la requête (limite de débit API). Réessayez plus tard — aucune donnée inventée.');
    }
    if (!res.ok) {
      return fail(`API GitHub injoignable (HTTP ${res.status}).`);
    }
    const rel: any = await res.json();
    const latest = typeof rel?.tag_name === 'string' ? rel.tag_name.replace(/^v/, '') : null;
    if (!latest) {
      return fail('Réponse GitHub inattendue (tag de version absent).');
    }
    // Asset installateur Windows réel (le plus gros .exe = setup NSIS).
    const exeAssets: AppReleaseAsset[] = (rel.assets ?? [])
      .filter((a: any) => typeof a?.name === 'string' && a.name.toLowerCase().endsWith('.exe'))
      .map((a: any) => ({ name: a.name, size: Number(a.size) || 0, downloadUrl: a.browser_download_url }))
      .sort((a: AppReleaseAsset, b: AppReleaseAsset) => b.size - a.size);
    const info: AppUpdateInfo = {
      current,
      latest,
      // Version inconnue localement → on AFFICHE la dernière version sans
      // affirmer qu'une mise à jour est disponible (honnêteté).
      updateAvailable: current !== 'inconnue' && compareVersions(latest, current) > 0,
      releaseUrl: typeof rel?.html_url === 'string' ? rel.html_url : null,
      releaseName: typeof rel?.name === 'string' ? rel.name : null,
      publishedAt: typeof rel?.published_at === 'string' ? rel.published_at : null,
      notes: typeof rel?.body === 'string' && rel.body.trim() ? rel.body.trim().slice(0, 1500) : null,
      asset: exeAssets[0] ?? null,
      checkedAt,
      error: null,
    };
    appCache = info;
    appCacheAt = Date.now();
    return info;
  } catch (e: any) {
    const reason = e?.name === 'AbortError' ? 'délai dépassé' : e?.message || 'raison inconnue';
    return fail(`Impossible de joindre GitHub (${reason}). Vérifiez la connexion — état réel conservé.`);
  }
}

// ---------------------------------------------------------------------------
//  2) Mise à jour des OUTILS — apt-cache policy RÉEL dans la distribution
// ---------------------------------------------------------------------------

let toolsCache: ToolsUpdateInfo | null = null;
let toolsCacheAt = 0;

/** Parse la sortie `apt-cache policy pkg1 pkg2 …` en blocs Installed/Candidate. */
export function parseAptPolicy(output: string): Map<string, { installed: string | null; candidate: string | null }> {
  const out = new Map<string, { installed: string | null; candidate: string | null }>();
  let currentPkg = '';
  let installed: string | null = null;
  let candidate: string | null = null;
  const flush = () => {
    if (currentPkg) out.set(currentPkg, { installed, candidate });
  };
  for (const rawLine of output.split('\n')) {
    const line = rawLine.replace(/\r$/, '');
    const pkgMatch = line.match(/^([A-Za-z0-9][A-Za-z0-9+.\-]*):$/);
    if (pkgMatch) {
      flush();
      currentPkg = pkgMatch[1];
      installed = null;
      candidate = null;
      continue;
    }
    const inst = line.match(/^\s{2}Installed:\s*(\S.*)$/);
    if (inst) {
      const v = inst[1].trim();
      installed = v && v !== '(none)' ? v : null;
    }
    const cand = line.match(/^\s{2}Candidate:\s*(\S.*)$/);
    if (cand) {
      const v = cand[1].trim();
      candidate = v && v !== '(none)' ? v : null;
    }
  }
  flush();
  return out;
}

export async function getToolsUpdateInfo(force = false): Promise<ToolsUpdateInfo> {
  const checkedAt = new Date().toISOString();
  if (!force && toolsCache && Date.now() - toolsCacheAt < CACHE_TTL_MS) return toolsCache;

  const base: ToolsUpdateInfo = {
    platform: process.platform,
    isWindows: IS_WINDOWS,
    distro: null,
    packages: [],
    upgradable: [],
    missing: [],
    checkedAt,
    error: null,
  };

  // Résout la distribution (Windows) ou exécute en natif (Linux).
  let distro: string | null = null;
  if (IS_WINDOWS) {
    const state = await getWslState();
    if (!state.available) {
      return {
        ...base,
        distro: state.defaultDistro,
        error: state.reason || 'WSL indisponible — impossible d\'interroger apt.',
      };
    }
    distro = state.defaultDistro;
  }
  base.distro = distro;

  const pkgs = APT_PACKAGES.join(' ');
  // 1) apt-get update : rafraîchit les MÉTADONNÉES réelles des dépôts (lecture
  //    seule, non destructive). 2) apt-cache policy : versions installées vs
  //    candidates réelles. -qq = sortie minimale.
  const cmd = `apt-get update -qq 2>&1 | tail -1; apt-cache policy ${pkgs} 2>&1`;
  let stdout = '';
  try {
    const res = await runApt(cmd, APT_CHECK_TIMEOUT_MS);
    stdout = res.stdout + res.stderr;
  } catch (e: any) {
    return { ...base, error: `Échec de l'interrogation apt : ${e?.message || 'raison inconnue'}` };
  }

  if (!stdout.includes('Candidate:')) {
    return { ...base, distro, error: 'apt n\'a renvoyé aucune information de version (sortie inattendue).' };
  }

  const policy = parseAptPolicy(stdout);
  const packages: ToolPackageStatus[] = [];
  const upgradable: string[] = [];
  const missing: string[] = [];
  for (const pkg of APT_PACKAGES) {
    const p = policy.get(pkg) ?? { installed: null, candidate: null };
    let action: ToolAction = 'none';
    if (!p.installed) {
      // Absent mais candidate connue → installable ; sans candidate (dépôt
      // absent du sources.list), on le signale quand même comme absent.
      if (p.candidate) {
        action = 'install';
        missing.push(pkg);
      } else {
        missing.push(pkg);
      }
    } else if (p.candidate && p.candidate !== p.installed && compareVersions(p.candidate, p.installed) > 0) {
      action = 'upgrade';
      upgradable.push(pkg);
    }
    packages.push({ package: pkg, installed: p.installed, candidate: p.candidate, action });
  }

  const info: ToolsUpdateInfo = { ...base, distro, packages, upgradable, missing, error: null };
  toolsCache = info;
  toolsCacheAt = Date.now();
  return info;
}

// ---------------------------------------------------------------------------
//  3) Application — UNE seule action : apt-get install -y <tout ce qui doit bouger>
// ---------------------------------------------------------------------------

/**
 * Met à jour les paquets périmés ET installe les manquants en UNE commande
 * (`apt-get install -y …`). Pas de choix multiples : l'appelant affiche UN
 * avertissement, l'utilisateur confirme UNE fois, tout s'applique.
 */
export async function applyToolUpdates(): Promise<ApplyToolsResult> {
  const info = await getToolsUpdateInfo(true); // re-check à chaud (cache invalidé)
  if (info.error) {
    return { output: `Impossible de déterminer les mises à jour : ${info.error}`, exitCode: -1, applied: [] };
  }
  // NOTE (bug réel corrigé) : un paquet absent SANS candidate (inconnu des
  // dépôts apt de la distribution) ferait échouer `apt-get install` ENTIER
  // (« Unable to locate package ») — il est exclu de la commande, et signalé
  // honnêtement dans la sortie. Seuls les paquets réellement installables sont
  // passés à apt.
  const installable = (pkg: string) => {
    const p = info.packages.find((x) => x.package === pkg);
    return Boolean(p?.candidate);
  };
  const applied = [...info.upgradable, ...info.missing].filter(installable);
  const unresolvable = [...info.upgradable, ...info.missing].filter((p) => !installable(p));
  if (applied.length === 0) {
    return {
      output: unresolvable.length
        ? `Rien à installer via apt : ${unresolvable.length} paquet(s) absent(s) des dépôts (${unresolvable.join(', ')}) et aucun paquet périmé.`
        : 'Rien à mettre à jour : tous les paquets sont à jour et aucun n\'est manquant.',
      exitCode: 0,
      applied: [],
      skipped: 'nothing-to-do',
    };
  }
  const cmd = `DEBIAN_FRONTEND=noninteractive apt-get install -y ${applied.join(' ')} 2>&1`;
  const state = IS_WINDOWS ? await getWslState() : null;
  if (IS_WINDOWS && !state?.available) {
    return { output: `Installation impossible : ${state?.reason || 'WSL indisponible'}`, exitCode: -1, applied };
  }
  const res = await runApt(cmd, APT_APPLY_TIMEOUT_MS);
  const output = res.stdout + res.stderr;
  const note = unresolvable.length
    ? `\n[Non installés — absents des dépôts apt de cette distribution : ${unresolvable.join(', ')}]`
    : '';
  return { output: (output + note).slice(-8000), exitCode: res.exitCode, applied };
}
