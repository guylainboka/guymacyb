// wsl.ts — Couche WSL ROBUSTE pour Guyma Cyb (Windows).
//
// Problèmes corrigés par ce module (bugs constatés sur Windows FR avec WSL à jour) :
//  1. `wsl.exe --list` et consorts écrivent leur sortie en **UTF-16LE** (avec BOM).
//     L'ancien code faisait `d.toString()` (UTF-8) puis supprimait les `\0` —
//     le parsing cassait dès que la moindre ligne localisée (française) apparaissait.
//     Stratégie confirmée par la recherche web (Millwright/VS Code : collecter le
//     Buffer brut → `toString('utf16le')` → strip BOM).
//  2. Le nom du distro était CODÉ EN DUR sur 'Ubuntu'. Or `wsl --install` moderne
//     installe souvent `Ubuntu-22.04`, `Ubuntu-24.04`, ou un autre distro (Debian…).
//     Résultat : `wsl -d Ubuntu …` échouait → tous les outils "manquants",
//     terminaux morts, installation impossible. Désormais le distro par défaut est
//     DÉTECTÉ dynamiquement (astérisque de `wsl -l -v`, fallback `--list --quiet`).
//  3. WSL démarre à froid (service LxssManager) : les premiers appels peuvent durer
//     plusieurs secondes → timeouts trop courts = "WSL non détecté". Ce module
//     gère un cache avec TTL et un timeout de premier contact plus long.

import { spawn } from 'child_process';

export const IS_WINDOWS = process.platform === 'win32';

/** Distro demandé explicitement via env (prioritaire sur la détection). */
const ENV_DISTRO = process.env.WSL_DISTRO || '';

export interface WslResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
}

export interface WslDistro {
  name: string;
  state: string;
  version: string;
  isDefault: boolean;
}

export interface WslState {
  /** wsl.exe présent ET au moins un distro démarre. */
  available: boolean;
  /** wsl.exe existe (binaire Windows) — même si aucun distro n'est installé. */
  installed: boolean;
  /** Version de WSL rapportée par `wsl --version` (vide si inconnue). */
  version: string;
  distros: WslDistro[];
  /** Distro par défaut détecté (astérisque `wsl -l -v`) ou premier de la liste. */
  defaultDistro: string | null;
  /** Raison honnête de l'indisponibilité (affichée telle quelle à l'utilisateur). */
  reason: string;
  checkedAt: number;
}

// ---------------------------------------------------------------------------
//  Décodage de la sortie console de wsl.exe (UTF-16LE)
// ---------------------------------------------------------------------------

/**
 * Décode la sortie brute d'un process Windows console (wsl.exe, powershell…).
 * wsl.exe écrit en UTF-16LE avec BOM ; les autres outils en CP/UTF-8.
 * Détection : BOM FF/FE, sinon densité d'octets nuls (>15 % sur l'échantillon).
 */
export function decodeConsoleOutput(buf: Buffer): string {
  if (buf.length === 0) return '';
  const sample = buf.subarray(0, Math.min(buf.length, 4096));
  const hasBom = sample.length >= 2 && sample[0] === 0xff && sample[1] === 0xfe;
  let nullCount = 0;
  for (const b of sample) if (b === 0x00) nullCount += 1;
  const nullDensity = nullCount / sample.length;
  if (hasBom || nullDensity > 0.15) {
    // UTF-16LE : le Buffer contient déjà l'encodage natif — toString le décode.
    let text = buf.toString('utf16le');
    // Strip BOM éventuel (FF FE -> U+FEFF en début de chaîne décodée)
    if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
    return text;
  }
  return buf.toString('utf8');
}

/** Retire les codes ANSI et normalise les fins de ligne. */
export function stripAnsi(text: string): string {
  return text.replace(/\x1b\[[0-9;]*m/g, '');
}

// ---------------------------------------------------------------------------
//  Exécution de wsl.exe
// ---------------------------------------------------------------------------

/** Exécute `wsl.exe <args>` et décode correctement la sortie UTF-16LE. */
export function wslRun(args: string[], timeoutMs = 20_000): Promise<WslResult> {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn('wsl.exe', args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      });
    } catch (e: any) {
      resolve({ stdout: '', stderr: e?.message || 'spawn failed', exitCode: -1, timedOut: false });
      return;
    }
    const chunks: Buffer[] = [];
    let settled = false;
    let timedOut = false;
    const timer = setTimeout(() => {
      if (!settled) {
        timedOut = true;
        try { child.kill('SIGKILL'); } catch { /* ignore */ }
      }
    }, timeoutMs);

    child.stdout.on('data', (d: Buffer) => chunks.push(d));
    child.stderr.on('data', (d: Buffer) => chunks.push(d));
    child.on('error', (err: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ stdout: '', stderr: err.message, exitCode: -1, timedOut });
    });
    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const raw = Buffer.concat(chunks);
      const text = stripAnsi(decodeConsoleOutput(raw));
      resolve({ stdout: text, stderr: '', exitCode: code ?? -1, timedOut });
    });
  });
}

/** Exécute une commande dans le distro donné (ou le distro par défaut si omis). */
export async function runInDistro(
  command: string[],
  opts: { distro?: string; timeoutMs?: number; user?: string } = {}
): Promise<WslResult> {
  const state = await getWslState();
  const distro = opts.distro || state.defaultDistro;
  if (!distro) {
    return { stdout: '', stderr: 'Aucun distro WSL disponible', exitCode: -1, timedOut: false };
  }
  const args = ['-d', distro];
  if (opts.user) args.push('-u', opts.user);
  args.push('--', ...command);
  return wslRun(args, opts.timeoutMs ?? 60_000);
}

// ---------------------------------------------------------------------------
//  Détection d'état WSL (cachée, TTL 15 s)
// ---------------------------------------------------------------------------

let cachedState: WslState | null = null;
let detectionInFlight: Promise<WslState> | null = null;
const STATE_TTL_MS = 15_000;

function parseListVerbose(text: string): WslDistro[] {
  const distros: WslDistro[] = [];
  const lines = text.split(/\r?\n/).map((l) => l.replace(/\uFEFF/g, '').trimEnd());
  for (const line of lines) {
    if (!line.trim()) continue;
    // Ligne d'en-tête : contient "NAME"/"STATE"/"VERSION" (ou localisé) — on la
    // saute en détectant l'absence de chiffre de version en fin de ligne.
    const isDefault = /^\s*\*/.test(line);
    const clean = line.replace(/^\s*\*\s*/, '').trim();
    const parts = clean.split(/\s{2,}|\t/).map((p) => p.trim()).filter(Boolean);
    if (parts.length >= 3 && /^\d+$/.test(parts[parts.length - 1])) {
      distros.push({
        name: parts[0],
        state: parts[1],
        version: parts[parts.length - 1],
        isDefault,
      });
    }
  }
  return distros;
}

/**
 * Nom de distribution VALIDE : lettres/chiffres/._- sans espace (format des
 * distros Store : Ubuntu, Ubuntu-24.04, Debian, kali-linux…).
 * CRITIQUE (bug constaté en test) : quand AUCUNE distro n'est installée,
 * `wsl --list --quiet` n'imprime PAS une liste vide mais un MESSAGE D'ERREUR
 * localisé (« Le système ne trouve pas le fichier spécifié. » / « Windows
 * Subsystem for Linux has no installed distributions. »). Sans ce filtre, le
 * message serait pris pour un NOM de distro → faux positif de détection.
 */
function isValidDistroName(name: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name);
}

/** Détection complète — résultat caché 15 s (WSL démarre à froid). */
export async function getWslState(force = false): Promise<WslState> {
  if (!IS_WINDOWS) {
    return {
      available: true,
      installed: true,
      version: 'n/a (Linux natif)',
      distros: [],
      defaultDistro: null,
      reason: 'Linux natif — les outils s’exécutent directement',
      checkedAt: Date.now(),
    };
  }
  if (!force && cachedState && Date.now() - cachedState.checkedAt < STATE_TTL_MS) {
    return cachedState;
  }
  if (detectionInFlight) return detectionInFlight;

  detectionInFlight = (async (): Promise<WslState> => {
    const state: WslState = {
      available: false,
      installed: false,
      version: '',
      distros: [],
      defaultDistro: null,
      reason: '',
      checkedAt: Date.now(),
    };

    // 1) wsl.exe existe-t-il ? (`--version` : rapide, même sans distro)
    const ver = await wslRun(['--version'], 10_000);
    if (ver.timedOut) {
      state.reason = 'wsl.exe ne répond pas (service WSL en cours de démarrage — réessayez)';
      cachedState = state;
      return state;
    }
    if (ver.exitCode !== 0 && !ver.stdout) {
      state.reason = 'WSL n’est pas installé (wsl.exe introuvable ou inerte) — bouton « Installer WSL » ci-dessous';
      cachedState = state;
      return state;
    }
    state.installed = true;
    state.version = ver.stdout.split('\n')[0]?.trim() || '';

    // 2) Liste des distros : `--list --quiet` (noms seuls) puis `-l -v` (état+version)
    const quiet = await wslRun(['--list', '--quiet'], 15_000);
    const names = quiet.stdout
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(isValidDistroName);

    const verbose = await wslRun(['--list', '--verbose'], 15_000);
    let distros = parseListVerbose(verbose.stdout);
    if (distros.length === 0 && names.length > 0) {
      distros = names.map((n) => ({ name: n, state: 'Unknown', version: '?', isDefault: false }));
    }
    state.distros = distros;

    if (distros.length === 0) {
      state.reason = 'WSL est installé mais AUCUN distro Linux — bouton « Installer Ubuntu » disponible ci-dessous (ou Core Manager)';
      cachedState = state;
      return state;
    }

    // 3) Distro par défaut : astérisque de -l -v, sinon premier nom, sinon env
    const marked = distros.find((d) => d.isDefault);
    state.defaultDistro = ENV_DISTRO || marked?.name || distros[0].name;

    // 4) Le distro démarre-t-il réellement ? (premier contact potentiellement long)
    const test = await runInDistro(['echo', 'gcyb-ok'], {
      distro: state.defaultDistro,
      timeoutMs: 30_000,
    });
    if (test.timedOut) {
      state.reason = `Le distro « ${state.defaultDistro} » ne répond pas (démarrage trop long ou corrompu)`;
      cachedState = state;
      return state;
    }
    if (test.exitCode !== 0 || !test.stdout.includes('gcyb-ok')) {
      state.reason = `Le distro « ${state.defaultDistro} » est installé mais ne démarre pas : ${test.stderr || `exit ${test.exitCode}`}`;
      cachedState = state;
      return state;
    }

    state.available = true;
    state.reason = '';
    cachedState = state;
    return state;
  })();

  try {
    return await detectionInFlight;
  } finally {
    detectionInFlight = null;
  }
}

/** Nom du distro actif (détection dynamique, jamais codé en dur). */
export async function getActiveDistro(): Promise<string | null> {
  const state = await getWslState();
  return state.available ? state.defaultDistro : null;
}

/** Réinitialise le cache (après installation WSL/tools par exemple). */
export function invalidateWslCache(): void {
  cachedState = null;
  detectionInFlight = null;
}

// ---------------------------------------------------------------------------
//  Installation de la DISTRIBUTION Ubuntu — état « WSL installé, 0 distro »
//
//  Cas réel constaté chez l'opérateur : `wsl --update` répond « déjà à jour »
//  mais `wsl -l -v` ne liste AUCUNE distribution. Le logiciel détecte cet état
//  mais n'offrait aucun bouton pour y remédier. Ce job installe Ubuntu en un
//  clic, NON-INTERACTIF, avec journal en direct :
//   1. `wsl --install -d Ubuntu --no-launch`  (doc Microsoft : installe sans
//      lancer — évite l'OOBE interactif qui bloque tout appel automatisé)
//   2. Fallback `--web-download` (contournement Microsoft Store)
//   3. Fallback avec élévation UAC (PowerShell Start-Process -Verb RunAs)
//   4. Attente de l'enregistrement (poll `wsl --list --quiet`)
//   5. Premier contact `-u root` (extraction du rootfs, pas d'OOBE en root)
//   6. `/etc/wsl.conf` [user] default=root (doc Microsoft, build 18980+) —
//      tous les appels de l'app passent ensuite sans prompt sudo.
// ---------------------------------------------------------------------------

export interface DistroInstallStatus {
  running: boolean;
  done: boolean;
  success: boolean;
  error: string;
  log: string[];
  distroName: string;
  startedAt: number | null;
  finishedAt: number | null;
}

interface DistroInstallJob extends DistroInstallStatus {}

const DISTRO_TARGET = process.env.GCYB_WSL_DISTRO || 'Ubuntu';
const MAX_LOG_LINES = 400;

let distroJob: DistroInstallJob = {
  running: false,
  done: false,
  success: false,
  error: '',
  log: [],
  distroName: '',
  startedAt: null,
  finishedAt: null,
};

function dlog(line: string): void {
  const stamp = new Date().toLocaleTimeString('fr-FR', { hour12: false });
  distroJob.log.push(`[${stamp}] ${line}`);
  if (distroJob.log.length > MAX_LOG_LINES) {
    distroJob.log.splice(0, distroJob.log.length - MAX_LOG_LINES);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Noms de distros enregistrés (`wsl --list --quiet`, décodage UTF-16LE inclus).
 *  Filtrage STRICT : les messages d'erreur localisés de wsl.exe (imprimés quand
 *  aucune distro n'est installée) ne doivent JAMAIS passer pour des noms. */
async function listDistroNames(): Promise<string[]> {
  const res = await wslRun(['--list', '--quiet'], 20_000);
  return res.stdout
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(isValidDistroName);
}

/** Dernier recours : `wsl --install` ÉLEVÉ via UAC (fenêtre Windows visible). */
function wslInstallElevated(): Promise<number> {
  return new Promise((resolve) => {
    const psScript =
      `try { $p = Start-Process wsl.exe -ArgumentList '--install','--no-launch','-d','${DISTRO_TARGET}' ` +
      `-Verb RunAs -Wait -PassThru; exit $p.ExitCode } catch { exit 1602 }`;
    let child;
    try {
      child = spawn('powershell.exe', ['-NoProfile', '-Command', psScript], {
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      });
    } catch {
      resolve(-1);
      return;
    }
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        try { child.kill(); } catch { /* ignore */ }
        resolve(-1);
      }
    }, 900_000);
    child.on('error', () => {
      if (!settled) { settled = true; clearTimeout(timer); resolve(-1); }
    });
    child.on('close', (code) => {
      if (!settled) { settled = true; clearTimeout(timer); resolve(code ?? -1); }
    });
  });
}

/** Démarre le job d'installation de la distribution (un seul à la fois). */
export function startDistroInstall(): { started: boolean; message: string } {
  if (distroJob.running) {
    return { started: false, message: 'Une installation de distribution est déjà en cours' };
  }
  if (!IS_WINDOWS) {
    return { started: false, message: 'Linux natif — aucune distribution WSL à installer' };
  }
  distroJob = {
    running: true,
    done: false,
    success: false,
    error: '',
    log: [],
    distroName: '',
    startedAt: Date.now(),
    finishedAt: null,
  };
  void runDistroInstall();
  return { started: true, message: `Installation de « ${DISTRO_TARGET} » démarrée — suivez le journal en direct` };
}

async function runDistroInstall(): Promise<void> {
  try {
    dlog('Vérification de l\'état WSL…');
    invalidateWslCache();
    const state = await getWslState(true);
    if (!state.installed) {
      throw new Error(
        'WSL n\'est pas installé — utilisez d\'abord « Installer WSL » (assistant UAC du Core Manager) ' +
        'ou lancez « wsl --install » dans PowerShell (admin).'
      );
    }
    if (state.distros.length > 0) {
      distroJob.success = true;
      dlog(`✓ Une distribution existe déjà (${state.defaultDistro}) — rien à installer.`);
      return;
    }

    dlog(`Téléchargement + enregistrement de « ${DISTRO_TARGET} » (5 à 15 min selon la connexion)…`);
    let res = await wslRun(['--install', '--no-launch', '-d', DISTRO_TARGET], 900_000);
    if (res.exitCode !== 0) {
      dlog(`1re tentative échouée (exit ${res.exitCode}) — nouvelle tentative avec --web-download (contournement Microsoft Store)…`);
      res = await wslRun(['--install', '--no-launch', '-d', DISTRO_TARGET, '--web-download'], 900_000);
    }
    if (res.exitCode !== 0) {
      dlog('Nouvelle tentative AVEC élévation UAC — une fenêtre Windows va s\'ouvrir : acceptez-la.');
      const code = await wslInstallElevated();
      if (code !== 0) {
        throw new Error(
          code === 1602 || code === 1223
            ? 'Élévation UAC refusée — relancez l\'installation et acceptez la fenêtre Windows.'
            : `wsl --install a échoué (exit ${code}). Sortie : ${(res.stdout || res.stderr || '').slice(0, 400)}`
        );
      }
    }
    dlog('✓ Commande wsl --install terminée — attente de l\'enregistrement de la distribution…');

    // La fin de wsl --install ne garantit pas un enregistrement immédiat : on
    // interroge `--list --quiet` toutes les 5 s pendant 5 min maximum.
    let names: string[] = [];
    for (let i = 0; i < 60; i++) {
      await sleep(5_000);
      names = await listDistroNames();
      if (names.length > 0) break;
      if (i % 6 === 5) dlog(`… toujours en attente d'enregistrement (${(i + 1) * 5} s)`);
    }
    if (names.length === 0) {
      throw new Error(
        'La distribution ne s\'est pas enregistrée après 5 min d\'attente. ' +
        'Vérifiez la connexion réseau / Microsoft Store puis relancez l\'installation.'
      );
    }
    // Plusieurs distros peuvent apparaître : on préfère un Ubuntu.
    const chosen = names.find((n) => /^ubuntu/i.test(n)) || names[0];
    distroJob.distroName = chosen;
    dlog(`✓ Distribution enregistrée : « ${chosen} » — premier démarrage (extraction du système, 1 à 5 min)…`);

    // Premier contact en root : initialise la distribution SANS OOBE interactif.
    const init = await wslRun(['-d', chosen, '-u', 'root', '--', 'echo', 'gcyb-init-ok'], 300_000);
    if (init.exitCode !== 0 || !init.stdout.includes('gcyb-init-ok')) {
      throw new Error(
        `La distribution « ${chosen} » est enregistrée mais ne démarre pas : ` +
        `${(init.stderr || init.stdout || `exit ${init.exitCode}`).slice(0, 300)}`
      );
    }
    dlog('✓ Distribution fonctionnelle — configuration du compte par défaut (root, zéro prompt sudo)…');

    // /etc/wsl.conf [user] default=root (doc Microsoft, build 18980+) : tous
    // les appels de l'app (apt, outils) passent ensuite sans interaction.
    const conf = await wslRun(
      ['-d', chosen, '-u', 'root', '--', 'bash', '-c',
       `printf '[user]\\ndefault=root\\n' > /etc/wsl.conf && cat /etc/wsl.conf`],
      30_000
    );
    if (conf.exitCode !== 0) {
      dlog('⚠ /etc/wsl.conf non écrit — l\'app utilisera `-u root` explicitement (aucun impact fonctionnel).');
    } else {
      await wslRun(['--terminate', chosen], 30_000);
      dlog('✓ Compte par défaut configuré (root) — redémarrage de la distribution effectué.');
    }

    invalidateWslCache();
    const finalState = await getWslState(true);
    if (finalState.available) {
      distroJob.success = true;
      dlog(
        `✓ TERMINÉ — WSL opérationnel (distro : ${finalState.defaultDistro}). ` +
        'Étape suivante : bouton « Installer les outils Linux ».'
      );
    } else {
      throw new Error(finalState.reason || 'WSL encore indisponible après installation de la distribution');
    }
  } catch (e: any) {
    distroJob.success = false;
    distroJob.error = e?.message || String(e);
    dlog(`✗ ÉCHEC — ${distroJob.error}`);
  } finally {
    distroJob.running = false;
    distroJob.done = true;
    distroJob.finishedAt = Date.now();
  }
}

/** État du job d'installation (journal inclus) — consommé par l'UI en polling. */
export function getDistroInstallStatus(): DistroInstallStatus {
  return { ...distroJob, log: [...distroJob.log] };
}
