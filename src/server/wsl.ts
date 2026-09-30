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
      .filter((l) => l && !l.startsWith('Windows Subsystem') && !/mise à jour|update/i.test(l));

    const verbose = await wslRun(['--list', '--verbose'], 15_000);
    let distros = parseListVerbose(verbose.stdout);
    if (distros.length === 0 && names.length > 0) {
      distros = names.map((n) => ({ name: n, state: 'Unknown', version: '?', isDefault: false }));
    }
    state.distros = distros;

    if (distros.length === 0) {
      state.reason = 'WSL est installé mais AUCUN distro Linux — lancez « wsl --install -d Ubuntu » (ou bouton ci-dessous)';
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
