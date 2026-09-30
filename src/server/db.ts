import initSqlJs, { Database } from 'sql.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Compatible ESM (tsx dev) ET CJS (bundle esbuild server.cjs) :
// en ESM __dirname n'existe pas, en CJS import.meta.url est shimé par esbuild.
const MODULE_DIR: string =
  typeof __dirname !== 'undefined'
    ? __dirname
    : path.dirname(fileURLToPath(import.meta.url));

// Le chemin de la base est surchargeable via GCYB_DB_PATH (Electron le pointe
// vers userData/ pour éviter toute écriture dans Program Files, qui échoue
// sans droits admin). Défaut : cwd (dev/sandbox).
const DB_FILE_PATH = process.env.GCYB_DB_PATH
  ? path.resolve(process.env.GCYB_DB_PATH)
  : path.resolve(process.cwd(), 'shadow_core.db');

let dbInstance: Database | null = null;

export async function getDatabase(): Promise<Database> {
  if (dbInstance) {
    return dbInstance;
  }

  // sql.js ne trouve PAS sql-wasm.wasm par défaut (contrairement à ce que dit la
  // doc) — il cherche dans process.cwd(). On fournit locateFile qui essaie, dans
  // l'ordre :
  //   1. le dossier du bundle server.cjs (dist-server/ en prod Electron),
  //   2. node_modules/sql.js/dist/ relatif au cwd (dev tsx) et au module,
  //   3. le nom brut (sql.js retombe alors sur sa résolution par défaut).
  const SQL = await initSqlJs({
    locateFile: (file: string) => {
      const candidates = [
        path.join(MODULE_DIR, file),
        path.resolve(process.cwd(), 'node_modules/sql.js/dist', file),
        path.resolve(MODULE_DIR, '../../node_modules/sql.js/dist', file),
      ];
      for (const c of candidates) {
        try {
          if (fs.existsSync(c)) return c;
        } catch { /* ignore */ }
      }
      return file;
    },
  });

  if (fs.existsSync(DB_FILE_PATH)) {
    try {
      const fileBuffer = fs.readFileSync(DB_FILE_PATH);
      dbInstance = new SQL.Database(fileBuffer);
      initTables(dbInstance);
      return dbInstance;
    } catch (err) {
      console.warn('Failed to load existing SQLite file, creating fresh database:', err);
    }
  }

  dbInstance = new SQL.Database();
  initTables(dbInstance);
  saveDatabaseToDisk(dbInstance);
  return dbInstance;
}

function initTables(db: Database) {
  db.run(`
    CREATE TABLE IF NOT EXISTS targets (
      id TEXT PRIMARY KEY,
      url TEXT NOT NULL,
      domain TEXT NOT NULL,
      scope TEXT NOT NULL,
      operator_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      last_scanned_at TEXT NOT NULL,
      status TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      target_id TEXT NOT NULL,
      url TEXT NOT NULL,
      scan_type TEXT NOT NULL,
      cvss_score REAL NOT NULL,
      risk_level TEXT NOT NULL,
      duration_ms INTEGER NOT NULL,
      endpoints_count INTEGER NOT NULL,
      technologies_json TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS endpoints (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL,
      path TEXT NOT NULL,
      method TEXT NOT NULL,
      status_code INTEGER NOT NULL,
      status_text TEXT NOT NULL,
      type TEXT NOT NULL,
      note TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS findings (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL,
      target_url TEXT NOT NULL,
      title TEXT NOT NULL,
      severity TEXT NOT NULL,
      cvss REAL NOT NULL,
      confidence INTEGER NOT NULL,
      status TEXT NOT NULL,
      affected_component TEXT NOT NULL,
      category TEXT NOT NULL,
      cwe TEXT NOT NULL,
      description TEXT NOT NULL,
      evidence_request TEXT NOT NULL,
      evidence_response TEXT NOT NULL,
      impact TEXT NOT NULL,
      remediation_title TEXT NOT NULL,
      remediation_steps_json TEXT NOT NULL,
      signature TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      tag TEXT NOT NULL,
      text TEXT NOT NULL,
      operator_id TEXT NOT NULL
    );
  `);

  // Doctrine « zéro invention » : on ne peuple PLUS la base avec des cibles
  // fictives au premier lancement. L'utilisateur démarre avec une base vide
  // et un dashboard honnête (« Aucune donnée disponible »). Les cibles
  // historiques n'apparaissent qu'après un vrai scan.
  // (Anciennement : 3 cibles fictives api.internal-cloud.io / stage-auth /
  // payment-gateway insérées ici — supprimées car elles donnaient l'illusion
  // qu'un audit avait déjà été effectué.)
}

export function saveDatabaseToDisk(db?: Database) {
  try {
    const targetDb = db || dbInstance;
    if (!targetDb) return;
    const data = targetDb.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(DB_FILE_PATH, buffer);
  } catch (err) {
    console.error('Error saving SQLite database to disk:', err);
  }
}

export function getDbFilePath(): string {
  return DB_FILE_PATH;
}

/** Chemin du dossier du module (utile pour localiser des ressources adjacentes). */
export function getModuleDir(): string {
  return MODULE_DIR;
}
