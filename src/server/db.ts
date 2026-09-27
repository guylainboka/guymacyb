import initSqlJs, { Database } from 'sql.js';
import fs from 'fs';
import path from 'path';

const DB_FILE_PATH = path.resolve(process.cwd(), 'shadow_core.db');

let dbInstance: Database | null = null;

export async function getDatabase(): Promise<Database> {
  if (dbInstance) {
    return dbInstance;
  }

  const SQL = await initSqlJs();

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

  // Seed default sample target if table is empty
  const countRes = db.exec("SELECT COUNT(*) as cnt FROM targets");
  const count = countRes[0]?.values[0]?.[0] as number || 0;
  if (count === 0) {
    db.run(`
      INSERT INTO targets (id, url, domain, scope, operator_id, created_at, last_scanned_at, status)
      VALUES 
        ('t-1', 'https://api.internal-cloud.io', 'api.internal-cloud.io', 'wildcard', 'SEC-OPS-0982', datetime('now', '-2 hours'), datetime('now', '-2 hours'), 'COMPLETED'),
        ('t-2', 'https://stage-auth.corporation.com', 'stage-auth.corporation.com', 'strict', 'SEC-OPS-0982', datetime('now', '-1 day'), datetime('now', '-1 day'), 'COMPLETED'),
        ('t-3', 'https://payment-gateway.node12.org', 'payment-gateway.node12.org', 'strict', 'SEC-OPS-0982', datetime('now', '-5 days'), datetime('now', '-5 days'), 'COMPLETED');
    `);
  }
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
