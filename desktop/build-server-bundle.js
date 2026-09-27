#!/usr/bin/env node
/**
 * build-server-bundle.js
 * ----------------------
 * Bundles the Express backend (`server.ts` + all `src/server/*.ts`) into a single
 * self-contained CommonJS file: `dist-server/server.cjs`.
 *
 * This bundle is what the Electron main process (`desktop/electron-main.cjs`) spawns
 * in production. By bundling everything into one .cjs file we avoid shipping tsx,
 * the TypeScript compiler, or the project's node_modules tree to end users.
 *
 * Usage:
 *   node desktop/build-server-bundle.js
 *
 * Output:
 *   dist-server/server.cjs        <- the bundled backend
 *   dist-server/sql-wasm.wasm     <- wasm binary needed by sql.js at runtime
 *
 * Notes:
 *   - `vite` is marked external because it is only used in dev mode (middleware for
 *     HMR). In production the `NODE_ENV=production` branch in server.ts serves the
 *     pre-built `dist/` folder directly with `express.static`, so `vite` is never
 *     required at runtime in production.
 *   - `sql.js` ships a .wasm file that it loads at runtime via `locateFile`. In
 *     Node, sql.js uses `__dirname + "/sql-wasm.wasm"` by default. Since the bundle
 *     is CJS at `dist-server/server.cjs`, `__dirname` resolves to `dist-server/` at
 *     runtime, so we just copy the wasm next to the bundle. db.ts needs no change.
 *   - `import.meta.url` (used in toolbridge.ts) is rewritten by esbuild to a CJS-safe
 *     shim backed by `__filename`, so `__dirname` derived from it points to the
 *     bundle's directory. The Electron main process sets `SHADOWSCAN_CORE_PATH` and
 *     `SECURITY_SCRIPTS_DIR` env vars to override toolbridge's PROJECT_ROOT-relative
 *     defaults, so the Rust binary and security scripts are found at the bundled
 *     locations (extraResources).
 *
 * NOTE: This file is ESM (uses `import`) because the project's package.json has
 * "type": "module". The output bundle is CJS — those are independent concerns.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import esbuild from 'esbuild';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PROJECT_ROOT = path.resolve(__dirname, '..');
const ENTRY = path.join(PROJECT_ROOT, 'server.ts');
const OUT_DIR = path.join(PROJECT_ROOT, 'dist-server');
const OUT_FILE = path.join(OUT_DIR, 'server.cjs');
const SQL_WASM_SRC = path.join(
  PROJECT_ROOT,
  'node_modules',
  'sql.js',
  'dist',
  'sql-wasm.wasm'
);
const SQL_WASM_DEST = path.join(OUT_DIR, 'sql-wasm.wasm');

function ensureDir(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function copyFile(src, dest) {
  fs.copyFileSync(src, dest);
  const size = fs.statSync(dest).size;
  console.log(`[build-server-bundle] copied ${path.basename(dest)} (${size} bytes)`);
}

async function main() {
  console.log('[build-server-bundle] entry :', path.relative(PROJECT_ROOT, ENTRY));
  console.log('[build-server-bundle] output:', path.relative(PROJECT_ROOT, OUT_FILE));

  if (!fs.existsSync(ENTRY)) {
    throw new Error(`Entry file not found: ${ENTRY}`);
  }
  if (!fs.existsSync(SQL_WASM_SRC)) {
    throw new Error(
      `sql-wasm.wasm not found at ${SQL_WASM_SRC}. Run "npm install" first.`
    );
  }

  ensureDir(OUT_DIR);

  // Bundle the server. Everything is inlined except `vite` (dev-only, huge, never
  // required in production). express, sql.js, dotenv, and all project TS files
  // are bundled into a single CJS file.
  await esbuild.build({
    entryPoints: [ENTRY],
    bundle: true,
    platform: 'node',
    format: 'cjs',
    target: 'node18',
    outfile: OUT_FILE,
    minify: true,
    sourcemap: false,
    legalComments: 'none',
    logLevel: 'info',
    // `vite` is only used in the dev branch of server.ts (createViteServer middleware).
    // In production (NODE_ENV=production) that branch is skipped, so we mark vite as
    // external to avoid bundling ~10MB of dev tooling into the production server.
    external: ['vite'],
    define: {
      // Force the production branch in server.ts at build time. This helps esbuild's
      // tree shaker drop the unused vite middleware path; we still need
      // `external: ['vite']` because the import is static at the top of server.ts.
      'process.env.NODE_ENV': '"production"',
      // toolbridge.ts uses `import.meta.url` to compute __dirname/__filename, but
      // `import.meta` is unavailable in CJS output (esbuild leaves it empty).
      // Replace the property access with a runtime identifier `__import_meta_url`
      // which we define in the banner below using Node's CJS `__filename`.
      'import.meta.url': '__import_meta_url',
    },
    banner: {
      js: [
        '// Guyma Cyb — bundled Express backend (production).',
        '// Built by desktop/build-server-bundle.js — do not edit by hand.',
        '// Source: server.ts + src/server/*.ts',
        '//',
        '// import.meta.url shim (CJS target doesn\'t support import.meta):',
        'var __import_meta_url = require("url").pathToFileURL(__filename).href;',
      ].join('\n'),
    },
  });

  // Copy the sql.js wasm binary next to the bundle. sql.js uses
  // `__dirname + "/sql-wasm.wasm"` as its default locateFile in Node, and since
  // this bundle is CJS at dist-server/server.cjs, __dirname == dist-server/.
  copyFile(SQL_WASM_SRC, SQL_WASM_DEST);

  const bundleSize = fs.statSync(OUT_FILE).size;
  console.log(
    `[build-server-bundle] bundle: ${path.relative(PROJECT_ROOT, OUT_FILE)} (${(bundleSize / 1024).toFixed(1)} KB)`
  );
  console.log('[build-server-bundle] done.');
}

main().catch((err) => {
  console.error('[build-server-bundle] FAILED:', err);
  process.exit(1);
});
