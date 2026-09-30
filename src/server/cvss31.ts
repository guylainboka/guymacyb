// ============================================================
//  Calculateur CVSS v3.1 VECTORIEL — Guyma Cyb
// ============================================================
//
// Implémentation RÉELLE de la spécification CVSS v3.1 (FIRST.org) :
// https://www.first.org/cvss/v3.1/specification-document
//
// Plus aucun score théorique dérivé d'une bande de sévérité : le score
// est CALCULÉ à partir du vecteur (AV/AC/PR/UI/S/C/I/A + temporel +
// environnemental), avec l'arrondi officiel « Roundup1 » de la spec
// (scaling entier ×100 000 pour éviter les artefacts flottants).
//
// Exemples de référence (spécification §8.1) :
//   CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  → 9.8 CRITICAL
//   CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H  → 10.0 CRITICAL
//   CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N  → 5.3 MEDIUM
//   CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N  → 6.5 MEDIUM

export type CvssSeverity = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface Cvss31Result {
  /** Vecteur normalisé (réordonné selon l'ordre de la spécification). */
  vector: string;
  /** Score de base (0.0 – 10.0). */
  baseScore: number;
  /** Score temporel (null si aucune métrique temporelle fournie). */
  temporalScore: number | null;
  /** Score environnemental (null si aucune métrique environnementale fournie). */
  environmentalScore: number | null;
  /** Score global retenu (env > temporel > base). */
  overallScore: number;
  /** Qualification officielle du score global. */
  severity: CvssSeverity;
}

const BASE_METRICS: Record<string, Record<string, number>> = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
};

// PR dépend du Scope (§8.2 de la spécification)
const PR_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };

const TEMPORAL_METRICS: Record<string, Record<string, number>> = {
  E: { X: 1, U: 0.91, P: 0.94, F: 0.97, H: 1 },
  RL: { X: 1, O: 0.95, T: 0.96, W: 0.97, U: 1 },
  RC: { X: 1, U: 0.91, R: 0.96, C: 1 },
};

const ENV_METRICS: Record<string, Record<string, number>> = {
  CR: { X: 1, L: 0.5, M: 1, H: 1.5 },
  IR: { X: 1, L: 0.5, M: 1, H: 1.5 },
  AR: { X: 1, L: 0.5, M: 1, H: 1.5 },
};

/** Ordre canonique des métriques selon la spécification. */
const METRIC_ORDER = [
  'AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A',
  'E', 'RL', 'RC',
  'CR', 'IR', 'AR', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA',
];

const KNOWN_VALUES: Record<string, readonly string[]> = {
  AV: ['N', 'A', 'L', 'P'],
  AC: ['L', 'H'],
  PR: ['N', 'L', 'H'],
  UI: ['N', 'R'],
  S: ['U', 'C'],
  C: ['H', 'L', 'N'],
  I: ['H', 'L', 'N'],
  A: ['H', 'L', 'N'],
  E: ['X', 'U', 'P', 'F', 'H'],
  RL: ['X', 'O', 'T', 'W', 'U'],
  RC: ['X', 'U', 'R', 'C'],
  CR: ['X', 'L', 'M', 'H'],
  IR: ['X', 'L', 'M', 'H'],
  AR: ['X', 'L', 'M', 'H'],
  MAV: ['X', 'N', 'A', 'L', 'P'],
  MAC: ['X', 'L', 'H'],
  MPR: ['X', 'N', 'L', 'H'],
  MUI: ['X', 'N', 'R'],
  MS: ['X', 'U', 'C'],
  MC: ['X', 'H', 'L', 'N'],
  MI: ['X', 'H', 'L', 'N'],
  MA: ['X', 'H', 'L', 'N'],
};

// Métriques de base obligatoires (un vecteur incomplet est rejeté — zéro invention)
const REQUIRED: (keyof typeof KNOWN_VALUES)[] = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];

/**
 * Arrondi officiel CVSS (« Roundup1 », 附录 A de la spécification) :
 * évite les artefacts de virgule flottante de Math.ceil(x*10)/10.
 */
function roundup1(input: number): number {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) {
    return intInput / 100000.0;
  }
  return (Math.floor(intInput / 10000) + 1) / 10.0;
}

/** Qualification officielle d'un score CVSS v3.1. */
export function cvssSeverityFromScore(score: number): CvssSeverity {
  if (score <= 0) return 'NONE';
  if (score <= 3.9) return 'LOW';
  if (score <= 6.9) return 'MEDIUM';
  if (score <= 8.9) return 'HIGH';
  return 'CRITICAL';
}

export interface ParsedCvssVector {
  version: string;
  metrics: Record<string, string>;
}

/** Parse et valide STRICTEMENT un vecteur CVSS v3.x (zéro invention). */
export function parseCvssVector(vector: string): ParsedCvssVector {
  if (typeof vector !== 'string' || vector.trim().length === 0) {
    throw new Error('Vecteur CVSS vide.');
  }
  const parts = vector.trim().split('/');
  const versionMatch = /^CVSS:3\.(0|1)$/.exec(parts[0] || '');
  if (!versionMatch) {
    throw new Error(`Vecteur CVSS invalide : préfixe « CVSS:3.0/ » ou « CVSS:3.1/ » attendu (reçu « ${parts[0] ?? 'vide'} »).`);
  }
  const metrics: Record<string, string> = {};
  for (const part of parts.slice(1)) {
    const m = /^([A-Z]{1,3}):([A-Z])$/.exec(part);
    if (!m) {
      throw new Error(`Métrique CVSS malformée : « ${part} ».`);
    }
    const [, key, value] = m;
    const allowed = KNOWN_VALUES[key];
    if (!allowed) {
      throw new Error(`Métrique CVSS inconnue : « ${key} ».`);
    }
    if (!allowed.includes(value)) {
      throw new Error(`Valeur « ${value} » invalide pour la métrique ${key} (permis : ${allowed.join('/')}).`);
    }
    if (metrics[key]) {
      throw new Error(`Métrique ${key} dupliquée dans le vecteur.`);
    }
    metrics[key] = value;
  }
  for (const req of REQUIRED) {
    if (!metrics[req]) {
      throw new Error(`Métrique de base obligatoire absente : ${req}.`);
    }
  }
  return { version: versionMatch[0], metrics };
}

function weightedCia(m: Record<string, string>): number {
  const C = BASE_METRICS.CIA[m.C] ?? 0;
  const I = BASE_METRICS.CIA[m.I] ?? 0;
  const A = BASE_METRICS.CIA[m.A] ?? 0;
  return 1 - (1 - C) * (1 - I) * (1 - A);
}

/** Score de base — équations §8.2 de la spécification. */
export function baseScore(metrics: Record<string, string>): number {
  const iss = weightedCia(metrics);
  const scopeChanged = metrics.S === 'C';
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  const prTable = scopeChanged ? PR_CHANGED : PR_UNCHANGED;
  const exploitability =
    8.22 * (BASE_METRICS.AV[metrics.AV] ?? 0) * (BASE_METRICS.AC[metrics.AC] ?? 0) * (prTable[metrics.PR] ?? 0) * (BASE_METRICS.UI[metrics.UI] ?? 0);
  if (impact <= 0) return 0;
  if (scopeChanged) {
    return roundup1(Math.min(1.08 * (impact + exploitability), 10));
  }
  return roundup1(Math.min(impact + exploitability, 10));
}

/** Score temporel — §8.3. */
export function temporalScore(base: number, metrics: Record<string, string>): number {
  const E = metrics.E && metrics.E !== 'X' ? TEMPORAL_METRICS.E[metrics.E] ?? 1 : 1;
  const RL = metrics.RL && metrics.RL !== 'X' ? TEMPORAL_METRICS.RL[metrics.RL] ?? 1 : 1;
  const RC = metrics.RC && metrics.RC !== 'X' ? TEMPORAL_METRICS.RC[metrics.RC] ?? 1 : 1;
  return roundup1(base * E * RL * RC);
}

/** Score environnemental — §8.4 (v3.1 : double roundup officiel). */
export function environmentalScore(metrics: Record<string, string>): number {
  const hasEnv = ['CR', 'IR', 'AR', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA']
    .some((k) => metrics[k] && metrics[k] !== 'X');
  if (!hasEnv) return NaN; // pas de score environnemental demandé

  const reqFactor = (key: 'CR' | 'IR' | 'AR'): number => {
    const v = metrics[key];
    if (!v || v === 'X') return 1;
    return ENV_METRICS[key][v] ?? 1;
  };
  const mc = metrics.MC && metrics.MC !== 'X' ? metrics.MC : metrics.C;
  const mi = metrics.MI && metrics.MI !== 'X' ? metrics.MI : metrics.I;
  const ma = metrics.MA && metrics.MA !== 'X' ? metrics.MA : metrics.A;

  const miss = Math.min(
    1 - (1 - (BASE_METRICS.CIA[mc] ?? 0) * reqFactor('CR')) * (1 - (BASE_METRICS.CIA[mi] ?? 0) * reqFactor('IR')) * (1 - (BASE_METRICS.CIA[ma] ?? 0) * reqFactor('AR')),
    0.56
  );

  // Scope modifié : X → hérite du scope de base
  const modifiedScope = metrics.MS && metrics.MS !== 'X' ? metrics.MS : metrics.S;
  const modifiedImpact =
    modifiedScope === 'C'
      ? 7.52 * (miss - 0.029) - 3.25 * Math.pow(miss - 0.02, 15)
      : 6.42 * miss;

  const mAV = metrics.MAV && metrics.MAV !== 'X' ? metrics.MAV : metrics.AV;
  const mAC = metrics.MAC && metrics.MAC !== 'X' ? metrics.MAC : metrics.AC;
  const mPR = metrics.MPR && metrics.MPR !== 'X' ? metrics.MPR : metrics.PR;
  const mUI = metrics.MUI && metrics.MUI !== 'X' ? metrics.MUI : metrics.UI;
  const prTableEnv = modifiedScope === 'C' ? PR_CHANGED : PR_UNCHANGED;
  const modifiedExploitability =
    8.22 * (BASE_METRICS.AV[mAV] ?? 0) * (BASE_METRICS.AC[mAC] ?? 0) * (prTableEnv[mPR] ?? 0) * (BASE_METRICS.UI[mUI] ?? 0);

  if (modifiedImpact <= 0) return 0;
  const inner = Math.min(modifiedImpact + modifiedExploitability, 10);
  const innerRounded = modifiedScope === 'C'
    ? roundup1(Math.min(1.08 * inner, 10))
    : roundup1(inner);
  const E = metrics.E && metrics.E !== 'X' ? TEMPORAL_METRICS.E[metrics.E] ?? 1 : 1;
  const RL = metrics.RL && metrics.RL !== 'X' ? TEMPORAL_METRICS.RL[metrics.RL] ?? 1 : 1;
  const RC = metrics.RC && metrics.RC !== 'X' ? TEMPORAL_METRICS.RC[metrics.RC] ?? 1 : 1;
  return roundup1(innerRounded * E * RL * RC);
}

/** Réordonne le vecteur selon l'ordre canonique de la spécification. */
function normalizeVector(metrics: Record<string, string>): string {
  const parts: string[] = ['CVSS:3.1'];
  for (const key of METRIC_ORDER) {
    if (metrics[key]) parts.push(`${key}:${metrics[key]}`);
  }
  return parts.join('/');
}

/**
 * Calcul complet d'un vecteur CVSS v3.1 : base + temporel + environnemental.
 * Lève une exception si le vecteur est malformé ou incomplet (zéro invention).
 */
export function computeCvss31(vector: string): Cvss31Result {
  const { metrics } = parseCvssVector(vector);
  const base = baseScore(metrics);
  const hasTemporal = ['E', 'RL', 'RC'].some((k) => metrics[k] && metrics[k] !== 'X');
  const temporal = hasTemporal ? temporalScore(base, metrics) : null;
  const environmental = environmentalScore(metrics);
  const overall = !Number.isNaN(environmental)
    ? environmental
    : temporal !== null
      ? temporal
      : base;

  return {
    vector: normalizeVector(metrics),
    baseScore: base,
    temporalScore: temporal,
    environmentalScore: Number.isNaN(environmental) ? null : environmental,
    overallScore: overall,
    severity: cvssSeverityFromScore(overall),
  };
}

/**
 * Score de base seul — raccourci utilisé par les moteurs de persistance.
 * En cas de vecteur invalide, lève (le moteur décide du fallback honnête).
 */
export function cvss31BaseScore(vector: string): { score: number; severity: CvssSeverity; normalizedVector: string } {
  const r = computeCvss31(vector);
  return { score: r.baseScore, severity: r.severity, normalizedVector: r.vector };
}
