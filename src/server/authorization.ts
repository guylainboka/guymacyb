import { getDatabase, saveDatabaseToDisk } from './db';

// ============================================================
//  Modèle d'autorisation d'audit — Guyma Cyb
// ============================================================
//
// Doctrine de la plateforme : des tests RÉELS, y compris agressifs /
// potentiellement déstructeurs, encadrés par une ATTESTATION EXPLICITE
// de l'opérateur. Tester un système sans autorisation est un délit
// (en France : articles 323-1 à 323-7 du Code pénal — atteintes aux
// systèmes de traitement automatisé de données, jusqu'à 7 ans
// d'emprisonnement et 700 000 € d'amende en bande organisée).
//
// Chaque attestation est validée côté serveur puis journalisée de
// façon immuable dans SQLite (table audit_logs) avec l'identité de
// l'opérateur, la cible, le niveau et le texte exact de l'attestation.

export type AuthorizationLevel = 'ACTIVE' | 'DESTRUCTIVE';

export interface TestAuthorization {
  operatorId: string;
  targetUrl: string;
  level: AuthorizationLevel;
  /** Texte EXACT de l'attestation cochée par l'opérateur (prouvé côté serveur). */
  statement: string;
  /** Horodatage ISO du clic de confirmation côté client. */
  confirmedAt: string;
}

/**
 * Déclarations légales exactes que l'opérateur doit cocher dans l'UI.
 * Le serveur vérifie que le champ `statement` de la requête correspond
 * mot pour mot — une case cochée sans le texte exact est rejetée.
 */
export const AUTHORIZATION_STATEMENTS: Record<AuthorizationLevel, string> = {
  ACTIVE:
    "Je certifie être le propriétaire de la cible ou détenir une autorisation écrite du propriétaire pour réaliser des tests de sécurité actifs sur celle-ci. Je comprends que les sondes envoyées sont réelles et qu'auditer un système sans autorisation constitue un délit pénal (Code pénal — atteintes aux systèmes de traitement automatisé de données). J'assume l'entière responsabilité légale de cette opération.",
  DESTRUCTIVE:
    "Je certifie être le propriétaire de la cible ou détenir une autorisation écrite EXPLICITE couvrant les tests AGRESSIFS potentiellement déstructeurs (scanners actifs complets, fuzzing intensif, attaques par force brute). Je comprends que ces opérations peuvent altérer ou interrompre le service audité et qu'auditer un système sans autorisation constitue un délit pénal (Code pénal — atteintes aux systèmes de traitement automatisé de données). J'assume l'entière responsabilité légale de cette opération.",
};

export type AuthorizationValidation =
  | { ok: true; authorization: TestAuthorization }
  | { ok: false; reason: string };

/**
 * Valide l'attestation contenue dans le corps d'une requête.
 * Requiert : operatorId, targetUrl, level attendu, statement identique
 * au texte officiel, confirmedAt ISO plausible.
 */
export function validateAuthorization(
  body: any,
  expectedLevel: AuthorizationLevel,
  fallbackTargetUrl?: string
): AuthorizationValidation {
  if (!body || typeof body !== 'object') {
    return { ok: false, reason: 'Corps de requête manquant — attestation requise.' };
  }
  const { operatorId, targetUrl, level, statement, confirmedAt } = body.authorization || {};

  if (!operatorId || typeof operatorId !== 'string' || operatorId.trim().length < 3) {
    return { ok: false, reason: 'Attestation invalide : operatorId manquant ou trop court.' };
  }
  if (level !== 'ACTIVE' && level !== 'DESTRUCTIVE') {
    return {
      ok: false,
      reason: `Attestation invalide : niveau inconnu « ${String(level ?? 'aucun')} » (attendu ACTIVE ou DESTRUCTIVE).`,
    };
  }
  const officialStatement = AUTHORIZATION_STATEMENTS[level as AuthorizationLevel];
  const resolvedTarget = targetUrl || fallbackTargetUrl;
  if (!resolvedTarget || typeof resolvedTarget !== 'string') {
    return { ok: false, reason: 'Attestation invalide : cible (targetUrl) manquante.' };
  }
  if (level !== expectedLevel) {
    return {
      ok: false,
      reason: `Attestation invalide : niveau requis « ${expectedLevel} », reçu « ${level ?? 'aucun'} ». ${
        expectedLevel === 'DESTRUCTIVE'
          ? "Les familles déstructrices exigent l'attestation AGRESSIVE complète."
          : ''
      }`,
    };
  }
  if (statement !== officialStatement) {
    return {
      ok: false,
      reason:
        "Attestation invalide : le texte exact de la déclaration officielle doit être renvoyé mot pour mot (anti-fraude). Rechargez la modale d'autorisation.",
    };
  }
  const confirmed = new Date(confirmedAt);
  if (Number.isNaN(confirmed.getTime())) {
    return { ok: false, reason: 'Attestation invalide : horodatage de confirmation manquant ou incorrect.' };
  }

  return {
    ok: true,
    authorization: {
      operatorId: operatorId.trim(),
      targetUrl: resolvedTarget,
      level: level as AuthorizationLevel,
      statement,
      confirmedAt: confirmed.toISOString(),
    },
  };
}

/**
 * Journalise l'attestation validée dans SQLite (audit_logs) — trace légale
 * immuable : qui, quoi, quand, à quel niveau, avec quel texte exact.
 */
export async function recordAuthorization(auth: TestAuthorization): Promise<void> {
  try {
    const db = await getDatabase();
    db.run(
      `INSERT INTO audit_logs (id, timestamp, tag, text, operator_id)
       VALUES (?, datetime('now'), ?, ?, ?)`,
      [
        `log-auth-${Date.now()}-${Math.abs(hashString(auth.targetUrl + auth.level + auth.confirmedAt))}`,
        'AUTHORIZATION',
        JSON.stringify({
          event: 'ATTESTATION_ENREGISTREE',
          target: auth.targetUrl,
          level: auth.level,
          confirmedAt: auth.confirmedAt,
          statement: auth.statement,
        }),
        auth.operatorId,
      ]
    );
    saveDatabaseToDisk(db);
  } catch (err) {
    // Ne jamais bloquer l'opération d'audit pour un échec de journalisation,
    // mais le signaler clairement dans les logs serveur.
    console.error('[Authorization] Échec de journalisation de l\'attestation:', err);
  }
}

function hashString(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  }
  return h;
}
