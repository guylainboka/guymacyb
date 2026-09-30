import React, { useEffect, useState } from 'react';
import { TargetConfig } from '../../types';

interface ActiveTestAuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  /** Renvoie le niveau + le texte exact de l'attestation + l'horodatage (anti-fraude serveur). */
  onConfirm: (level: 'ACTIVE' | 'DESTRUCTIVE', statement: string, confirmedAt: string) => void;
  targetConfig: TargetConfig;
}

/**
 * Modale d'AUTORISATION LÉGALE — obligatoire avant toute sonde réelle.
 * L'opérateur choisit son niveau d'attestation (ACTIVE ou DESTRUCTIVE),
 * lit la déclaration exacte et la certifie. Le texte est renvoyé mot pour
 * mot au serveur qui le vérifie et le journalise (audit_logs).
 */
export const ActiveTestAuthModal: React.FC<ActiveTestAuthModalProps> = ({
  isOpen,
  onClose,
  onConfirm,
  targetConfig,
}) => {
  const [statements, setStatements] = useState<Record<string, string> | null>(null);
  const [level, setLevel] = useState<'ACTIVE' | 'DESTRUCTIVE'>('ACTIVE');
  const [attested, setAttested] = useState<boolean>(false);
  const [loadError, setLoadError] = useState<boolean>(false);

  useEffect(() => {
    if (!isOpen) return;
    setAttested(false);
    setLoadError(false);
    let cancelled = false;
    fetch('/api/authorization/statements')
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((data) => {
        if (!cancelled) setStatements(data);
      })
      .catch(() => {
        if (!cancelled) setLoadError(true);
      });
    return () => {
      cancelled = true;
    };
  }, [isOpen]);

  if (!isOpen) return null;

  const statement = statements?.[level];
  const canConfirm = Boolean(attested && statement);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 animate-in fade-in duration-200">
      <div className="bg-[#171b26] border border-[#ffb4ab]/40 rounded-lg max-w-2xl w-full shadow-2xl overflow-hidden flex flex-col font-sans max-h-[92vh]">
        {/* Modal Header */}
        <div className="bg-[#0a0e18] px-5 py-3 border-b border-[#24314c] flex items-center justify-between">
          <div className="flex items-center gap-2 text-[#ffb4ab]">
            <span className="material-symbols-outlined text-[20px]">gavel</span>
            <span className="font-mono text-xs font-bold uppercase tracking-wider">
              Autorisation légale — tests réels sur la cible
            </span>
          </div>
          <button onClick={onClose} className="text-[#8c909f] hover:text-white transition-colors" type="button">
            <span className="material-symbols-outlined text-[18px]">close</span>
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 flex flex-col gap-4 overflow-y-auto">
          <div className="bg-[#0a0e18] rounded p-3 font-mono text-xs flex flex-col gap-1.5 border border-[#24314c]">
            <div className="flex justify-between items-center">
              <span className="text-[#8c909f]">Cible :</span>
              <span className="text-[#4cd7f6] font-semibold">{targetConfig.url}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-[#8c909f]">Scope :</span>
              <span className="text-[#dfe2f1]">
                {targetConfig.scope === 'wildcard' ? 'Cible + sous-domaines (*)' : `${targetConfig.url} (hôte strict)`}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-[#8c909f]">ID Opérateur :</span>
              <span className="text-[#3b82f6]">{targetConfig.operatorId || 'SEC-OPS-0982'}</span>
            </div>
          </div>

          {/* Avertissement pénal */}
          <div className="p-3 bg-[#93000a]/20 border border-[#ffb4ab]/30 rounded text-xs text-[#ffb4ab] flex items-start gap-2.5">
            <span className="material-symbols-outlined text-[18px] shrink-0 mt-0.5">crisis_alert</span>
            <div>
              <strong className="block font-semibold uppercase tracking-wider text-[11px]">
                AVERTISSEMENT PÉNAL — LISEZ ATTENTIVEMENT
              </strong>
              <p className="mt-1 text-[#ffdad6]/90 leading-relaxed text-[11px]">
                Les sondes qui suivent sont <strong>réelles</strong> : elles envoient de vraies requêtes réseau à la cible.
                Auditer un système sans être propriétaire ou sans autorisation écrite du propriétaire est un{' '}
                <strong>délit pénal</strong> (Code pénal — atteintes aux systèmes de traitement automatisé de données :
                jusqu'à <strong>7 ans d'emprisonnement et 700 000 € d'amende</strong> en bande organisée). Guyma Cyb
                journalise votre attestation (identité, cible, niveau, horodatage, texte exact) de manière immuable.
              </p>
            </div>
          </div>

          {/* Choix du niveau */}
          <div className="flex flex-col gap-2">
            <span className="font-mono text-[11px] text-[#8c909f] uppercase tracking-wider">Niveau d'attestation :</span>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => { setLevel('ACTIVE'); setAttested(false); }}
                className={`p-3 rounded border text-left transition-all ${
                  level === 'ACTIVE'
                    ? 'bg-[#262a35] border-[#4cd7f6] ring-1 ring-[#4cd7f6]/40'
                    : 'bg-[#0a0e18] border-[#24314c] hover:bg-[#1c1f2a]'
                }`}
              >
                <span className="flex items-center gap-2 text-[#dfe2f1] font-bold text-xs font-mono">
                  <span className="material-symbols-outlined text-[16px] text-[#4cd7f6]">bolt</span>
                  ACTIF (non altérant)
                </span>
                <span className="block text-[10px] text-[#8c909f] mt-1 leading-snug">
                  Sondes actives réelles : en-têtes, verbes HTTP, TLS, fuzzing de chemins, détection SQLi/XSS, CORS, mesure de débit.
                </span>
              </button>
              <button
                type="button"
                onClick={() => { setLevel('DESTRUCTIVE'); setAttested(false); }}
                className={`p-3 rounded border text-left transition-all ${
                  level === 'DESTRUCTIVE'
                    ? 'bg-[#262a35] border-[#ffb4ab] ring-1 ring-[#ffb4ab]/40'
                    : 'bg-[#0a0e18] border-[#24314c] hover:bg-[#1c1f2a]'
                }`}
              >
                <span className="flex items-center gap-2 text-[#dfe2f1] font-bold text-xs font-mono">
                  <span className="material-symbols-outlined text-[16px] text-[#ffb4ab]">dangerous</span>
                  AGRESSIF (potentiellement déstructeur)
                </span>
                <span className="block text-[10px] text-[#8c909f] mt-1 leading-snug">
                  Ajoute les scanners actifs complets (nikto) et toute future famille lourde. Safe Mode doit aussi être OFF.
                </span>
              </button>
            </div>
          </div>

          {/* Attestation exacte */}
          {statement ? (
            <label className="flex items-start gap-3 p-3 bg-[#1c1f2a] rounded cursor-pointer border border-[#262a35] hover:border-[#3b82f6]/50 transition-colors select-text">
              <input
                type="checkbox"
                checked={attested}
                onChange={(e) => setAttested(e.target.checked)}
                className="mt-1 w-4 h-4 accent-[#3b82f6] rounded cursor-pointer shrink-0"
              />
              <span className="text-[#dfe2f1] text-[11px] leading-relaxed">{statement}</span>
            </label>
          ) : loadError ? (
            <span className="text-[#ffb4ab] font-mono text-[11px]">
              Déclaration légale indisponible (backend injoignable) — les tests réels restent bloqués. C'est un garde-fou volontaire.
            </span>
          ) : (
            <span className="text-[#8c909f] font-mono text-[11px]">Chargement de la déclaration légale…</span>
          )}
        </div>

        {/* Modal Footer Actions */}
        <div className="bg-[#0a0e18] px-5 py-3 border-t border-[#24314c] flex items-center justify-end gap-3">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 rounded font-mono text-xs text-[#c2c6d6] hover:bg-[#262a35] transition-colors"
          >
            Annuler
          </button>
          <button
            type="button"
            disabled={!canConfirm}
            onClick={() =>
              canConfirm &&
              statement &&
              onConfirm(level, statement, new Date().toISOString())
            }
            className={`flex items-center gap-2 px-5 py-2 rounded font-mono text-xs font-bold uppercase tracking-wider transition-all shadow-md ${
              canConfirm
                ? 'bg-[#93000a] hover:bg-[#ff5449] text-white shadow-red-950/50'
                : 'bg-[#262a35] text-[#8c909f] cursor-not-allowed'
            }`}
          >
            <span className="material-symbols-outlined text-[16px]">bolt</span>
            <span>[ LANCER LES TESTS RÉELS ]</span>
          </button>
        </div>
      </div>
    </div>
  );
};
