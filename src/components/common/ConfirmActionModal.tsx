import React from 'react';

/**
 * ConfirmActionModal — L'AVERTISSEMENT UNIQUE (V2).
 *
 * Règle produit demandée par l'opérateur : « pas de choix un puis deux, juste
 * UNE seule [action] mais avec avertissement ». Ce modal est CET avertissement :
 * un seul écran d'accord avant l'exécution directe de l'action complète.
 * Aucune étape supplémentaire, aucune sélection multiple — Confirmer → tout
 * s'exécute d'un bloc.
 */
interface ConfirmActionModalProps {
  open: boolean;
  /** Titre court (ex. « Avertissement — action unique »). */
  title: string;
  /** Corps : description RÉELLE de ce qui va se passer (aucune invention). */
  children: React.ReactNode;
  confirmLabel: string;
  cancelLabel?: string;
  /** Pendant l'exécution, on interdit la fermeture accidentelle. */
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export const ConfirmActionModal: React.FC<ConfirmActionModalProps> = ({
  open,
  title,
  children,
  confirmLabel,
  cancelLabel = 'Annuler',
  busy = false,
  onConfirm,
  onCancel,
}) => {
  if (!open) return null;
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      onClick={() => { if (!busy) onCancel(); }}
    >
      <div
        className="w-full max-w-lg rounded-lg border border-amber-500/40 bg-[#171b26] p-5 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-3 flex items-center gap-2">
          <span className="material-symbols-outlined text-[22px] text-amber-400">warning</span>
          <h3 className="text-sm font-semibold text-[#dfe2f1]">{title}</h3>
        </div>
        {children}
        <div className="mt-4 flex justify-end gap-2">
          <button
            onClick={onCancel}
            disabled={busy}
            className="rounded border border-[#24314c] bg-[#0a0e18] px-4 py-2 text-sm text-[#c2c6d6] transition-colors hover:border-[#4d8eff]/50 disabled:opacity-50"
            type="button"
          >
            {cancelLabel}
          </button>
          <button
            onClick={onConfirm}
            disabled={busy}
            className="flex items-center gap-2 rounded bg-[#4d8eff] px-4 py-2 text-sm font-semibold text-[#0a0e18] transition-colors hover:bg-[#6da4ff] disabled:opacity-50"
            type="button"
          >
            <span className="material-symbols-outlined text-[16px]">bolt</span>
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
};
