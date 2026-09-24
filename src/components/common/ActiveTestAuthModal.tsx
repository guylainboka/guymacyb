import React, { useState } from 'react';
import { TargetConfig } from '../../types';

interface ActiveTestAuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  targetConfig: TargetConfig;
}

export const ActiveTestAuthModal: React.FC<ActiveTestAuthModalProps> = ({
  isOpen,
  onClose,
  onConfirm,
  targetConfig,
}) => {
  const [isAuthorizedChecked, setIsAuthorizedChecked] = useState<boolean>(true);
  const [operatorInitials, setOperatorInitials] = useState<string>('SEC-OPS-0982');

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 animate-in fade-in duration-200">
      <div className="bg-[#171b26] border border-[#ffb4ab]/40 rounded-lg max-w-lg w-full shadow-2xl overflow-hidden flex flex-col font-sans">
        {/* Modal Header */}
        <div className="bg-[#0a0e18] px-5 py-3 border-b border-[#24314c] flex items-center justify-between">
          <div className="flex items-center gap-2 text-[#ffb4ab]">
            <span className="material-symbols-outlined text-[20px]">warning</span>
            <span className="font-mono text-xs font-bold uppercase tracking-wider">
              ACTIVE SECURITY TEST AUTHORIZATION
            </span>
          </div>
          <button
            onClick={onClose}
            className="text-[#8c909f] hover:text-white transition-colors"
            type="button"
          >
            <span className="material-symbols-outlined text-[18px]">close</span>
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 flex flex-col gap-4">
          <div className="bg-[#0a0e18] rounded p-3 font-mono text-xs flex flex-col gap-2 border border-[#24314c]">
            <div className="flex justify-between items-center">
              <span className="text-[#8c909f]">Target :</span>
              <span className="text-[#4cd7f6] font-semibold">{targetConfig.url}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-[#8c909f]">Scope :</span>
              <span className="text-[#dfe2f1]">
                {targetConfig.scope === 'wildcard' ? '*.example.com (Cible + Sous-domaines)' : `${targetConfig.url}/*`}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-[#8c909f]">ID Opérateur :</span>
              <span className="text-[#3b82f6]">{operatorInitials}</span>
            </div>
          </div>

          {/* Authorization Checkbox */}
          <label className="flex items-start gap-3 p-3 bg-[#1c1f2a] rounded cursor-pointer border border-[#262a35] hover:border-[#3b82f6]/50 transition-colors">
            <input
              type="checkbox"
              checked={isAuthorizedChecked}
              onChange={(e) => setIsAuthorizedChecked(e.target.checked)}
              className="mt-0.5 w-4 h-4 accent-[#3b82f6] rounded cursor-pointer"
            />
            <div className="flex flex-col text-xs">
              <span className="text-[#dfe2f1] font-medium">
                I am authorized to test this application / Je certifie être autorisé
              </span>
              <span className="text-[#8c909f] text-[11px] mt-0.5">
                Je confirme détenir le mandat formel de sécurité ou tester une application locale de laboratoire.
              </span>
            </div>
          </label>

          {/* Warning Banner */}
          <div className="p-3 bg-[#93000a]/20 border border-[#ffb4ab]/30 rounded text-xs text-[#ffb4ab] flex items-start gap-2.5">
            <span className="material-symbols-outlined text-[18px] shrink-0 mt-0.5">crisis_alert</span>
            <div>
              <strong className="block font-semibold uppercase tracking-wider text-[11px]">
                WARNING — TESTS ACTIFS CONTRÔLÉS
              </strong>
              <p className="mt-1 text-[#ffdad6]/90 leading-relaxed text-[11px]">
                Les tests actifs génèrent des requêtes réelles avec sondes contextuelles (SQLi, IDOR, verbes HTTP, bypass auth). Les sondes sont strictement non-destructives et ne suppriment aucune donnée.
              </p>
            </div>
          </div>
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
            disabled={!isAuthorizedChecked}
            onClick={() => {
              if (isAuthorizedChecked) {
                onConfirm();
                onClose();
              }
            }}
            className={`flex items-center gap-2 px-5 py-2 rounded font-mono text-xs font-bold uppercase tracking-wider transition-all shadow-md ${
              isAuthorizedChecked
                ? 'bg-[#93000a] hover:bg-[#ff5449] text-white shadow-red-950/50'
                : 'bg-[#262a35] text-[#8c909f] cursor-not-allowed'
            }`}
          >
            <span className="material-symbols-outlined text-[16px]">bolt</span>
            <span>[ START TEST ]</span>
          </button>
        </div>
      </div>
    </div>
  );
};
