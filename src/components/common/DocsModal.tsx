import React from 'react';

interface DocsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const DocsModal: React.FC<DocsModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 animate-in fade-in duration-200 font-sans">
      <div className="bg-[#171b26] border border-[#24314c] rounded-lg max-w-2xl w-full shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="bg-[#0a0e18] px-5 py-3 border-b border-[#24314c] flex items-center justify-between">
          <div className="flex items-center gap-2 text-[#4cd7f6]">
            <span className="material-symbols-outlined text-[20px]">menu_book</span>
            <span className="font-mono text-xs font-bold uppercase tracking-wider">
              SHADOWSCAN — CAHIER DES CHARGES & DOCTRINE DE SÉCURITÉ
            </span>
          </div>
          <button onClick={onClose} className="text-[#8c909f] hover:text-white" type="button">
            <span className="material-symbols-outlined text-[18px]">close</span>
          </button>
        </div>

        {/* Content */}
        <div className="p-6 flex flex-col gap-5 max-h-[75vh] overflow-y-auto text-xs leading-relaxed text-[#c2c6d6]">
          {/* Section 1 */}
          <div className="flex flex-col gap-2">
            <h3 className="font-bold text-sm text-[#dfe2f1] flex items-center gap-2 font-mono">
              <span className="text-[#4cd7f6]">01.</span>
              PHILOSOPHIE DU PRODUIT
            </h3>
            <p>
              Le logiciel ne doit pas simplement dire : <em>« Une vulnérabilité existe. »</em> Il doit systématiquement répondre à quatre questions :
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-1">
              <div className="bg-[#0a0e18] p-3 rounded border border-[#24314c]">
                <strong className="text-[#4cd7f6] block">1. Qu'est-ce qui est exposé ?</strong>
                <span className="text-[11px] text-[#8c909f]">Surface cartographique, routes d'API, endpoints, headers et technologies.</span>
              </div>
              <div className="bg-[#0a0e18] p-3 rounded border border-[#24314c]">
                <strong className="text-[#4cd7f6] block">2. Quel problème a été détecté ?</strong>
                <span className="text-[11px] text-[#8c909f]">Anomalie structurelle ou faiblesse potentielle dans l'implémentation.</span>
              </div>
              <div className="bg-[#0a0e18] p-3 rounded border border-[#24314c]">
                <strong className="text-[#4cd7f6] block">3. Peut-il être confirmé par un test ?</strong>
                <span className="text-[11px] text-[#8c909f]">Sonde active contrôlée non-destructive apportant la preuve technique réelle.</span>
              </div>
              <div className="bg-[#0a0e18] p-3 rounded border border-[#24314c]">
                <strong className="text-[#4cd7f6] block">4. Que doit faire le développeur ?</strong>
                <span className="text-[11px] text-[#8c909f]">Patchs correctifs concrets (code diff avant / après) et configuration recommandée.</span>
              </div>
            </div>
          </div>

          {/* Section 2 */}
          <div className="flex flex-col gap-2 border-t border-[#24314c] pt-4">
            <h3 className="font-bold text-sm text-[#dfe2f1] flex items-center gap-2 font-mono">
              <span className="text-[#4cd7f6]">02.</span>
              CYCLE DE VALIDATION RIGOUREUSE
            </h3>
            <p>Pour éliminer les faux positifs, chaque finding traverse une chaîne d'états :</p>
            <div className="flex items-center justify-between bg-[#0a0e18] p-2.5 rounded border border-[#24314c] font-mono text-[11px]">
              <span className="text-[#8c909f]">INFO</span>
              <span className="text-[#424754]">→</span>
              <span className="text-[#c0c1ff]">POTENTIAL</span>
              <span className="text-[#424754]">→</span>
              <span className="text-[#4cd7f6]">DETECTED</span>
              <span className="text-[#424754]">→</span>
              <span className="text-[#10b981] font-bold">VALIDATED</span>
            </div>
          </div>

          {/* Section 3 */}
          <div className="flex flex-col gap-2 border-t border-[#24314c] pt-4">
            <h3 className="font-bold text-sm text-[#dfe2f1] flex items-center gap-2 font-mono">
              <span className="text-[#4cd7f6]">03.</span>
              RÈGLE D'ENGAGEMENT SÉCURISÉ (SAFE-SCAN)
            </h3>
            <p>
              Toutes les sondes injectées sont <strong>strictement non-destructives</strong>. Elles n'altèrent pas les bases de données, ne verrouillent aucun compte et n'effectuent pas de saturation de déni de service (DoS).
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="bg-[#0a0e18] px-5 py-3 border-t border-[#24314c] flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 rounded font-mono text-xs bg-[#262a35] hover:bg-[#313540] text-[#dfe2f1]"
          >
            Fermer
          </button>
        </div>
      </div>
    </div>
  );
};
