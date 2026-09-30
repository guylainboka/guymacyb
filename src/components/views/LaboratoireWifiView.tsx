import React, { useState, useEffect } from 'react';
import { WifiLabVector, WifiAttackCategory, TargetConfig } from '../../types';
import { ActiveTestAuthModal } from '../common/ActiveTestAuthModal';

interface LaboratoireWifiViewProps {
  onGoToCours: () => void;
}

const CATEGORY_LABEL: Record<string, { label: string; icon: string; color: string }> = {
  WIFI_DEAUTH:     { label: 'Déauthentification',  icon: 'block',          color: 'text-rose-400 bg-rose-500/10 border-rose-500/30' },
  WIFI_EVIL_TWIN:  { label: 'Evil Twin',           icon: 'wifi_calling',   color: 'text-rose-400 bg-rose-500/10 border-rose-500/30' },
  WIFI_KRACK:      { label: 'KRACK (WPA2)',        icon: 'no_encryption',  color: 'text-amber-400 bg-amber-500/10 border-amber-500/30' },
  WIFI_WPS:        { label: 'WPS (PIN)',           icon: 'pin',            color: 'text-amber-400 bg-amber-500/10 border-amber-500/30' },
  WIFI_HANDSHAKE:  { label: 'Handshake/PMKID',     icon: 'key',            color: 'text-sky-400 bg-sky-500/10 border-sky-500/30' },
  WIFI_DOWNGRADE:  { label: 'Downgrade WPA3',      icon: 'downloading',    color: 'text-amber-400 bg-amber-500/10 border-amber-500/30' },
};

/**
 * Procédures RÉELLES : chaque vecteur est relié à l'outil WiFi réel du
 * backend (/api/wifi/* — aircrack-ng suite, iw, reaver, hostapd… via WSL).
 * Sans matériel radio réel, les outils renvoient des erreurs honnêtes
 * (mode: no-wireless-hardware) — aucune donnée WiFi n'est fabriquée.
 *
 * authLevel = niveau d'ATTESTATION LÉGALE exigé avant l'appel (source de
 * vérité serveur : GET /api/wifi/auth-requirements) — null = outil passif
 * de détection/audit, sans attestation obligatoire.
 */
interface RealProcedure {
  endpoint: string;
  note: string;
  authLevel: 'ACTIVE' | 'DESTRUCTIVE' | null;
  params: { key: string; label: string; placeholder: string }[];
}
const REAL_PROCEDURES: Record<string, RealProcedure | null> = {
  'wifi-deauth-flood': {
    endpoint: '/api/wifi/deauth-detect',
    note: 'Détection IDS réelle des trames de désauthentification sur votre interface monitor (sur votre propre réseau autorisé).',
    authLevel: null,
    params: [{ key: 'iface', label: 'Interface monitor', placeholder: 'wlan0mon' }],
  },
  'wifi-evil-twin': {
    endpoint: '/api/wifi/evil-twin',
    note: 'Evil Twin RÉEL (hostapd + dnsmasq) : un vrai point d\'accès usurpé émet votre SSID et un vrai DHCP répond aux clients associés. ATTESTATION DESTRUCTIVE OBLIGATOIRE — n\'usurpez QUE le SSID de VOTRE propre réseau de test.',
    authLevel: 'DESTRUCTIVE',
    params: [
      { key: 'ssid', label: 'SSID à usurper (réseau autorisé)', placeholder: 'MonReseau-Test' },
      { key: 'channel', label: 'Canal', placeholder: '6' },
      { key: 'iface', label: 'Interface monitor', placeholder: 'wlan0mon' },
    ],
  },
  'wifi-krack': {
    endpoint: '/api/wifi/wpa-audit',
    note: 'Audit WPA réel de la cible (versions supportées, PMF) — la vulnérabilité KRACK dépend des correctifs du client.',
    authLevel: null,
    params: [
      { key: 'target', label: 'ESSID cible', placeholder: 'MonReseau' },
      { key: 'iface', label: 'Interface', placeholder: 'wlan0mon' },
    ],
  },
  'wifi-wps-pixie': {
    endpoint: '/api/wifi/wps-attack',
    note: 'Attaque WPS Pixie Dust réelle (reaver) — UNIQUEMENT sur votre propre point d\'accès autorisé.',
    authLevel: 'DESTRUCTIVE',
    params: [
      { key: 'bssid', label: 'BSSID cible', placeholder: 'AA:BB:CC:DD:EE:FF' },
      { key: 'iface', label: 'Interface monitor', placeholder: 'wlan0mon' },
    ],
  },
  'wifi-wps-brute': {
    endpoint: '/api/wifi/wps-attack',
    note: 'Attaque WPS PIN réelle (reaver) — UNIQUEMENT sur votre propre point d\'accès autorisé.',
    authLevel: 'DESTRUCTIVE',
    params: [
      { key: 'bssid', label: 'BSSID cible', placeholder: 'AA:BB:CC:DD:EE:FF' },
      { key: 'iface', label: 'Interface monitor', placeholder: 'wlan0mon' },
    ],
  },
  'wifi-pmkid-capture': {
    endpoint: '/api/wifi/handshake-capture',
    note: 'Capture réelle (airodump-ng) du 4-way handshake / PMKID sur le réseau autorisé.',
    authLevel: 'ACTIVE',
    params: [
      { key: 'bssid', label: 'BSSID cible', placeholder: 'AA:BB:CC:DD:EE:FF' },
      { key: 'channel', label: 'Canal', placeholder: '6' },
      { key: 'iface', label: 'Interface monitor', placeholder: 'wlan0mon' },
    ],
  },
  'wifi-handshake-capture': {
    endpoint: '/api/wifi/handshake-capture',
    note: 'Capture réelle (airodump-ng) du 4-way handshake sur le réseau autorisé.',
    authLevel: 'ACTIVE',
    params: [
      { key: 'bssid', label: 'BSSID cible', placeholder: 'AA:BB:CC:DD:EE:FF' },
      { key: 'channel', label: 'Canal', placeholder: '6' },
      { key: 'iface', label: 'Interface monitor', placeholder: 'wlan0mon' },
    ],
  },
  'wifi-downgrade-wpa3': {
    endpoint: '/api/wifi/wpa-audit',
    note: 'Audit WPA réel : vérifie les mécanismes de transition WPA3/WPA2 et PMF (protection contre le downgrade).',
    authLevel: null,
    params: [
      { key: 'target', label: 'ESSID cible', placeholder: 'MonReseau' },
      { key: 'iface', label: 'Interface', placeholder: 'wlan0mon' },
    ],
  },
};

export const LaboratoireWifiView: React.FC<LaboratoireWifiViewProps> = ({
  onGoToCours,
}) => {
  const [vectors, setVectors] = useState<WifiLabVector[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<WifiLabVector | null>(null);
  const [filter, setFilter] = useState<string>('ALL');
  const [activeTab, setActiveTab] = useState<'fiche' | 'procedure' | 'code'>('fiche');
  const [isRunning, setIsRunning] = useState(false);
  const [realResult, setRealResult] = useState<any | null>(null);
  const [paramValues, setParamValues] = useState<Record<string, string>>({});
  const [toast, setToast] = useState<string | null>(null);
  // Autorisation légale : procédure en attente de confirmation d'attestation
  const [pendingAuth, setPendingAuth] = useState<{ procedure: RealProcedure; level: 'ACTIVE' | 'DESTRUCTIVE' } | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch('/api/wifi/lab/vectors')
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((data) => {
        if (cancelled) return;
        setVectors(Array.isArray(data) ? data : []);
        if (Array.isArray(data) && data.length > 0) setSelected(data[0]);
        setLoading(false);
      })
      .catch(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const showToast = (m: string) => { setToast(m); setTimeout(() => setToast(null), 4500); };

  const filtered = vectors.filter((v) => filter === 'ALL' || v.category === filter);

  /** Exécution réseau réelle — appelée APRÈS confirmation d'attestation si requise. */
  const executeProcedure = async (procedure: RealProcedure, level: 'ACTIVE' | 'DESTRUCTIVE', statement: string, confirmedAt: string) => {
    if (!selected) return;
    setIsRunning(true);
    setRealResult(null);
    try {
      const body: Record<string, unknown> = {};
      for (const p of procedure.params) {
        if (paramValues[p.key] !== undefined && paramValues[p.key] !== '') body[p.key] = paramValues[p.key];
      }
      // Clés normalisées attendues par le backend selon l'outil
      if (procedure.endpoint === '/api/wifi/deauth-detect') body.interface = body.iface;
      if (procedure.endpoint === '/api/wifi/wpa-audit') body.interface = body.iface;
      if (procedure.endpoint === '/api/wifi/handshake-capture') body.interface = body.iface;
      if (procedure.endpoint === '/api/wifi/evil-twin') body.interface = body.iface;
      if (procedure.endpoint === '/api/wifi/wps-attack') body.interface = body.iface;
      if (procedure.authLevel) {
        const target = String(body.bssid || body.ssid || body.target || body.iface || 'cible-wifi');
        body.authorization = {
          operatorId: 'SEC-OPS-0982',
          targetUrl: target,
          level,
          statement,
          confirmedAt,
        };
      }
      const res = await fetch(procedure.endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({ error: 'Réponse illisible du backend' }));
      setRealResult(data);
      if (res.status === 403 && data?.attestationRequired) {
        showToast('Attestation rejetée par le serveur : rechargez la modale d\'autorisation et confirmez la déclaration exacte.');
      } else if (!res.ok || data?.error || data?.mode === 'no-wireless-hardware') {
        showToast(
          data?.mode === 'no-wireless-hardware'
            ? 'Matériel radio absent : branchez une clé WiFi mode monitor (AR9271 / 88XXAU) pour exécuter réellement cette procédure.'
            : `Outil réel terminé avec erreur : ${data?.error || data?.mode || `HTTP ${res.status}`}`
        );
      } else {
        showToast('Procédure réelle exécutée — résultat brut de l\'outil affiché ci-dessous.');
      }
    } catch (err: any) {
      showToast(`Échec de la procédure réelle : ${err?.message || 'API injoignable'}`);
    } finally {
      setIsRunning(false);
    }
  };

  const runRealProcedure = () => {
    if (!selected) return;
    const procedure = REAL_PROCEDURES[selected.id];
    if (!procedure) {
      showToast('Aucune procédure automatisée pour ce vecteur — suivez la procédure manuelle de la fiche.');
      return;
    }
    // Garde-fou légal : attestation obligatoire AVANT tout outil agressif.
    if (procedure.authLevel) {
      setPendingAuth({ procedure, level: procedure.authLevel });
      return;
    }
    void executeProcedure(procedure, 'ACTIVE', '', '');
  };

  const wifiTargetConfig: TargetConfig = {
    url: String(
      paramValues.bssid || paramValues.ssid || paramValues.target || paramValues.iface || 'cible-wifi'
    ),
    port: 0,
    scope: 'strict',
    authorized: false,
    operatorId: 'SEC-OPS-0982',
    localDbName: 'guymacyb',
  };

  if (loading) {
    return (
      <div className="h-full flex items-center justify-center bg-[#0a0e18] text-[#8c909f]">
        <div className="flex items-center gap-3">
          <span className="material-symbols-outlined animate-spin">progress_activity</span>
          Chargement du laboratoire WiFi...
        </div>
      </div>
    );
  }

  const selectedProcedure = selected ? REAL_PROCEDURES[selected.id] : null;

  return (
    <div className="h-full overflow-y-auto bg-[#0a0e18] text-[#dfe2f1] p-6">
      {/* Modale d'autorisation légale — obligatoire avant tout outil agressif */}
      <ActiveTestAuthModal
        isOpen={pendingAuth !== null}
        onClose={() => setPendingAuth(null)}
        targetConfig={wifiTargetConfig}
        onConfirm={(level, statement, confirmedAt) => {
          const pending = pendingAuth;
          setPendingAuth(null);
          if (pending) void executeProcedure(pending.procedure, level, statement, confirmedAt);
        }}
      />
      {toast && (
        <div className="fixed top-24 right-6 z-50 px-4 py-2 bg-[#171b26] border border-[#4cd7f6]/50 rounded text-sm text-[#dfe2f1] shadow-lg backdrop-blur max-w-md">
          {toast}
        </div>
      )}
      <div className="max-w-7xl mx-auto">
        {/* En-tête */}
        <div className="mb-5 flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <span className="material-symbols-outlined text-rose-400">science</span>
              Laboratoire WiFi — Procédures Réelles
            </h1>
            <p className="text-sm text-[#8c909f] mt-1">
              {vectors.length} fiches techniques WiFi (WPA, WPA2, WPA3, WPS, Evil Twin, KRACK…) reliées aux outils réels
              (aircrack-ng, reaver, iw) exécutés via WSL. Sans matériel radio, les outils le signalent honnêtement.
            </p>
          </div>
          <button
            onClick={onGoToCours}
            className="px-3 py-1.5 text-xs rounded bg-[#171b26] border border-[#24314c] hover:border-sky-500/50 text-[#c2c6d6] flex items-center gap-1.5 transition-colors"
            type="button"
          >
            <span className="material-symbols-outlined text-[16px]">school</span>
            Cours
          </button>
        </div>

        {/* Avertissement légal permanent */}
        <div className="mb-4 p-3 bg-[#93000a]/10 border border-[#ffb4ab]/30 rounded flex items-start gap-2.5 text-[11px] text-[#ffb4ab]">
          <span className="material-symbols-outlined text-[18px] shrink-0">gavel</span>
          <span className="leading-relaxed">
            <strong>AVERTISSEMENT :</strong> les procédures WiFi ci-dessous sont réelles et peuvent être déstructrices.
            Ne les exécutez QUE sur votre propre réseau ou avec l'autorisation écrite du propriétaire. Auditer un réseau
            sans autorisation est un délit pénal (Code pénal — atteintes aux STAD, jusqu'à 7 ans et 700 000 € d'amende).
          </span>
        </div>

        {/* Filtres */}
        <div className="flex flex-wrap gap-1.5 mb-4">
          <button
            onClick={() => setFilter('ALL')}
            className={`px-2.5 py-1 text-[11px] rounded border font-mono transition-colors ${filter === 'ALL' ? 'bg-rose-500/20 border-rose-500/50 text-rose-400' : 'bg-[#171b26] border-[#24314c] text-[#8c909f] hover:text-[#dfe2f1]'}`}
            type="button"
          >Tous ({vectors.length})</button>
          {Object.entries(CATEGORY_LABEL).map(([k, m]) => {
            const count = vectors.filter(v => v.category === k).length;
            if (count === 0) return null;
            return (
              <button
                key={k}
                onClick={() => setFilter(k)}
                className={`px-2.5 py-1 text-[11px] rounded border font-mono transition-colors flex items-center gap-1 ${filter === k ? 'bg-rose-500/20 border-rose-500/50 text-rose-400' : 'bg-[#171b26] border-[#24314c] text-[#8c909f] hover:text-[#dfe2f1]'}`}
                type="button"
              >
                <span className="material-symbols-outlined text-[13px]">{m.icon}</span>
                {m.label} ({count})
              </button>
            );
          })}
        </div>

        <div className="grid grid-cols-12 gap-4">
          {/* Catalogue */}
          <div className="col-span-12 lg:col-span-5 bg-[#171b26] border border-[#24314c] rounded-lg flex flex-col overflow-hidden">
            <div className="px-3 py-2.5 bg-[#0a0e18] border-b border-[#24314c] flex items-center justify-between">
              <span className="font-mono text-xs font-bold uppercase tracking-wider">Fiches techniques ({filtered.length})</span>
              <span className="text-[10px] text-[#8c909f] font-mono">MITRE ATT&amp;CK Wireless</span>
            </div>
            <div className="flex-1 overflow-y-auto p-3 flex flex-col gap-2">
              {filtered.map((v) => {
                const proc = REAL_PROCEDURES[v.id];
                return (
                  <div
                    key={v.id}
                    onClick={() => { setSelected(v); setRealResult(null); setParamValues({}); setActiveTab(proc ? 'procedure' : 'fiche'); }}
                    className={`p-3 rounded border cursor-pointer transition-all ${
                      selected?.id === v.id
                        ? 'bg-[#262a35] border-[#4cd7f6] ring-1 ring-[#4cd7f6]/40'
                        : 'bg-[#0a0e18] border-[#24314c] hover:bg-[#1c1f2a]'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <span className="text-[10px] text-[#8c909f] font-mono">{v.mitre}</span>
                        <strong className="block text-xs text-white">{v.name}</strong>
                      </div>
                      <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold border ${CATEGORY_LABEL[v.category]?.color ?? 'bg-[#262a35] text-[#8c909f] border-[#24314c]'}`}>
                        {CATEGORY_LABEL[v.category]?.label ?? v.category}
                      </span>
                    </div>
                    <div className="flex items-center justify-between mt-1.5 pt-1.5 border-t border-[#24314c]/60 text-[10px]">
                      <span className="text-[#8c909f]">{v.targetEncryption} • difficulté {v.difficulty}</span>
                      <span className={proc ? 'text-[#34d399] font-bold' : 'text-[#64748b]'}>
                        {proc ? 'Procédure réelle dispo' : 'Fiche + procédure manuelle'}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Détail */}
          <div className="col-span-12 lg:col-span-7 bg-[#171b26] border border-[#24314c] rounded-lg flex flex-col overflow-hidden">
            {selected ? (
              <>
                <div className="px-4 py-3 bg-[#0a0e18] border-b border-[#24314c]">
                  <h2 className="text-sm font-bold text-white font-mono">{selected.name}</h2>
                  <div className="text-[11px] text-[#8c909f] font-mono mt-0.5">
                    {selected.mitre} • cible {selected.targetEncryption} • {selected.severity}
                  </div>
                  <div className="flex gap-2 mt-2.5 font-mono text-[11px]">
                    {([
                      ['fiche', 'description', 'Fiche technique'],
                      ['procedure', 'play_circle', 'Procédure réelle'],
                      ['code', 'code', 'Code Avant / Après'],
                    ] as const).map(([key, icon, label]) => (
                      <button
                        key={key}
                        type="button"
                        onClick={() => setActiveTab(key)}
                        className={`px-3 py-1 rounded flex items-center gap-1.5 transition-all ${
                          activeTab === key
                            ? 'bg-[#262a35] text-[#4cd7f6] font-bold border border-[#4cd7f6]/40'
                            : 'text-[#8c909f] hover:text-white'
                        }`}
                      >
                        <span className="material-symbols-outlined text-[14px]">{icon}</span>
                        {label}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-3 text-xs">
                  {activeTab === 'fiche' && (
                    <>
                      {selected.cvssVector && (
                        <div className="bg-[#0a0e18] border border-[#24314c] rounded p-3 font-mono">
                          <div className="flex items-center justify-between gap-2 flex-wrap">
                            <span className="text-[11px] text-[#4cd7f6] font-bold">CVSS v3.1 — score CALCULÉ du vecteur :</span>
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                              (selected.cvssSeverity ?? '') === 'CRITICAL'
                                ? 'bg-[#93000a]/30 border-[#ffb4ab]/50 text-[#ffb4ab]'
                                : (selected.cvssSeverity ?? '') === 'HIGH'
                                  ? 'bg-orange-500/15 border-orange-500/40 text-orange-400'
                                  : 'bg-amber-500/10 border-amber-500/40 text-amber-400'
                            }`}>
                              {selected.cvssScore ?? '—'} {(selected.cvssSeverity ?? '').toUpperCase()}
                            </span>
                          </div>
                          <code className="block mt-2 text-[10px] text-[#c2c6d6] select-text break-all">{selected.cvssVectorNormalized || selected.cvssVector}</code>
                          <p className="mt-1.5 text-[9px] text-[#8c909f] leading-relaxed">
                            Score dérivé des métriques AV/AC/PR/UI/S/C/I/A par le calculateur v3.1 conforme FIRST (base, temporel, environnemental) — jamais d'une bande de sévérité.
                          </p>
                        </div>
                      )}
                      <div className="bg-[#0a0e18] border border-[#24314c] rounded p-3">
                        <span className="text-[11px] text-[#4cd7f6] font-bold font-mono">Principe :</span>
                        <p className="text-[#c2c6d6] mt-1 leading-relaxed">{selected.description}</p>
                      </div>
                      <div className="bg-[#0a0e18] border border-[#24314c] rounded p-3">
                        <span className="text-[11px] text-[#4cd7f6] font-bold font-mono">Scénario d'attaque :</span>
                        <p className="text-[#c2c6d6] mt-1 leading-relaxed">{selected.attackScenario}</p>
                      </div>
                      <div className="bg-[#0a0e18] border border-[#24314c] rounded p-3">
                        <span className="text-[11px] text-[#34d399] font-bold font-mono">Contremesures (Blue Team) :</span>
                        <ul className="mt-1.5 flex flex-col gap-1 list-disc list-inside text-[#c2c6d6]">
                          {selected.defensiveControls.map((c, i) => <li key={i}>{c}</li>)}
                        </ul>
                      </div>
                    </>
                  )}

                  {activeTab === 'procedure' && (
                    <>
                      {selectedProcedure ? (
                        <>
                          <div className="bg-[#0a0e18] border border-[#24314c] rounded p-3 text-[#c2c6d6] leading-relaxed">
                            <span className="text-[11px] text-[#ffb4ab] font-bold font-mono">Procédure réelle — outil backend :</span>
                            <p className="mt-1">{selectedProcedure.note}</p>
                            <code className="block mt-2 text-[10px] text-[#4cd7f6]">{selectedProcedure.endpoint}</code>
                            {selectedProcedure.authLevel && (
                              <div className="mt-2 inline-flex items-center gap-1.5 px-2 py-1 rounded bg-[#93000a]/20 border border-[#ffb4ab]/40 text-[10px] text-[#ffb4ab] font-bold font-mono">
                                <span className="material-symbols-outlined text-[13px]">gavel</span>
                                ATTESTATION {selectedProcedure.authLevel === 'DESTRUCTIVE' ? 'AGRESSIVE (DESTRUCTIVE)' : 'ACTIVE'} OBLIGATOIRE
                              </div>
                            )}
                          </div>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            {selectedProcedure.params.map((p) => (
                              <label key={p.key} className="flex flex-col gap-1 font-mono">
                                <span className="text-[10px] text-[#8c909f]">{p.label}</span>
                                <input
                                  type="text"
                                  value={paramValues[p.key] || ''}
                                  onChange={(e) => setParamValues((prev) => ({ ...prev, [p.key]: e.target.value }))}
                                  placeholder={p.placeholder}
                                  className="bg-[#171b26] border border-[#24314c] rounded px-2 py-1.5 text-[11px] text-[#dfe2f1] focus:outline-none focus:border-[#4cd7f6]/60 select-text"
                                />
                              </label>
                            ))}
                          </div>
                          <button
                            type="button"
                            onClick={runRealProcedure}
                            disabled={isRunning}
                            className={`self-start px-4 py-2 rounded text-white font-bold flex items-center gap-2 disabled:opacity-50 transition-colors ${
                              selectedProcedure.authLevel === 'DESTRUCTIVE'
                                ? 'bg-[#93000a] hover:bg-[#ff5449]'
                                : selectedProcedure.authLevel === 'ACTIVE'
                                  ? 'bg-amber-600 hover:bg-amber-500'
                                  : 'bg-rose-600 hover:bg-rose-500'
                            }`}
                          >
                            <span className={`material-symbols-outlined text-[16px] ${isRunning ? 'animate-spin' : ''}`}>
                              {isRunning ? 'progress_activity' : selectedProcedure.authLevel ? 'gavel' : 'play_circle'}
                            </span>
                            {isRunning
                              ? 'Outil réel en cours…'
                              : selectedProcedure.authLevel
                                ? 'Autoriser puis exécuter (attestation obligatoire)'
                                : 'Exécuter la procédure réelle'}
                          </button>
                          {realResult !== null && (
                            <div className="bg-[#0a0e18] border border-[#24314c] rounded p-3">
                              <span className="text-[11px] text-[#8c909f] font-bold">Résultat brut de l'outil réel :</span>
                              <pre className="mt-1.5 text-[10px] text-[#dfe2f1] overflow-x-auto max-h-72 select-text whitespace-pre-wrap">
                                {JSON.stringify(realResult, null, 2)}
                              </pre>
                            </div>
                          )}
                        </>
                      ) : (
                        <div className="bg-[#0a0e18] border border-dashed border-[#24314c] rounded p-4 text-[#8c909f] leading-relaxed">
                          <strong className="text-[#dfe2f1] block mb-1">Pas de procédure automatisée pour ce vecteur.</strong>
                          Ce vecteur nécessite un banc d'essai contrôlé manuellement (point d'accès de test, hostapd, isolation RF).
                          Étudiez la fiche technique et les contremesures — Guyma Cyb ne fabrique aucune donnée pour compenser
                          l'absence de banc d'essai.
                        </div>
                      )}
                    </>
                  )}

                  {activeTab === 'code' && (
                    <>
                      <div className="bg-[#0a0e18] border border-[#93000a]/50 rounded overflow-hidden">
                        <div className="px-3 py-1.5 bg-[#93000a]/20 border-b border-[#93000a]/40 text-[#ffb4ab] font-bold text-[11px] flex items-center gap-1">
                          <span className="material-symbols-outlined text-[14px]">close</span>
                          Configuration vulnérable (à proscrire)
                        </div>
                        <pre className="p-3 text-[11px] text-[#ffb4ab] overflow-x-auto leading-relaxed bg-[#0a0e18] select-text">
                          {selected.remediationCodeExample.vulnerable}
                        </pre>
                      </div>
                      <div className="bg-[#0a0e18] border border-[#10b981]/50 rounded overflow-hidden">
                        <div className="px-3 py-1.5 bg-[#10b981]/20 border-b border-[#10b981]/40 text-[#34d399] font-bold text-[11px] flex items-center gap-1">
                          <span className="material-symbols-outlined text-[14px]">check</span>
                          Configuration durcie
                        </div>
                        <pre className="p-3 text-[11px] text-[#34d399] overflow-x-auto leading-relaxed bg-[#0a0e18] select-text">
                          {selected.remediationCodeExample.fixed}
                        </pre>
                      </div>
                    </>
                  )}
                </div>
              </>
            ) : (
              <div className="flex-1 flex items-center justify-center text-[#8c909f] text-xs">
                Sélectionnez une fiche technique.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
