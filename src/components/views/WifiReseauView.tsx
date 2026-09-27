import React, { useState } from 'react';
import { WifiScanResult, WpaAuditResult, DeauthDetectionResult, WifiEncryption } from '../../types';

interface WifiReseauViewProps {
  onGoToLab: () => void;
  onGoToCours: () => void;
}

type Tab = 'scan' | 'wpa-audit' | 'deauth' | 'attaques';

export const WifiReseauView: React.FC<WifiReseauViewProps> = ({ onGoToLab, onGoToCours }) => {
  const [tab, setTab] = useState<Tab>('scan');
  const [iface, setIface] = useState<string>('wlan0');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<WifiScanResult | null>(null);

  const [auditTarget, setAuditTarget] = useState<string>('');
  const [auditIface, setAuditIface] = useState<string>('wlan0');
  const [isAuditing, setIsAuditing] = useState<boolean>(false);
  const [auditResult, setAuditResult] = useState<WpaAuditResult | null>(null);

  const [deauthIface, setDeauthIface] = useState<string>('wlan0mon');
  const [deauthDuration, setDeauthDuration] = useState<number>(15);
  const [isDetecting, setIsDetecting] = useState<boolean>(false);
  const [deauthResult, setDeauthResult] = useState<DeauthDetectionResult | null>(null);

  // Onglet Attaques WiFi avancées
  const [atkIface, setAtkIface] = useState<string>('wlan0');
  const [monResult, setMonResult] = useState<any | null>(null);
  const [isMonEnabling, setIsMonEnabling] = useState(false);
  const [hsBssid, setHsBssid] = useState<string>('');
  const [hsChannel, setHsChannel] = useState<number>(6);
  const [hsDuration, setHsDuration] = useState<number>(30);
  const [hsResult, setHsResult] = useState<any | null>(null);
  const [isHsCapturing, setIsHsCapturing] = useState(false);
  const [crackCap, setCrackCap] = useState<string>('');
  const [crackWl, setCrackWl] = useState<string>('');
  const [crackResult, setCrackResult] = useState<any | null>(null);
  const [isCracking, setIsCracking] = useState(false);
  const [wpsBssid, setWpsBssid] = useState<string>('');
  const [wpsMode, setWpsMode] = useState<'pixie' | 'pin' | 'brute'>('pixie');
  const [wpsPin, setWpsPin] = useState<string>('');
  const [wpsResult, setWpsResult] = useState<any | null>(null);
  const [isWpsAttacking, setIsWpsAttacking] = useState(false);
  const [macIface, setMacIface] = useState<string>('wlan0');
  const [macNew, setMacNew] = useState<string>('');
  const [macResult, setMacResult] = useState<any | null>(null);
  const [isMacChanging, setIsMacChanging] = useState(false);

  const handleScan = async () => {
    setIsScanning(true);
    setScanResult(null);
    try {
      const res = await fetch('/api/wifi/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: iface }),
      });
      const data = await res.json();
      setScanResult(data);
    } catch (e) {
      setScanResult({ error: 'Échec du scan WiFi', tool: 'wifi-scan', mode: 'error', interface: iface, networks: [], totalCount: 0, secureCount: 0, weakCount: 0, scannedAt: '', durationMs: 0 } as any);
    } finally {
      setIsScanning(false);
    }
  };

  const handleAudit = async (bssid?: string) => {
    const target = bssid || auditTarget;
    if (!target) return;
    setIsAuditing(true);
    setAuditResult(null);
    try {
      const res = await fetch('/api/wifi/wpa-audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, interface: auditIface }),
      });
      const data = await res.json();
      setAuditResult(data);
      setAuditTarget(target);
    } catch (e) {
      setAuditResult({ error: 'Échec de l\'audit WPA', tool: 'wpa-audit', target, interface: auditIface, encryption: 'UNKNOWN', authMode: '', cipher: '', pmf: {supported:false,enabled:false,requirement:'DISABLED'}, wps: {enabled:false,locked:false,version:'',pinMethod:''}, handshake: {captured:false,fourWayComplete:false,pmkidPresent:false,notes:''}, vulnerabilities: [], grade: 'F', scannedAt: '' } as any);
    } finally {
      setIsAuditing(false);
    }
  };

  const handleDeauth = async () => {
    setIsDetecting(true);
    setDeauthResult(null);
    try {
      const res = await fetch('/api/wifi/deauth-detect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: deauthIface, duration: deauthDuration }),
      });
      const data = await res.json();
      setDeauthResult(data);
    } catch (e) {
      setDeauthResult({ error: 'Échec de la détection', tool: 'deauth-detect', interface: deauthIface, monitorMode: false, durationSec: deauthDuration, events: [], totalDeauths: 0, suspectedAttack: false, attackType: null, scannedAt: '' } as any);
    } finally {
      setIsDetecting(false);
    }
  };

  // Handlers attaques WiFi
  const handleMonitorMode = async () => {
    setIsMonEnabling(true); setMonResult(null);
    try {
      const r = await fetch('/api/wifi/monitor-mode', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ interface: atkIface }) });
      setMonResult(await r.json());
    } catch (e:any) { setMonResult({ error: e.message }); }
    finally { setIsMonEnabling(false); }
  };
  const handleHandshake = async () => {
    if (!hsBssid) return;
    setIsHsCapturing(true); setHsResult(null);
    try {
      const r = await fetch('/api/wifi/handshake-capture', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ bssid: hsBssid, channel: hsChannel, interface: atkIface, duration: hsDuration }) });
      setHsResult(await r.json());
    } catch (e:any) { setHsResult({ error: e.message }); }
    finally { setIsHsCapturing(false); }
  };
  const handleCrack = async () => {
    if (!crackCap) return;
    setIsCracking(true); setCrackResult(null);
    try {
      const r = await fetch('/api/wifi/crack-handshake', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ capFile: crackCap, wordlist: crackWl || undefined }) });
      setCrackResult(await r.json());
    } catch (e:any) { setCrackResult({ error: e.message }); }
    finally { setIsCracking(false); }
  };
  const handleWps = async () => {
    if (!wpsBssid) return;
    setIsWpsAttacking(true); setWpsResult(null);
    try {
      const r = await fetch('/api/wifi/wps-attack', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ bssid: wpsBssid, interface: atkIface, mode: wpsMode, pin: wpsPin || undefined }) });
      setWpsResult(await r.json());
    } catch (e:any) { setWpsResult({ error: e.message }); }
    finally { setIsWpsAttacking(false); }
  };
  const handleMacChange = async () => {
    setIsMacChanging(true); setMacResult(null);
    try {
      const r = await fetch('/api/wifi/mac-changer', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ interface: macIface, mac: macNew || undefined }) });
      setMacResult(await r.json());
    } catch (e:any) { setMacResult({ error: e.message }); }
    finally { setIsMacChanging(false); }
  };

  const encColor = (enc: WifiEncryption | string) => {
    switch (enc) {
      case 'WPA3':
      case 'WPA2/WPA3':
        return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
      case 'WPA2':
        return 'text-sky-400 bg-sky-500/10 border-sky-500/30';
      case 'WPA':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'WEP':
        return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'OPEN':
        return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
      default:
        return 'text-zinc-400 bg-zinc-500/10 border-zinc-500/30';
    }
  };

  const gradeColor = (g: string) => {
    if (g === 'A+' || g === 'A') return 'text-emerald-400';
    if (g === 'B') return 'text-sky-400';
    if (g === 'C') return 'text-amber-400';
    if (g === 'D') return 'text-orange-400';
    return 'text-red-400';
  };

  const sevColor = (s: string) => {
    if (s === 'CRITICAL') return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
    if (s === 'HIGH') return 'text-red-400 bg-red-500/10 border-red-500/30';
    if (s === 'MEDIUM') return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
    if (s === 'LOW') return 'text-sky-400 bg-sky-500/10 border-sky-500/30';
    return 'text-zinc-400 bg-zinc-500/10 border-zinc-500/30';
  };

  return (
    <div className="h-full overflow-y-auto bg-[#0a0e18] text-[#dfe2f1] p-6">
      <div className="max-w-7xl mx-auto">
        {/* En-tête */}
        <div className="mb-6 flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <span className="material-symbols-outlined text-emerald-400">wifi</span>
              WiFi & Réseau Sans Fil
            </h1>
            <p className="text-sm text-[#8c909f] mt-1">
              Découverte des points d'accès, audit WPA/WPA2/WPA3, détection d'attaques deauth.
            </p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={onGoToCours}
              className="px-3 py-1.5 text-xs rounded bg-[#171b26] border border-[#24314c] hover:border-emerald-500/50 text-[#c2c6d6] flex items-center gap-1.5 transition-colors"
              type="button"
            >
              <span className="material-symbols-outlined text-[16px]">school</span>
              Cours WiFi
            </button>
            <button
              onClick={onGoToLab}
              className="px-3 py-1.5 text-xs rounded bg-emerald-600/15 border border-emerald-500/30 text-emerald-400 hover:bg-emerald-600/25 flex items-center gap-1.5 transition-colors"
              type="button"
            >
              <span className="material-symbols-outlined text-[16px]">science</span>
              Lab Attaques WiFi
            </button>
          </div>
        </div>

        {/* Onglets */}
        <div className="flex gap-1 mb-6 border-b border-[#24314c]">
          {([
            { id: 'scan' as Tab, label: 'Scan Réseaux', icon: 'wifi_tethering' },
            { id: 'wpa-audit' as Tab, label: 'Audit WPA/WPA2/WPA3', icon: 'shield_lock' },
            { id: 'deauth' as Tab, label: 'Détection Deauth', icon: 'sensors' },
            { id: 'attaques' as Tab, label: 'Attaques WiFi', icon: 'gpp_bad' },
          ]).map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors flex items-center gap-2 ${
                tab === t.id
                  ? 'border-emerald-500 text-emerald-400'
                  : 'border-transparent text-[#8c909f] hover:text-[#dfe2f1]'
              }`}
              type="button"
            >
              <span className="material-symbols-outlined text-[18px]">{t.icon}</span>
              {t.label}
            </button>
          ))}
        </div>

        {/* ====================== Tab: Scan ====================== */}
        {tab === 'scan' && (
          <div className="space-y-4">
            <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4">
              <div className="flex flex-wrap gap-3 items-end">
                <div className="flex-1 min-w-[200px]">
                  <label className="block text-xs text-[#8c909f] mb-1 font-mono">Interface sans fil</label>
                  <input
                    type="text"
                    value={iface}
                    onChange={(e) => setIface(e.target.value)}
                    placeholder="wlan0 / wlp2s0"
                    className="w-full px-3 py-2 bg-[#0a0e18] border border-[#24314c] rounded text-sm font-mono text-[#dfe2f1] focus:border-emerald-500 outline-none"
                  />
                </div>
                <button
                  onClick={handleScan}
                  disabled={isScanning}
                  className="px-5 py-2 bg-emerald-600/20 border border-emerald-500/40 text-emerald-400 rounded text-sm font-medium hover:bg-emerald-600/30 disabled:opacity-50 flex items-center gap-2 transition-colors"
                  type="button"
                >
                  {isScanning ? (
                    <><span className="material-symbols-outlined animate-spin text-[18px]">progress_activity</span> Scan en cours...</>
                  ) : (
                    <><span className="material-symbols-outlined text-[18px]">play_arrow</span> Lancer le scan</>
                  )}
                </button>
              </div>
              <p className="text-[11px] text-[#8c909f] mt-2 font-mono">
                Utilise iw → iwlist → aircrack-ng → simulation. Sans sudo, bascule en mode simulation réaliste.
              </p>
            </div>

            {scanResult && !scanResult.error && (
              <>
                <div className="grid grid-cols-3 gap-3">
                  <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                    <div className="text-[10px] text-[#8c909f] font-mono uppercase">Total réseaux</div>
                    <div className="text-2xl font-bold text-[#dfe2f1]">{scanResult.totalCount}</div>
                  </div>
                  <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                    <div className="text-[10px] text-[#8c909f] font-mono uppercase">Sécurisés (WPA2+)</div>
                    <div className="text-2xl font-bold text-emerald-400">{scanResult.secureCount}</div>
                  </div>
                  <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                    <div className="text-[10px] text-[#8c909f] font-mono uppercase">Vulnérables (WEP/OPEN)</div>
                    <div className="text-2xl font-bold text-rose-400">{scanResult.weakCount}</div>
                  </div>
                </div>

                <div className="bg-[#171b26] border border-[#24314c] rounded-lg overflow-hidden">
                  <div className="px-4 py-2 border-b border-[#24314c] flex items-center justify-between">
                    <div className="text-xs font-mono text-[#8c909f]">
                      Mode: <span className="text-emerald-400">{scanResult.mode}</span> • Interface: {scanResult.interface}
                    </div>
                    <div className="text-[10px] text-[#8c909f]">{scanResult.scannedAt}</div>
                  </div>
                  <div className="max-h-[460px] overflow-y-auto">
                    <table className="w-full text-sm">
                      <thead className="bg-[#0a0e18] sticky top-0">
                        <tr className="text-[10px] text-[#8c909f] font-mono uppercase">
                          <th className="text-left px-3 py-2">BSSID</th>
                          <th className="text-left px-3 py-2">SSID</th>
                          <th className="text-left px-3 py-2">Ch</th>
                          <th className="text-left px-3 py-2">Signal</th>
                          <th className="text-left px-3 py-2">Chiffrement</th>
                          <th className="text-left px-3 py-2">Fabriquant</th>
                          <th className="text-left px-3 py-2"></th>
                        </tr>
                      </thead>
                      <tbody>
                        {scanResult.networks.map((n) => (
                          <tr key={n.bssid} className="border-t border-[#24314c] hover:bg-[#1f2433]">
                            <td className="px-3 py-2 font-mono text-[11px] text-[#c2c6d6]">{n.bssid}</td>
                            <td className="px-3 py-2 text-[#dfe2f1]">
                              {n.isHidden ? <span className="italic text-[#8c909f]">[Hidden]</span> : n.ssid}
                            </td>
                            <td className="px-3 py-2 font-mono text-[11px] text-[#c2c6d6]">{n.channel}</td>
                            <td className="px-3 py-2">
                              <div className="flex items-center gap-2">
                                <div className="w-16 h-1.5 bg-[#24314c] rounded overflow-hidden">
                                  <div
                                    className={`h-full ${n.quality > 60 ? 'bg-emerald-500' : n.quality > 30 ? 'bg-amber-500' : 'bg-rose-500'}`}
                                    style={{ width: `${n.quality}%` }}
                                  />
                                </div>
                                <span className="text-[10px] font-mono text-[#8c909f]">{n.signalDbm}dBm</span>
                              </div>
                            </td>
                            <td className="px-3 py-2">
                              <span className={`px-2 py-0.5 text-[10px] font-mono rounded border ${encColor(n.encryption)}`}>
                                {n.encryption}
                              </span>
                            </td>
                            <td className="px-3 py-2 text-[11px] text-[#8c909f]">{n.vendor}</td>
                            <td className="px-3 py-2">
                              <button
                                onClick={() => { setTab('wpa-audit'); handleAudit(n.bssid); }}
                                className="px-2 py-0.5 text-[10px] rounded bg-sky-500/10 border border-sky-500/30 text-sky-400 hover:bg-sky-500/20 transition-colors"
                                type="button"
                              >
                                Audit
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </>
            )}
            {scanResult?.error && (
              <div className="bg-rose-500/10 border border-rose-500/30 rounded-lg p-4 text-sm text-rose-400">
                {scanResult.error}
              </div>
            )}
          </div>
        )}

        {/* ====================== Tab: WPA Audit ====================== */}
        {tab === 'wpa-audit' && (
          <div className="space-y-4">
            <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4">
              <div className="flex flex-wrap gap-3 items-end">
                <div className="flex-1 min-w-[240px]">
                  <label className="block text-xs text-[#8c909f] mb-1 font-mono">Cible (BSSID ou SSID)</label>
                  <input
                    type="text"
                    value={auditTarget}
                    onChange={(e) => setAuditTarget(e.target.value)}
                    placeholder="AA:BB:CC:DD:EE:FF ou MonReseau"
                    className="w-full px-3 py-2 bg-[#0a0e18] border border-[#24314c] rounded text-sm font-mono text-[#dfe2f1] focus:border-emerald-500 outline-none"
                  />
                </div>
                <div className="min-w-[140px]">
                  <label className="block text-xs text-[#8c909f] mb-1 font-mono">Interface</label>
                  <input
                    type="text"
                    value={auditIface}
                    onChange={(e) => setAuditIface(e.target.value)}
                    className="w-full px-3 py-2 bg-[#0a0e18] border border-[#24314c] rounded text-sm font-mono text-[#dfe2f1] focus:border-emerald-500 outline-none"
                  />
                </div>
                <button
                  onClick={() => handleAudit()}
                  disabled={isAuditing || !auditTarget}
                  className="px-5 py-2 bg-emerald-600/20 border border-emerald-500/40 text-emerald-400 rounded text-sm font-medium hover:bg-emerald-600/30 disabled:opacity-50 flex items-center gap-2 transition-colors"
                  type="button"
                >
                  {isAuditing ? (
                    <><span className="material-symbols-outlined animate-spin text-[18px]">progress_activity</span> Audit...</>
                  ) : (
                    <><span className="material-symbols-outlined text-[18px]">shield_lock</span> Auditer</>
                  )}
                </button>
              </div>
            </div>

            {auditResult && !auditResult.error && (
              <>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                    <div className="text-[10px] text-[#8c909f] font-mono uppercase">Chiffrement</div>
                    <div className={`text-lg font-bold ${encColor(auditResult.encryption).split(' ')[0]}`}>
                      {auditResult.encryption}
                    </div>
                    <div className="text-[10px] text-[#8c909f] font-mono">{auditResult.cipher} / {auditResult.authMode}</div>
                  </div>
                  <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                    <div className="text-[10px] text-[#8c909f] font-mono uppercase">Note sécurité</div>
                    <div className={`text-3xl font-bold ${gradeColor(auditResult.grade)}`}>{auditResult.grade}</div>
                  </div>
                  <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                    <div className="text-[10px] text-[#8c909f] font-mono uppercase">PMF (802.11w)</div>
                    <div className={`text-sm font-bold ${auditResult.pmf.enabled ? 'text-emerald-400' : 'text-rose-400'}`}>
                      {auditResult.pmf.enabled ? 'Activé' : 'Désactivé'}
                    </div>
                    <div className="text-[10px] text-[#8c909f] font-mono">{auditResult.pmf.requirement}</div>
                  </div>
                  <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                    <div className="text-[10px] text-[#8c909f] font-mono uppercase">WPS</div>
                    <div className={`text-sm font-bold ${auditResult.wps.enabled ? 'text-amber-400' : 'text-emerald-400'}`}>
                      {auditResult.wps.enabled ? 'Activé' : 'Désactivé'}
                    </div>
                    {auditResult.wps.enabled && (
                      <div className="text-[10px] text-[#8c909f] font-mono">{auditResult.wps.version} • {auditResult.wps.pinMethod}</div>
                    )}
                  </div>
                </div>

                {auditResult.vulnerabilities.length > 0 && (
                  <div className="bg-[#171b26] border border-[#24314c] rounded-lg overflow-hidden">
                    <div className="px-4 py-2 border-b border-[#24314c] text-sm font-medium text-[#dfe2f1] flex items-center gap-2">
                      <span className="material-symbols-outlined text-rose-400 text-[18px]">warning</span>
                      Vulnérabilités détectées ({auditResult.vulnerabilities.length})
                    </div>
                    <div className="divide-y divide-[#24314c]">
                      {auditResult.vulnerabilities.map((v) => (
                        <div key={v.id} className="px-4 py-3">
                          <div className="flex items-start justify-between gap-3 mb-1">
                            <div className="flex-1">
                              <span className={`px-2 py-0.5 text-[10px] font-mono rounded border mr-2 ${sevColor(v.severity)}`}>
                                {v.severity}
                              </span>
                              <span className="text-sm font-medium text-[#dfe2f1]">{v.title}</span>
                              <span className="ml-2 text-[10px] font-mono text-[#8c909f]">{v.cwe}</span>
                            </div>
                          </div>
                          <p className="text-xs text-[#8c909f] mt-1">{v.description}</p>
                          <p className="text-xs text-emerald-400/80 mt-1">→ {v.remediation}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4">
                  <div className="text-xs font-mono text-[#8c909f] uppercase mb-2">Handshake</div>
                  <div className="grid grid-cols-3 gap-3 text-xs">
                    <div>
                      <span className="text-[#8c909f]">Capturé: </span>
                      <span className={auditResult.handshake.captured ? 'text-amber-400' : 'text-zinc-400'}>
                        {auditResult.handshake.captured ? 'Oui' : 'Non'}
                      </span>
                    </div>
                    <div>
                      <span className="text-[#8c909f]">4-way complet: </span>
                      <span className={auditResult.handshake.fourWayComplete ? 'text-amber-400' : 'text-zinc-400'}>
                        {auditResult.handshake.fourWayComplete ? 'Oui' : 'Non'}
                      </span>
                    </div>
                    <div>
                      <span className="text-[#8c909f]">PMKID: </span>
                      <span className={auditResult.handshake.pmkidPresent ? 'text-amber-400' : 'text-zinc-400'}>
                        {auditResult.handshake.pmkidPresent ? 'Oui' : 'Non'}
                      </span>
                    </div>
                  </div>
                  <p className="text-[11px] text-[#8c909f] mt-2 italic">{auditResult.handshake.notes}</p>
                </div>
              </>
            )}
            {auditResult?.error && (
              <div className="bg-rose-500/10 border border-rose-500/30 rounded-lg p-4 text-sm text-rose-400">
                {auditResult.error}
              </div>
            )}
          </div>
        )}

        {/* ====================== Tab: Deauth Detection ====================== */}
        {tab === 'deauth' && (
          <div className="space-y-4">
            <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4">
              <div className="flex flex-wrap gap-3 items-end">
                <div className="min-w-[180px]">
                  <label className="block text-xs text-[#8c909f] mb-1 font-mono">Interface monitor</label>
                  <input
                    type="text"
                    value={deauthIface}
                    onChange={(e) => setDeauthIface(e.target.value)}
                    placeholder="wlan0mon"
                    className="w-full px-3 py-2 bg-[#0a0e18] border border-[#24314c] rounded text-sm font-mono text-[#dfe2f1] focus:border-emerald-500 outline-none"
                  />
                </div>
                <div className="min-w-[140px]">
                  <label className="block text-xs text-[#8c909f] mb-1 font-mono">Durée (sec)</label>
                  <input
                    type="number"
                    value={deauthDuration}
                    onChange={(e) => setDeauthDuration(parseInt(e.target.value) || 15)}
                    min={5}
                    max={120}
                    className="w-full px-3 py-2 bg-[#0a0e18] border border-[#24314c] rounded text-sm font-mono text-[#dfe2f1] focus:border-emerald-500 outline-none"
                  />
                </div>
                <button
                  onClick={handleDeauth}
                  disabled={isDetecting}
                  className="px-5 py-2 bg-emerald-600/20 border border-emerald-500/40 text-emerald-400 rounded text-sm font-medium hover:bg-emerald-600/30 disabled:opacity-50 flex items-center gap-2 transition-colors"
                  type="button"
                >
                  {isDetecting ? (
                    <><span className="material-symbols-outlined animate-spin text-[18px]">progress_activity</span> Détection... ({deauthDuration}s)</>
                  ) : (
                    <><span className="material-symbols-outlined text-[18px]">sensors</span> Démarrer la détection</>
                  )}
                </button>
              </div>
              <p className="text-[11px] text-[#8c909f] mt-2 font-mono">
                Nécessite le mode monitor (airmon-ng). Sans sudo, bascule en simulation réaliste.
              </p>
            </div>

            {deauthResult && !deauthResult.error && (
              <>
                <div className="grid grid-cols-3 gap-3">
                  <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                    <div className="text-[10px] text-[#8c909f] font-mono uppercase">Trames deauth</div>
                    <div className="text-2xl font-bold text-[#dfe2f1]">{deauthResult.totalDeauths}</div>
                    <div className="text-[10px] text-[#8c909f]">en {deauthResult.durationSec}s</div>
                  </div>
                  <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                    <div className="text-[10px] text-[#8c909f] font-mono uppercase">Mode monitor</div>
                    <div className={`text-lg font-bold ${deauthResult.monitorMode ? 'text-emerald-400' : 'text-amber-400'}`}>
                      {deauthResult.monitorMode ? 'Activé' : 'Désactivé'}
                    </div>
                  </div>
                  <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-3">
                    <div className="text-[10px] text-[#8c909f] font-mono uppercase">Attaque suspectée</div>
                    <div className={`text-lg font-bold ${deauthResult.suspectedAttack ? 'text-rose-400' : 'text-emerald-400'}`}>
                      {deauthResult.suspectedAttack ? 'OUI' : 'Non'}
                    </div>
                    {deauthResult.attackType && (
                      <div className="text-[10px] font-mono text-rose-400">{deauthResult.attackType}</div>
                    )}
                  </div>
                </div>

                <div className="bg-[#171b26] border border-[#24314c] rounded-lg overflow-hidden">
                  <div className="px-4 py-2 border-b border-[#24314c] text-sm font-medium text-[#dfe2f1] flex items-center gap-2">
                    <span className="material-symbols-outlined text-emerald-400 text-[18px]">list_alt</span>
                    Journal des événements deauth
                  </div>
                  <div className="max-h-[400px] overflow-y-auto">
                    {deauthResult.events.length === 0 ? (
                      <div className="px-4 py-8 text-center text-sm text-[#8c909f]">
                        Aucune trame deauth détectée pendant la période de surveillance.
                      </div>
                    ) : (
                      <table className="w-full text-xs">
                        <thead className="bg-[#0a0e18] sticky top-0">
                          <tr className="text-[10px] text-[#8c909f] font-mono uppercase">
                            <th className="text-left px-3 py-2">Timestamp</th>
                            <th className="text-left px-3 py-2">Source BSSID</th>
                            <th className="text-left px-3 py-2">Client cible</th>
                            <th className="text-left px-3 py-2">Type</th>
                            <th className="text-left px-3 py-2">Raison</th>
                          </tr>
                        </thead>
                        <tbody>
                          {deauthResult.events.map((ev, i) => (
                            <tr key={i} className="border-t border-[#24314c] hover:bg-[#1f2433]">
                              <td className="px-3 py-2 font-mono text-[10px] text-[#8c909f]">{ev.timestamp}</td>
                              <td className="px-3 py-2 font-mono text-[10px] text-[#c2c6d6]">{ev.sourceBssid}</td>
                              <td className="px-3 py-2 font-mono text-[10px] text-[#c2c6d6]">{ev.targetClient}</td>
                              <td className="px-3 py-2 font-mono text-[10px] text-emerald-400">{ev.frameType}</td>
                              <td className="px-3 py-2 text-[11px] text-[#8c909f]">{ev.reason}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                </div>
              </>
            )}
            {deauthResult?.error && (
              <div className="bg-rose-500/10 border border-rose-500/30 rounded-lg p-4 text-sm text-rose-400">
                {deauthResult.error}
              </div>
            )}
          </div>
        )}

        {/* ====================== Tab: Attaques WiFi ====================== */}
        {tab === 'attaques' && (
          <div className="space-y-4">
            <div className="bg-rose-500/5 border border-rose-500/20 rounded-lg p-3 text-xs text-rose-300 flex items-start gap-2">
              <span className="material-symbols-outlined text-[16px] mt-0.5">warning</span>
              <div>
                <strong>Attaques WiFi réelles</strong> — nécessitent Linux root + aircrack-ng + carte WiFi USB mode monitor.
                Sans sudo, les scripts basculent en <strong>mode simulation réaliste</strong> pour la démonstration.
                À n'utiliser que sur vos propres réseaux ou avec autorisation écrite.
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* Mode Monitor */}
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4">
                <h3 className="text-sm font-semibold text-[#dfe2f1] mb-3 flex items-center gap-2">
                  <span className="material-symbols-outlined text-emerald-400 text-[18px]">wifi_tethering</span>
                  1. Mode Monitor
                </h3>
                <div className="flex gap-2 mb-3">
                  <input type="text" value={atkIface} onChange={(e)=>setAtkIface(e.target.value)} placeholder="wlan0" className="flex-1 px-2 py-1.5 bg-[#0a0e18] border border-[#24314c] rounded text-xs font-mono text-[#dfe2f1] outline-none focus:border-emerald-500" />
                  <button onClick={handleMonitorMode} disabled={isMonEnabling} className="px-3 py-1.5 text-xs bg-emerald-600/20 border border-emerald-500/40 text-emerald-400 rounded hover:bg-emerald-600/30 disabled:opacity-50 flex items-center gap-1" type="button">
                    {isMonEnabling ? <><span className="material-symbols-outlined animate-spin text-[14px]">progress_activity</span></> : <><span className="material-symbols-outlined text-[14px]">play_arrow</span>Activer</>}
                  </button>
                </div>
                {monResult && (
                  <div className={`text-xs p-2 rounded font-mono ${monResult.enabled ? 'bg-emerald-500/10 text-emerald-400' : 'bg-rose-500/10 text-rose-400'}`}>
                    {monResult.enabled ? `✓ Mode monitor activé sur ${monResult.monitorInterface} (${monResult.method})` : `✗ ${monResult.error || 'Échec'}`}
                  </div>
                )}
              </div>

              {/* MAC Changer */}
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4">
                <h3 className="text-sm font-semibold text-[#dfe2f1] mb-3 flex items-center gap-2">
                  <span className="material-symbols-outlined text-amber-400 text-[18px]">fingerprint</span>
                  2. Changeur MAC
                </h3>
                <div className="flex gap-2 mb-2">
                  <input type="text" value={macIface} onChange={(e)=>setMacIface(e.target.value)} placeholder="wlan0" className="flex-1 px-2 py-1.5 bg-[#0a0e18] border border-[#24314c] rounded text-xs font-mono text-[#dfe2f1] outline-none focus:border-amber-500" />
                </div>
                <div className="flex gap-2 mb-3">
                  <input type="text" value={macNew} onChange={(e)=>setMacNew(e.target.value)} placeholder="MAC (vide = aléatoire)" className="flex-1 px-2 py-1.5 bg-[#0a0e18] border border-[#24314c] rounded text-xs font-mono text-[#dfe2f1] outline-none focus:border-amber-500" />
                  <button onClick={handleMacChange} disabled={isMacChanging} className="px-3 py-1.5 text-xs bg-amber-600/20 border border-amber-500/40 text-amber-400 rounded hover:bg-amber-600/30 disabled:opacity-50 flex items-center gap-1" type="button">
                    {isMacChanging ? <span className="material-symbols-outlined animate-spin text-[14px]">progress_activity</span> : 'Changer'}
                  </button>
                </div>
                {macResult && (
                  <div className="text-xs p-2 rounded font-mono bg-[#0a0e18] border border-[#24314c] text-[#c2c6d6]">
                    {macResult.originalMac && <div>Original: <span className="text-[#8c909f]">{macResult.originalMac}</span></div>}
                    <div>Nouvelle: <span className="text-amber-400">{macResult.newMac}</span></div>
                    <div className={macResult.changed ? 'text-emerald-400' : 'text-rose-400'}>{macResult.changed ? '✓ MAC changée' : '✗ ' + (macResult.error || 'échec')}</div>
                  </div>
                )}
              </div>

              {/* Capture Handshake */}
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4">
                <h3 className="text-sm font-semibold text-[#dfe2f1] mb-3 flex items-center gap-2">
                  <span className="material-symbols-outlined text-sky-400 text-[18px]">key</span>
                  3. Capture Handshake
                </h3>
                <div className="space-y-2 mb-3">
                  <input type="text" value={hsBssid} onChange={(e)=>setHsBssid(e.target.value)} placeholder="BSSID cible (AA:BB:CC:DD:EE:FF)" className="w-full px-2 py-1.5 bg-[#0a0e18] border border-[#24314c] rounded text-xs font-mono text-[#dfe2f1] outline-none focus:border-sky-500" />
                  <div className="flex gap-2">
                    <input type="number" value={hsChannel} onChange={(e)=>setHsChannel(parseInt(e.target.value)||6)} min={1} max={165} placeholder="Canal" className="w-20 px-2 py-1.5 bg-[#0a0e18] border border-[#24314c] rounded text-xs font-mono text-[#dfe2f1] outline-none" />
                    <input type="number" value={hsDuration} onChange={(e)=>setHsDuration(parseInt(e.target.value)||30)} min={5} max={300} placeholder="Durée (s)" className="w-24 px-2 py-1.5 bg-[#0a0e18] border border-[#24314c] rounded text-xs font-mono text-[#dfe2f1] outline-none" />
                    <button onClick={handleHandshake} disabled={isHsCapturing || !hsBssid} className="flex-1 px-3 py-1.5 text-xs bg-sky-600/20 border border-sky-500/40 text-sky-400 rounded hover:bg-sky-600/30 disabled:opacity-50 flex items-center justify-center gap-1" type="button">
                      {isHsCapturing ? <><span className="material-symbols-outlined animate-spin text-[14px]">progress_activity</span> Capture...</> : 'Capturer'}
                    </button>
                  </div>
                </div>
                {hsResult && (
                  <div className="text-xs p-2 rounded font-mono bg-[#0a0e18] border border-[#24314c] text-[#c2c6d6]">
                    <div className={hsResult.handshakeFound ? 'text-emerald-400' : 'text-amber-400'}>
                      {hsResult.handshakeFound ? '✓ Handshake capturé !' : '✗ Pas de handshake'}
                    </div>
                    {hsResult.capFile && <div className="text-[10px] text-[#8c909f]">Cap: {hsResult.capFile}</div>}
                    <div className="text-[10px] text-[#8c909f]">{hsResult.packetsCaptured} paquets • {hsResult.mode}</div>
                    {hsResult.crackCap && <button onClick={()=>setCrackCap(hsResult.capFile)} className="mt-1 text-[10px] text-sky-400 underline">→ Cracker ce handshake</button>}
                  </div>
                )}
              </div>

              {/* Crack Handshake */}
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4">
                <h3 className="text-sm font-semibold text-[#dfe2f1] mb-3 flex items-center gap-2">
                  <span className="material-symbols-outlined text-rose-400 text-[18px]">no_encryption</span>
                  4. Crack Handshake
                </h3>
                <div className="space-y-2 mb-3">
                  <input type="text" value={crackCap} onChange={(e)=>setCrackCap(e.target.value)} placeholder="Chemin du .cap" className="w-full px-2 py-1.5 bg-[#0a0e18] border border-[#24314c] rounded text-xs font-mono text-[#dfe2f1] outline-none focus:border-rose-500" />
                  <input type="text" value={crackWl} onChange={(e)=>setCrackWl(e.target.value)} placeholder="Wordlist (vide = auto)" className="w-full px-2 py-1.5 bg-[#0a0e18] border border-[#24314c] rounded text-xs font-mono text-[#dfe2f1] outline-none" />
                  <button onClick={handleCrack} disabled={isCracking || !crackCap} className="w-full px-3 py-1.5 text-xs bg-rose-600/20 border border-rose-500/40 text-rose-400 rounded hover:bg-rose-600/30 disabled:opacity-50 flex items-center justify-center gap-1" type="button">
                    {isCracking ? <><span className="material-symbols-outlined animate-spin text-[14px]">progress_activity</span> Cassage...</> : 'Casser le handshake'}
                  </button>
                </div>
                {crackResult && (
                  <div className="text-xs p-2 rounded font-mono bg-[#0a0e18] border border-[#24314c] text-[#c2c6d6]">
                    {crackResult.cracked ? (
                      <div className="text-emerald-400">✓ Mot de passe trouvé: <strong>{crackResult.password}</strong></div>
                    ) : (
                      <div className="text-rose-400">✗ Non cassé ({crackResult.error || 'wordlist insuffisante'})</div>
                    )}
                    <div className="text-[10px] text-[#8c909f]">{crackResult.keysTried} clés testées • {crackResult.mode}</div>
                  </div>
                )}
              </div>

              {/* WPS Attack */}
              <div className="bg-[#171b26] border border-[#24314c] rounded-lg p-4 lg:col-span-2">
                <h3 className="text-sm font-semibold text-[#dfe2f1] mb-3 flex items-center gap-2">
                  <span className="material-symbols-outlined text-violet-400 text-[18px]">pin</span>
                  5. Attaque WPS (Pixie-Dust / PIN / Brute)
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-2 mb-3">
                  <input type="text" value={wpsBssid} onChange={(e)=>setWpsBssid(e.target.value)} placeholder="BSSID cible" className="px-2 py-1.5 bg-[#0a0e18] border border-[#24314c] rounded text-xs font-mono text-[#dfe2f1] outline-none focus:border-violet-500" />
                  <select value={wpsMode} onChange={(e)=>setWpsMode(e.target.value as any)} className="px-2 py-1.5 bg-[#0a0e18] border border-[#24314c] rounded text-xs font-mono text-[#dfe2f1] outline-none">
                    <option value="pixie">Pixie-Dust (reaver -K 1)</option>
                    <option value="pin">PIN spécifique</option>
                    <option value="brute">Brute force PIN</option>
                  </select>
                  <input type="text" value={wpsPin} onChange={(e)=>setWpsPin(e.target.value)} placeholder="PIN (mode pin)" disabled={wpsMode!=='pin'} className="px-2 py-1.5 bg-[#0a0e18] border border-[#24314c] rounded text-xs font-mono text-[#dfe2f1] outline-none disabled:opacity-40" />
                  <button onClick={handleWps} disabled={isWpsAttacking || !wpsBssid} className="px-3 py-1.5 text-xs bg-violet-600/20 border border-violet-500/40 text-violet-400 rounded hover:bg-violet-600/30 disabled:opacity-50 flex items-center justify-center gap-1" type="button">
                    {isWpsAttacking ? <><span className="material-symbols-outlined animate-spin text-[14px]">progress_activity</span> Attaque...</> : 'Lancer'}
                  </button>
                </div>
                {wpsResult && (
                  <div className="text-xs p-2 rounded font-mono bg-[#0a0e18] border border-[#24314c] text-[#c2c6d6]">
                    {wpsResult.cracked ? (
                      <div className="text-emerald-400">✓ WPS cassé ! PIN: <strong>{wpsResult.pin}</strong> • Mot de passe: <strong>{wpsResult.password}</strong></div>
                    ) : (
                      <div className="text-amber-400">⏳ Progression: {wpsResult.progress}% • {wpsResult.error || wpsResult.note || ''}</div>
                    )}
                    <div className="text-[10px] text-[#8c909f]">Méthode: {wpsResult.method}</div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
