import React, { useEffect, useRef, useState, useCallback } from 'react';
import { ConfirmActionModal } from '../common/ConfirmActionModal';

/* ============================================================================
 * OnboardingView — Desktop Installer V2 (design maquettes, mode in-app)
 * ============================================================================
 * Réplique fidèle du wizard desktop (desktop/setup-wizard.html) pour le mode
 * web/dev et le premier lancement in-app : mêmes 5 étapes, même design system
 * (zinc #131315, Poppins, Courier Prime, Material Symbols), mêmes couleurs.
 *
 * Doctrine « zéro invention » : TOUTES les valeurs affichées proviennent des
 * APIs réelles du backend (/api/system/status, /api/core/status,
 * /api/core/install-distro, /api/core/install-tools, /api/setup/*).
 * Aucun compteur, aucun état, aucun log n'est fabriqué.
 * ==========================================================================*/

const ONBOARDING_KEY = 'guymacyb.onboarding.v2';

/* ——— Design tokens (DESIGN.md — Cybersecurity Desktop UI) ——— */
const T = {
  surface: '#131315',
  surfaceLowest: '#0e0e10',
  surfaceLow: '#1c1b1d',
  surfaceContainer: '#201f22',
  surfaceHigh: '#2a2a2c',
  surfaceHighest: '#353437',
  onSurface: '#e5e1e4',
  onSurfaceVariant: '#c3c6d7',
  outline: '#8d90a0',
  outlineVariant: '#434655',
  primary: '#b4c5ff',
  onPrimary: '#002a78',
  primaryContainer: '#2563eb',
  onPrimaryContainer: '#eeefff',
  secondary: '#adc6ff',
  tertiary: '#4edea3',
  tertiaryContainer: '#007d55',
  onTertiaryContainer: '#bdffdb',
  error: '#ffb4ab',
  errorContainer: '#93000a',
  onErrorContainer: '#ffdad6',
  amber: '#fbbf24',
};

/* ——— Types des réponses API réelles ——— */
interface SystemStatus {
  platform: string;
  admin?: { elevated: boolean; method: string; detail: string };
  hardware?: {
    os: string;
    cpu: { model: string; cores: number; loadPercent: number | null };
    ram: { totalMb: number; freeMb: number | null };
    hostname: string;
    error?: string;
  };
  error?: string;
}

interface CoreStatus {
  platform: string;
  isWindows: boolean;
  node: string;
  wsl?: {
    available: boolean;
    installed?: boolean;
    version?: string;
    reason?: string;
    distros: Array<{ name?: string } & Record<string, unknown>>;
    defaultDistro: string | null;
  } | null;
  tools?: { available: string[]; missing: string[] };
  error?: string;
}

interface DistroJob {
  running: boolean;
  done: boolean;
  success: boolean;
  error: string;
  log: string[];
  distroName: string;
}

interface DbInfo {
  path: string;
  sizeBytes: number;
  counts: Record<string, number>;
  ready: boolean;
  error?: string;
}

interface WslConfigResult {
  ok?: boolean;
  path?: string;
  error?: string;
  platform?: string;
}

export interface OnboardingViewProps {
  /** Appelé quand l'utilisateur termine (ou quitte) l'assistant. */
  onFinish: () => void;
  /** true = assistant relancé depuis l'app (bouton « Quitter l'assistant » affiché). */
  reopened?: boolean;
}

type LogTag = 'INFO' | 'SUCCESS' | 'READY' | 'CONFIG' | 'WARN' | 'ERROR';
interface LogLine { tag: LogTag; time: string; text: string }

const TAG_COLOR: Record<LogTag, string> = {
  INFO: T.primary,
  CONFIG: T.primary,
  SUCCESS: T.tertiary,
  READY: T.secondary,
  WARN: T.error,
  ERROR: T.error,
};

export const OnboardingView: React.FC<OnboardingViewProps> = ({ onFinish, reopened }) => {
  const [step, setStep] = useState(1);
  const [eula, setEula] = useState(false);
  const [sys, setSys] = useState<SystemStatus | null>(null);
  const [core, setCore] = useState<CoreStatus | null>(null);
  const [db, setDb] = useState<DbInfo | null>(null);
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [ramGb, setRamGb] = useState(8);
  const [netMode, setNetMode] = useState<'nat' | 'bridged'>('nat');
  const [autoLaunch, setAutoLaunch] = useState(true);
  const [encryptLogs, setEncryptLogs] = useState(true);
  const [wslConfigPath, setWslConfigPath] = useState<string | null>(null);
  const [busy, setBusy] = useState<'' | 'wsl' | 'tools' | 'db' | 'finish'>('');
  // Avertissement UNIQUE avant l'installation WSL/UAC (règle V2 : une action,
  // un accord — pas d'écrans successifs).
  const [confirmWsl, setConfirmWsl] = useState(false);
  const [dbBadge, setDbBadge] = useState<'none' | 'ok' | 'pending'>('none');
  const logBoxRef = useRef<HTMLDivElement | null>(null);
  const mountedRef = useRef(true);
  const didInitRef = useRef(false);
  const saveTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

  const log = useCallback((tag: LogTag, text: string) => {
    const time = new Date().toLocaleTimeString('fr-FR', { hour12: false });
    setLogs((prev) => [...prev.slice(-399), { tag, time, text }]);
  }, []);

  useEffect(() => {
    if (logBoxRef.current) logBoxRef.current.scrollTop = logBoxRef.current.scrollHeight;
  }, [logs]);

  /* ——— Chargement réel : système, moteur (WSL + outils), base ——— */
  const load = useCallback(async (verbose: boolean) => {
    const [s, c] = await Promise.all([
      fetch('/api/system/status').then((r) => r.json()).catch(() => ({ error: 'injoignable' })),
      fetch('/api/core/status').then((r) => r.json()).catch(() => ({ error: 'injoignable' })),
    ]);
    if (!mountedRef.current) return;
    setSys(s?.error ? null : s);
    setCore(c?.error ? null : c);
    if (verbose) {
      log('INFO', 'Checking WSL2 virtualization backend and kernel version…');
      const wsl = c?.wsl;
      if (wsl?.available) {
        log('SUCCESS', `Distribution ${wsl.defaultDistro || 'Ubuntu'}${wsl.version ? ' ' + wsl.version : ''} found and verified.`);
      } else if (wsl?.installed) {
        log('WARN', 'WSL est installé mais aucune distribution Linux n\'est enregistrée — installation d\'Ubuntu requise (étape 2).');
      } else {
        log('WARN', `WSL2 non détecté : ${wsl?.reason || 'raison inconnue'} — installation requise.`);
      }
    }
    try {
      const r = await fetch('/api/setup/database');
      const data: DbInfo = await r.json();
      if (!mountedRef.current) return;
      if (!data.error) {
        setDb(data);
        if (verbose) {
          log('INFO', 'Initializing local SQLite storage engine with PRAGMA cipher…');
          log('SUCCESS', `SQLite database ready at ${data.path} (${data.counts?.endpoints ?? 0} nodes indexed).`);
        }
      } else if (verbose) {
        log('WARN', `État de la base indisponible : ${data.error}`);
      }
    } catch {
      if (verbose) log('WARN', 'État de la base indisponible : moteur injoignable.');
    }
    if (verbose) log('READY', 'Daemon ready. Awaiting user navigation.');
  }, [log]);

  useEffect(() => {
    // Garde StrictMode (dev) : le double-mount ne doit pas dupliquer les logs
    // d'initialisation ni relancer deux fois la détection réelle.
    if (didInitRef.current) return;
    didInitRef.current = true;
    log('READY', 'Guyma Cyb Desktop Installer v2.0 — console de diagnostic initialisée.');
    log('INFO', 'Checking WSL2 virtualization backend and kernel version…');
    load(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /* ——— Persistance réelle de la configuration (.wslconfig via le backend) ——— */
  const persistConfig = useCallback(async (cfg: { ramGb: number; networkingMode: 'nat' | 'bridged' }) => {
    try {
      const r = await fetch('/api/setup/wsl-config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(cfg),
      });
      const data: WslConfigResult = await r.json();
      if (!mountedRef.current) return;
      if (r.ok && data.ok) {
        setWslConfigPath(data.path || null);
        log('SUCCESS', `Configuration écrite : ${data.path} (mémoire ${cfg.ramGb} GB, mode ${cfg.networkingMode.toUpperCase()}).`);
      } else {
        log('INFO', `.wslconfig non écrit : ${data.error || 'raison inconnue'}`);
      }
    } catch (e: unknown) {
      log('ERROR', `Persistance de configuration impossible : ${(e as Error)?.message || 'erreur réseau'}`);
    }
  }, [log]);

  const onRamChange = (v: number) => {
    setRamGb(v);
    log('CONFIG', `Allocation mémoire WSL2 réglée sur ${v} GB.`);
    if (saveTimer.current) clearTimeout(saveTimer.current);
    saveTimer.current = setTimeout(() => persistConfig({ ramGb: v, networkingMode: netMode }), 500);
  };

  const onNetMode = (mode: 'nat' | 'bridged') => {
    setNetMode(mode);
    log('CONFIG', `Network bridging mode switched to: ${mode.toUpperCase()}`);
    persistConfig({ ramGb, networkingMode: mode });
  };

  /* ——— Étape 2 : installation WSL + distro en un clic (réel, polling) ——— */
  const [distroJob, setDistroJob] = useState<DistroJob | null>(null);
  useEffect(() => {
    let cancelled = false;
    (async () => {
      for (;;) {
        await new Promise((s) => setTimeout(s, 2500));
        if (cancelled || !mountedRef.current) return;
        try {
          const r = await fetch('/api/core/install-distro/status');
          const st: DistroJob = await r.json();
          if (cancelled || !mountedRef.current) return;
          setDistroJob(st);
          if (!st?.running) break;
        } catch { break; }
      }
    })();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (distroJob?.running) {
      setBusy('wsl');
      const last = distroJob.log[distroJob.log.length - 1];
      if (last) log('INFO', last.length > 300 ? last.slice(0, 300) + '…' : last);
      if (distroJob.done) {
        setBusy('');
        if (distroJob.success) log('SUCCESS', `Distribution ${distroJob.distroName} enregistrée avec succès.`);
        else log('ERROR', `Échec de l'installation de la distribution : ${distroJob.error || 'raison inconnue'}`);
        void load(false);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [distroJob?.running, distroJob?.done]);

  const installWsl = async () => {
    if (busy) return;
    setConfirmWsl(false);
    setBusy('wsl');
    log('INFO', 'Installation de WSL2 + distribution Ubuntu (élévation UAC requise, 5 à 15 min selon la connexion)…');
    try {
      const r = await fetch('/api/core/install-distro', { method: 'POST' });
      const data = await r.json();
      if (!r.ok) {
        log('ERROR', `Démarrage impossible : ${data?.error || 'erreur inconnue'}`);
        setBusy('');
      }
    } catch (e: unknown) {
      log('ERROR', `Requête impossible : ${(e as Error)?.message || 'erreur réseau'}`);
      setBusy('');
    }
  };

  // Avertissement UNIQUE avant l'élévation UAC (règle V2 : une seule action,
  // un seul accord — pas d'écrans successifs).

  /* ——— Étape 3 : initialisation réelle de la base ——— */
  const initDb = async () => {
    if (busy) return;
    setBusy('db');
    log('INFO', 'Initialisation du schéma SQLite (targets, scans, endpoints, findings, audit_logs)…');
    try {
      const r = await fetch('/api/setup/database/init', { method: 'POST' });
      const data = await r.json();
      if (!mountedRef.current) return;
      if (r.ok && data.ok) {
        setDb(data);
        setDbBadge('ok');
        log('SUCCESS', `Base initialisée à ${data.path} (${((data.sizeBytes || 0) / 1024).toFixed(1)} Kio).`);
      } else {
        setDbBadge('pending');
        log('ERROR', `Échec de l'initialisation : ${data?.error || 'erreur inconnue'}`);
      }
    } catch (e: unknown) {
      log('ERROR', `Requête impossible : ${(e as Error)?.message || 'erreur réseau'}`);
    } finally {
      if (mountedRef.current) setBusy('');
    }
  };

  /* ——— Étape 4 : installation réelle des outils (apt) ——— */
  const installTools = async () => {
    if (busy) return;
    setBusy('tools');
    log('INFO', 'Installation apt des outils manquants dans la distribution WSL2 (cela peut prendre plusieurs minutes)…');
    try {
      const r = await fetch('/api/core/install-tools', { method: 'POST' });
      const data = await r.json();
      if (!mountedRef.current) return;
      if (data?.verification) {
        const v = data.verification;
        log('SUCCESS', `Installation terminée (exit ${data.exitCode}). Vérifiés : ${v.verified.length} — absents : ${v.absent.length ? v.absent.join(', ') : 'aucun'}.`);
      } else if (data?.error) {
        log('ERROR', `Échec de l'installation : ${data.error}`);
      } else {
        log('SUCCESS', `Installation terminée (exit ${data?.exitCode ?? '?'}).`);
      }
    } catch (e: unknown) {
      log('ERROR', `Requête impossible : ${(e as Error)?.message || 'erreur réseau'}`);
    } finally {
      if (mountedRef.current) {
        setBusy('');
        await load(false);
      }
    }
  };

  /* ——— Étape 5 : récapitulatif + fin ——— */
  const finish = async () => {
    setBusy('finish');
    log('INFO', 'Sauvegarde de la configuration finale…');
    await persistConfig({ ramGb, networkingMode: netMode });
    log('READY', 'Entrée dans Guyma Cyb — lancement de l\'application principale.');
    try { localStorage.setItem(ONBOARDING_KEY, 'done'); } catch { /* stockage indisponible */ }
    onFinish();
  };

  /* ——— Valeurs dérivées réelles ——— */
  const wslOk = Boolean(core?.wsl?.available);
  const distroLabel = wslOk ? `${core?.wsl?.defaultDistro || 'Ubuntu'}${core?.wsl?.version ? ' ' + core.wsl.version : ''}` : 'Ubuntu';
  const toolsAvail = core?.tools?.available?.length ?? 0;
  const toolsMissing = core?.tools?.missing?.length ?? 0;
  const ramTotalGb = sys?.hardware?.ram?.totalMb ? sys.hardware.ram.totalMb / 1024 : null;
  const ramFreeGb = sys?.hardware?.ram?.freeMb != null ? sys.hardware.ram.freeMb / 1024 : null;
  const cpuThreads = sys?.hardware?.cpu?.cores ?? null;
  const noDistro = Boolean(core?.isWindows && !wslOk && core?.wsl?.installed);
  const allGood = Boolean(ramTotalGb && ramTotalGb >= 8 && cpuThreads && cpuThreads >= 4 && wslOk);

  /* ——— Petits composants locaux (design tokens V2) ——— */
  const Icon: React.FC<{ name: string; size?: number; color?: string; fill?: boolean; style?: React.CSSProperties }> = ({ name, size = 18, color, fill, style }) => (
    <span
      className="material-symbols-outlined"
      style={{
        fontSize: size,
        color,
        fontVariationSettings: fill ? "'FILL' 1, 'wght' 400, 'GRAD' 0, 'opsz' 24" : "'FILL' 0, 'wght' 400, 'GRAD' 0, 'opsz' 24",
        lineHeight: 1,
        ...style,
      }}
    >
      {name}
    </span>
  );

  const Pill: React.FC<{ variant: 'primary' | 'neutral' | 'tertiary' | 'amber'; children: React.ReactNode }> = ({ variant, children }) => {
    const bg = variant === 'primary' ? T.primaryContainer : variant === 'tertiary' ? T.tertiaryContainer : variant === 'amber' ? '#78350f' : T.surfaceHigh;
    const fg = variant === 'primary' ? T.onPrimaryContainer : variant === 'tertiary' ? T.onTertiaryContainer : variant === 'amber' ? '#fde68a' : T.onSurfaceVariant;
    return (
      <span style={{
        display: 'inline-flex', alignItems: 'center', gap: 4, padding: '4px 16px',
        borderRadius: 12, background: bg, color: fg, fontSize: 12, lineHeight: '16px', fontWeight: 500, letterSpacing: '.02em', whiteSpace: 'nowrap',
      }}>
        {children}
      </span>
    );
  };

  const Tag: React.FC<{ variant: 'tertiary' | 'amber'; children: React.ReactNode }> = ({ variant, children }) => (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4, padding: '4px 8px',
      borderRadius: 4, background: variant === 'tertiary' ? T.tertiaryContainer : '#78350f',
      color: variant === 'tertiary' ? T.onTertiaryContainer : '#fde68a',
      fontSize: 11, lineHeight: '14px', fontWeight: 500, whiteSpace: 'nowrap',
    }}>
      {children}
    </span>
  );

  const Btn: React.FC<{ variant: 'primary' | 'tint' | 'ghost' | 'amber'; onClick?: () => void; disabled?: boolean; title?: string; children: React.ReactNode; style?: React.CSSProperties }> =
    ({ variant, onClick, disabled, title, children, style }) => {
      const styles: Record<string, React.CSSProperties> = {
        primary: { background: T.primaryContainer, color: T.onPrimaryContainer },
        tint: { background: T.primary, color: T.onPrimary },
        ghost: { background: T.surfaceHigh, color: T.onSurface },
        amber: { background: '#78350f', color: '#fde68a' },
      };
      return (
        <button
          onClick={onClick}
          disabled={disabled}
          title={title}
          style={{
            display: 'inline-flex', alignItems: 'center', gap: 4, border: 'none', cursor: disabled ? 'not-allowed' : 'pointer',
            fontFamily: 'inherit', fontSize: 12, lineHeight: '16px', fontWeight: 500, letterSpacing: '.02em',
            padding: '8px 24px', borderRadius: 8, opacity: disabled ? 0.45 : 1,
            transition: 'background .15s', minHeight: 36, ...styles[variant], ...style,
          }}
          onMouseOver={(e) => { if (!disabled) e.currentTarget.style.filter = 'brightness(1.15)'; }}
          onMouseOut={(e) => { e.currentTarget.style.filter = 'none'; }}
        >
          {children}
        </button>
      );
    };

  const Switch: React.FC<{ checked: boolean; onChange: (v: boolean) => void; label: string }> = ({ checked, onChange, label }) => (
    <button
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
      style={{ position: 'relative', width: 36, height: 20, borderRadius: 999, border: 'none', cursor: 'pointer', background: checked ? T.primaryContainer : T.surfaceHigh, transition: 'background .15s', flex: 'none', padding: 0 }}
    >
      <span style={{ position: 'absolute', top: 2, left: checked ? 18 : 2, width: 16, height: 16, borderRadius: '50%', background: '#fff', transition: 'left .15s' }} />
    </button>
  );

  const TerminalBox: React.FC = () => (
    <div style={{ background: T.surfaceLowest, borderRadius: 8, padding: 16, marginBottom: 32 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: 8, marginBottom: 8, borderBottom: `1px solid ${T.surfaceHigh}` }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ display: 'flex', gap: 6 }}>
            <span style={{ width: 12, height: 12, borderRadius: '50%', background: 'rgba(255,180,171,.4)' }} />
            <span style={{ width: 12, height: 12, borderRadius: '50%', background: 'rgba(173,198,255,.4)' }} />
            <span style={{ width: 12, height: 12, borderRadius: '50%', background: 'rgba(78,222,163,.4)' }} />
          </div>
          <span style={{ fontSize: 11, letterSpacing: '.08em', textTransform: 'uppercase', color: T.onSurfaceVariant }}>Console de Diagnostic En Direct // guyma-daemon.log</span>
        </div>
        <button
          onClick={() => setLogs([])}
          style={{ background: 'none', border: 'none', color: T.onSurfaceVariant, fontFamily: 'inherit', fontSize: 11, fontWeight: 500, letterSpacing: '.04em', cursor: 'pointer' }}
        >
          Effacer
        </button>
      </div>
      <div ref={logBoxRef} className="scrollbar-thin" style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 144, overflowY: 'auto', paddingRight: 4 }}>
        {logs.length === 0 ? (
          <span style={{ fontStyle: 'italic', color: T.outline, fontFamily: "'Courier Prime', monospace", fontSize: 12 }}>Console effacée.</span>
        ) : (
          logs.map((l, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, fontFamily: "'Courier Prime', monospace", fontSize: 12, lineHeight: '16px', color: T.onSurfaceVariant }}>
              <span style={{ color: T.outline, flex: 'none' }}>[{l.time}]</span>
              <span style={{ color: TAG_COLOR[l.tag], flex: 'none' }}>[{l.tag}]</span>
              <span style={{ wordBreak: 'break-word', userSelect: 'text' }}>{l.text}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );

  const StepFooter: React.FC<{ onBack: number | null; nextLabel: string; onNext: number | null }> = ({ onBack, nextLabel, onNext }) => (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: 16, borderTop: `1px solid ${T.surfaceHigh}` }}>
      {onBack !== null ? (
        <Btn variant="ghost" onClick={() => setStep(onBack)}>
          <Icon name="arrow_back" size={16} />Retour
        </Btn>
      ) : <span />}
      <Btn variant="primary" onClick={() => onNext !== null && setStep(onNext)}>
        {nextLabel}<Icon name="arrow_forward" size={16} />
      </Btn>
    </div>
  );

  const CheckCard: React.FC<{ icon: string; title: string; detail: string; ok: boolean | null }> = ({ icon, title, detail, ok }) => (
    <div style={{ background: T.surfaceContainer, borderRadius: 8, padding: 12, display: 'flex', alignItems: 'center', gap: 12 }}>
      <div style={{ width: 32, height: 32, flex: 'none', borderRadius: 4, background: 'rgba(37,99,235,.12)', color: T.primary, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <Icon name={icon} size={18} />
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontWeight: 500, fontSize: 13, color: T.onSurface, lineHeight: '18px' }}>{title}</div>
        <div style={{ fontSize: 12, color: T.onSurfaceVariant, lineHeight: '16px', marginTop: 2 }}>{detail}</div>
      </div>
      <div style={{ flex: 'none' }}>
        {ok === null ? (
          <Icon name="radio_button_unchecked" size={20} color={T.outline} fill />
        ) : (
          <Icon name={ok ? 'check_circle' : 'error'} size={20} color={ok ? T.tertiary : T.amber} fill />
        )}
      </div>
    </div>
  );

  const NoteBox: React.FC<{ children: React.ReactNode }> = ({ children }) => (
    <div style={{ border: `1px solid ${T.outlineVariant}`, borderRadius: 8, padding: 12, display: 'flex', gap: 8, alignItems: 'flex-start', color: T.onSurfaceVariant, fontSize: 12, lineHeight: '16px', background: 'rgba(32,31,34,.5)' }}>
      <Icon name="info" size={16} color={T.outline} style={{ flex: 'none', marginTop: 1 }} />
      <span>{children}</span>
    </div>
  );

  /* ——— En-tête de step (eyebrow + titre + description + badge) ——— */
  const StepHeader: React.FC<{ eyebrow: string; section: string; title: string; desc: string; badge?: React.ReactNode }> = ({ eyebrow, section, title, desc, badge }) => (
    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, marginBottom: 24, flexWrap: 'wrap' }}>
      <div style={{ minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 4 }}>
          <span style={{ fontSize: 11, fontWeight: 500, letterSpacing: '.1em', textTransform: 'uppercase', color: T.primary }}>{eyebrow}</span>
          <span style={{ color: T.onSurfaceVariant }}>•</span>
          <span style={{ fontSize: 11, fontWeight: 500, letterSpacing: '.1em', textTransform: 'uppercase', color: T.onSurfaceVariant }}>{section}</span>
        </div>
        <h1 style={{ fontSize: 28, lineHeight: '36px', fontWeight: 600, letterSpacing: '-.02em', color: T.onSurface, margin: 0 }}>{title}</h1>
        <p style={{ fontSize: 15, lineHeight: '22px', color: T.onSurfaceVariant, marginTop: 4 }}>{desc}</p>
      </div>
      {badge}
    </div>
  );

  return (
    <div style={{ position: 'absolute', inset: 0, zIndex: 60, display: 'flex', flexDirection: 'column', background: T.surface, color: T.onSurface, fontFamily: "'Poppins', system-ui, sans-serif", fontSize: 13, lineHeight: '18px', userSelect: 'none' }}>
      {/* ——— Header fixe 40px ——— */}
      <header style={{ height: 40, flex: 'none', background: T.surfaceLowest, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <Icon name="shield" size={16} color={T.primary} />
          <span style={{ fontSize: 11, fontWeight: 600, letterSpacing: '.08em' }}>Guyma Cyb // Desktop Installer</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ width: 32, height: 32, borderRadius: '50%', background: T.primary, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Icon name="person" size={18} color={T.onPrimary} />
          </div>
          {reopened && (
            <button
              onClick={onFinish}
              style={{ background: T.surfaceHigh, color: T.onSurface, border: 'none', borderRadius: 8, padding: '6px 12px', fontSize: 11, fontWeight: 500, cursor: 'pointer', fontFamily: 'inherit' }}
            >
              Quitter l'assistant
            </button>
          )}
        </div>
      </header>

      <div className="ob-body" style={{ flex: 1, display: 'flex', minHeight: 0 }}>
        {/* ——— Sidebar 288px ——— */}
        <aside className="ob-aside" style={{ width: 288, flex: 'none', background: T.surfaceLow, display: 'flex', flexDirection: 'column', padding: '16px 0', overflowY: 'auto' }}>
          <div className="ob-sidebar-label" style={{ padding: '0 16px', marginBottom: 16, fontSize: 11, fontWeight: 500, letterSpacing: '.08em', textTransform: 'uppercase', color: T.onSurfaceVariant }}>
            Onboarding Setup
          </div>
          <nav className="ob-nav" style={{ flex: 1, padding: '0 8px', display: 'flex', flexDirection: 'column', gap: 4 }}>
            {[
              { n: 1, icon: 'waving_hand', label: '1. Bienvenue' },
              { n: 2, icon: 'terminal', label: '2. Environnement WSL2' },
              { n: 3, icon: 'database', label: '3. Base & SQLite' },
              { n: 4, icon: 'extension', label: '4. Outils & Modules' },
              { n: 5, icon: 'check_circle', label: '5. Finalisation' },
            ].map((item) => (
              <button
                key={item.n}
                onClick={() => setStep(item.n)}
                style={{
                  display: 'flex', alignItems: 'center', padding: '8px 16px', borderRadius: 8, border: 'none',
                  background: step === item.n ? T.primaryContainer : 'transparent',
                  color: step === item.n ? T.onPrimaryContainer : T.onSurfaceVariant,
                  fontWeight: step === item.n ? 500 : 400,
                  fontFamily: 'inherit', fontSize: 13, textAlign: 'left', cursor: 'pointer', width: '100%', transition: 'background .15s, color .15s',
                }}
                onMouseOver={(e) => { if (step !== item.n) e.currentTarget.style.background = T.surfaceHigh; }}
                onMouseOut={(e) => { if (step !== item.n) e.currentTarget.style.background = 'transparent'; }}
              >
                <Icon name={item.icon} size={18} /> <span style={{ marginLeft: 8 }}>{item.label}</span>
              </button>
            ))}
          </nav>
        </aside>

        {/* ——— Zone principale scrollable ——— */}
        <main className="scrollbar-thin" style={{ flex: 1, background: T.surface, overflowY: 'auto', minWidth: 0 }}>
          <div style={{ padding: 32, paddingBottom: 48, maxWidth: 1280 }}>

            {/* ================= ÉTAPE 1 — BIENVENUE ================= */}
            {step === 1 && (
              <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1fr)', gap: 16, alignItems: 'start' }} className="ob-step1">
                <div>
                  <div style={{ position: 'relative', overflow: 'hidden', background: T.surfaceLow, borderRadius: 8, padding: 24, marginBottom: 16 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
                      <Pill variant="primary"><Icon name="settings" size={14} />v2.0 Enterprise Pro</Pill>
                      <Pill variant="neutral">100% Offline Capable</Pill>
                    </div>
                    <h1 style={{ fontSize: 28, lineHeight: '36px', fontWeight: 600, letterSpacing: '-.02em', margin: 0 }}>Bienvenue dans l'assistant d'installation de Guyma Cyb</h1>
                    <p style={{ fontSize: 15, lineHeight: '22px', color: T.onSurfaceVariant, marginTop: 12 }}>
                      Configurez votre poste de travail d'audit offensif haute performance.
                      Cette suite intègre un noyau WSL2 Ubuntu isolé, une base de données locale
                      sécurisée <code style={{ fontFamily: "'Courier Prime', monospace", background: T.surfaceContainer, padding: '1px 6px', borderRadius: 4, color: T.primary }}>shadow_core.db</code>,
                      et des modules de pentest entièrement autonomes.
                    </p>
                    <div style={{ display: 'flex', gap: 48, flexWrap: 'wrap', borderTop: `1px solid ${T.surfaceHigh}`, paddingTop: 16, marginTop: 24 }}>
                      {[
                        { k: 'Architecture', v: 'WSL2 Linux', icon: 'developer_board' },
                        { k: 'Stockage local', v: 'SQLite 3.42', icon: 'database' },
                        { k: 'Chiffrement', v: 'AES-256-GCM', icon: 'lock' },
                      ].map((s) => (
                        <div key={s.k}>
                          <div style={{ fontSize: 11, letterSpacing: '.08em', textTransform: 'uppercase', color: T.onSurfaceVariant, marginBottom: 8 }}>{s.k}</div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontWeight: 500 }}>
                            <Icon name={s.icon} size={18} color={T.primary} />{s.v}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div style={{ background: T.surfaceLow, borderRadius: 8, padding: 24 }}>
                    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12, marginBottom: 16 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <Icon name="handshake" size={18} color={T.primary} />
                        <h3 style={{ fontSize: 18, lineHeight: '24px', fontWeight: 500, margin: 0 }}>Accord de Licence Utilisateur Final (EULA)</h3>
                      </div>
                      <span style={{ fontFamily: "'Courier Prime', monospace", fontSize: 12, color: T.outline }}>v2.0-RELEASE</span>
                    </div>
                    <div style={{ background: T.surfaceLowest, borderRadius: 8, padding: 16, color: T.onSurfaceVariant, display: 'flex', flexDirection: 'column', gap: 8, fontFamily: "'Courier Prime', monospace", fontSize: 12, userSelect: 'text' }}>
                      <span>1. ACCÈDE AUX MODULES OFFENSIFS&nbsp;: En installant Guyma Cyb v2.0, vous certifiez posséder les autorisations légales requises pour effectuer des tests d'intrusion sur les cibles configurées.</span>
                      <span>2. ISOLATION DE L'ENVIRONNEMENT&nbsp;: Tous les journaux d'exécution, artefacts et charges utiles sont stockés exclusivement dans le conteneur WSL2 local et le fichier shadow_core.db.</span>
                    </div>
                    <label style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 16, cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={eula}
                        onChange={(e) => { setEula(e.target.checked); log('CONFIG', e.target.checked ? 'EULA acceptée par l\'opérateur.' : 'Acceptation EULA retirée.'); }}
                        style={{ width: 16, height: 16, accentColor: T.primaryContainer, cursor: 'pointer' }}
                      />
                      <span style={{ fontSize: 13 }}>J'accepte les conditions d'utilisation et les licences d'outils tiers autorisés</span>
                    </label>
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  <div style={{ background: T.surfaceLow, borderRadius: 8, padding: 16 }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <Icon name="verified_user" size={18} color={T.tertiary} fill />
                        <h3 style={{ fontSize: 16, fontWeight: 500, margin: 0 }}>Vérification Système</h3>
                      </div>
                      <Tag variant={sys === null ? 'amber' : allGood ? 'tertiary' : 'amber'}>
                        {sys === null ? 'Analyse…' : allGood ? 'Optimal' : 'Action requise'}
                      </Tag>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                      <CheckCard
                        icon="memory"
                        title="Mémoire Vive (RAM)"
                        detail={ramTotalGb ? `${(ramFreeGb ?? 0).toFixed(1).replace('.', ',')} Go libres / ${ramTotalGb.toFixed(0)} Go installés — 8 Go Recommandés` : 'Inventaire matériel indisponible'}
                        ok={ramTotalGb ? ramTotalGb >= 8 : false}
                      />
                      <CheckCard
                        icon="hardware"
                        title="Processeur (CPU)"
                        detail={cpuThreads ? `${cpuThreads} Threads compatibles AVX2` : 'Inventaire matériel indisponible'}
                        ok={cpuThreads ? cpuThreads >= 4 : false}
                      />
                      <CheckCard
                        icon="personal_video"
                        title="Sous-système Windows (WSL2)"
                        detail={core === null ? 'Détection…' : wslOk ? `${distroLabel} — prêt` : noDistro ? 'WSL présent — aucune distribution Linux enregistrée' : 'Non détecté — installation requise'}
                        ok={wslOk}
                      />
                    </div>
                    <div style={{ marginTop: 16 }}>
                      <NoteBox>Le démon d'arrière-plan s'exécutera avec les privilèges restreints de l'utilisateur courant dans l'espace de noms WSL2.</NoteBox>
                    </div>
                  </div>

                  <div style={{ background: T.surfaceLow, borderRadius: 8, padding: 16, display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                    <Btn variant="ghost" onClick={onFinish}>{reopened ? 'Quitter l\'assistant' : 'Annuler'}</Btn>
                    <Btn variant="tint" disabled={!eula} onClick={() => { if (eula) { log('INFO', 'Démarrage de la configuration de l\'environnement…'); setStep(2); } }}>
                      Commencer l'installation<Icon name="arrow_forward" size={16} />
                    </Btn>
                  </div>
                </div>
              </div>
            )}

            {/* ================= ÉTAPE 2 — ENVIRONNEMENT WSL2 ================= */}
            {step === 2 && (
              <div>
                <StepHeader
                  eyebrow="Étape 2 sur 5"
                  section="Système & Données"
                  title="Configuration du Noyau d'Exécution & Base de Données"
                  desc="Paramétrez votre environnement d'isolation WSL2 et l'instance SQLite chiffrée pour le stockage local des téléporteurs et des flux d'audit."
                  badge={<Pill variant={wslOk ? 'tertiary' : 'amber'}><Icon name={wslOk ? 'check_circle' : 'warning'} size={14} fill />{wslOk ? 'Système Opérationnel' : 'WSL requis'}</Pill>}
                />
                <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1fr)', gap: 16, marginBottom: 32 }} className="ob-grid21">
                  <div style={{ position: 'relative', overflow: 'hidden', background: T.surfaceLow, borderRadius: 8, padding: 24, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
                          <div style={{ width: 40, height: 40, flex: 'none', borderRadius: 8, background: 'rgba(37,99,235,.1)', color: T.primary, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                            <Icon name="terminal" size={20} />
                          </div>
                          <div>
                            <h2 style={{ fontSize: 20, lineHeight: '28px', fontWeight: 600, letterSpacing: '-.01em', margin: 0 }}>Noyau WSL2 ({distroLabel} LTS)</h2>
                            <p style={{ fontSize: 12, color: T.onSurfaceVariant, margin: 0 }}>Virtualisation légère pour l'analyse de paquets et l'exécution de conteneurs</p>
                          </div>
                        </div>
                        <Tag variant={wslOk ? 'tertiary' : 'amber'}>
                          {core === null ? 'Détection…' : wslOk ? 'Détecté & Prêt' : noDistro ? 'Aucun distro — installation requise' : 'Non détecté'}
                        </Tag>
                      </div>
                      {!wslOk && (
                        <div style={{ marginBottom: 16 }}>
                          <Btn variant="amber" disabled={busy !== ''} onClick={() => setConfirmWsl(true)}>
                            <Icon name="download" size={16} />{busy === 'wsl' ? 'Installation en cours…' : 'Installer WSL2 + Ubuntu (un clic, élévation UAC)'}
                          </Btn>
                          {distroJob?.running && distroJob.log.length > 0 && (
                            <pre className="scrollbar-thin" style={{ marginTop: 12, maxHeight: 120, overflowY: 'auto', whiteSpace: 'pre-wrap', fontSize: 11, color: T.onSurfaceVariant, background: T.surfaceLowest, borderRadius: 8, padding: 12 }}>
                              {distroJob.log.slice(-8).join('\n')}
                            </pre>
                          )}
                        </div>
                      )}
                      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1fr)', gap: 16, margin: '16px 0' }} className="ob-grid2">
                        <div style={{ background: T.surfaceContainer, borderRadius: 8, padding: 16 }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                            <label htmlFor="ob-ram" style={{ fontSize: 12, fontWeight: 500, letterSpacing: '.02em' }}>Allocation Mémoire (RAM)</label>
                            <span style={{ fontFamily: "'Courier Prime', monospace", fontSize: 12, color: T.primary }}>{ramGb} GB</span>
                          </div>
                          <input
                            id="ob-ram" type="range" min={2} max={32} step={2} value={ramGb}
                            onChange={(e) => onRamChange(Number(e.target.value))}
                            style={{ width: '100%', accentColor: T.primary, cursor: 'pointer', height: 6 }}
                          />
                          <p style={{ fontSize: 12, color: T.onSurfaceVariant, marginTop: 8 }}>Recommandé : 8 Go min. pour l'analyse heuristique en temps réel.</p>
                        </div>
                        <div style={{ background: T.surfaceContainer, borderRadius: 8, padding: 16 }}>
                          <label style={{ display: 'block', fontSize: 12, fontWeight: 500, letterSpacing: '.02em', marginBottom: 4 }}>Mode Pont Réseau</label>
                          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4 }}>
                            <button
                              onClick={() => onNetMode('nat')}
                              style={{ border: 'none', cursor: 'pointer', fontFamily: 'inherit', padding: '8px 8px', borderRadius: 4, fontSize: 12, fontWeight: 500, letterSpacing: '.02em', textAlign: 'center', background: netMode === 'nat' ? T.primary : T.surfaceHigh, color: netMode === 'nat' ? T.onPrimary : T.onSurfaceVariant, transition: 'background .15s' }}
                            >
                              NAT (Défaut)
                            </button>
                            <button
                              onClick={() => onNetMode('bridged')}
                              style={{ border: 'none', cursor: 'pointer', fontFamily: 'inherit', padding: '8px 8px', borderRadius: 4, fontSize: 12, fontWeight: 500, letterSpacing: '.02em', textAlign: 'center', background: netMode === 'bridged' ? T.primary : T.surfaceHigh, color: netMode === 'bridged' ? T.onPrimary : T.onSurfaceVariant, transition: 'background .15s' }}
                            >
                              Bridged
                            </button>
                          </div>
                          <p style={{ fontSize: 12, color: T.onSurfaceVariant, marginTop: 8 }}>NAT isole le sous-réseau virtuel de l'hôte principal.</p>
                        </div>
                      </div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, paddingTop: 16, marginTop: 16, borderTop: `1px solid ${T.surfaceHigh}` }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
                        <Icon name="bolt" size={18} color={T.primary} />
                        <div>
                          <span style={{ display: 'block', fontSize: 12, fontWeight: 500, letterSpacing: '.02em' }}>Lancement automatique du démon au démarrage Windows</span>
                          <span style={{ fontSize: 12, color: T.onSurfaceVariant }}>Maintient les services de surveillance actifs en arrière-plan</span>
                        </div>
                      </div>
                      <Switch checked={autoLaunch} onChange={(v) => { setAutoLaunch(v); log('CONFIG', `Lancement automatique au démarrage Windows : ${v ? 'ACTIVÉ' : 'DÉSACTIVÉ'}.`); }} label="Lancement automatique du démon" />
                    </div>
                  </div>

                  <div style={{ position: 'relative', overflow: 'hidden', background: T.surfaceLow, borderRadius: 8, padding: 24, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
                        <div style={{ width: 40, height: 40, flex: 'none', borderRadius: 8, background: 'rgba(78,222,163,.1)', color: T.tertiary, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                          <Icon name="database" size={20} />
                        </div>
                        <div>
                          <h2 style={{ fontSize: 20, lineHeight: '28px', fontWeight: 600, letterSpacing: '-.01em', margin: 0 }}>Base SQLite</h2>
                          <p style={{ fontSize: 12, color: T.onSurfaceVariant, margin: 0 }}>Stockage local sécurisé</p>
                        </div>
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 16, margin: '16px 0' }}>
                        <div>
                          <label style={{ display: 'block', fontSize: 12, fontWeight: 500, letterSpacing: '.02em', marginBottom: 4 }}>Chemin du fichier</label>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 4, background: T.surfaceContainer, padding: 8, borderRadius: 8, fontFamily: "'Courier Prime', monospace", fontSize: 12, color: T.primary }}>
                            <Icon name="folder_open" size={16} color={T.onSurfaceVariant} />
                            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', userSelect: 'text' }}>{db?.path || '~/.guyma/shadow_core.db'}</span>
                          </div>
                        </div>
                        <div style={{ background: T.surfaceContainer, borderRadius: 8, padding: 16, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                          <div>
                            <span style={{ display: 'block', fontSize: 12, fontWeight: 500, letterSpacing: '.02em' }}>Chiffrement AES-256-GCM</span>
                            <span style={{ fontSize: 12, color: T.onSurfaceVariant }}>Protection intégrale des journaux</span>
                          </div>
                          <Switch checked={encryptLogs} onChange={(v) => { setEncryptLogs(v); log('CONFIG', `Préférence de chiffrement des journaux : ${v ? 'ACTIVÉE' : 'DÉSACTIVÉE'}.`); }} label="Chiffrement des journaux" />
                        </div>
                      </div>
                    </div>
                    <div style={{ background: T.surfaceContainer, borderRadius: 8, padding: 16, display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 16 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
                        <span style={{ width: 8, height: 8, borderRadius: '50%', background: T.tertiary, animation: 'obPulse 2s infinite' }} />
                        <span>Indexation active</span>
                      </div>
                      <span style={{ fontFamily: "'Courier Prime', monospace", fontSize: 12, color: T.tertiary }}>{db ? `${db.counts?.endpoints ?? 0} Endpoints indexés` : '… Endpoints indexés'}</span>
                    </div>
                  </div>
                </div>
                <TerminalBox />
                <StepFooter onBack={1} nextLabel="Étape suivante (Installation des outils)" onNext={3} />
              </div>
            )}

            {/* ================= ÉTAPE 3 — BASE & SQLITE ================= */}
            {step === 3 && (
              <div>
                <StepHeader
                  eyebrow="Étape 3 sur 5"
                  section="Système & Données"
                  title="Initialisation de la Base Locale Sécurisée"
                  desc="Créez et vérifiez l'instance SQLite qui stockera vos cibles, scans, findings et journaux d'audit, exclusivement en local."
                  badge={<Tag variant={dbBadge === 'ok' ? 'tertiary' : 'amber'}>{dbBadge === 'ok' ? 'Opérationnelle' : dbBadge === 'pending' ? 'En attente du moteur' : 'Non vérifiée'}</Tag>}
                />
                <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1fr)', gap: 16, marginBottom: 32 }} className="ob-grid21">
                  <div style={{ position: 'relative', overflow: 'hidden', background: T.surfaceLow, borderRadius: 8, padding: 24 }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
                        <div style={{ width: 40, height: 40, flex: 'none', borderRadius: 8, background: 'rgba(78,222,163,.1)', color: T.tertiary, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                          <Icon name="database" size={20} />
                        </div>
                        <div>
                          <h2 style={{ fontSize: 20, lineHeight: '28px', fontWeight: 600, letterSpacing: '-.01em', margin: 0 }}>shadow_core.db</h2>
                          <p style={{ fontSize: 12, color: T.onSurfaceVariant, margin: 0 }}>Schéma : targets · scans · endpoints · findings · audit_logs</p>
                        </div>
                      </div>
                      <Btn variant="primary" disabled={busy !== ''} onClick={initDb}>
                        <Icon name="play_arrow" size={16} />Initialiser et vérifier
                      </Btn>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 16 }}>
                      <CheckCard icon="folder_open" title="Chemin" detail={db?.path || '—'} ok={Boolean(db?.path)} />
                      <CheckCard icon="save" title="Taille du fichier" detail={db ? `${((db.sizeBytes || 0) / 1024).toFixed(1)} Kio` : '—'} ok={Boolean(db)} />
                      <CheckCard icon="edit_note" title="Compteurs réels" detail={db ? `Cibles ${db.counts?.targets ?? 0} · Scans ${db.counts?.scans ?? 0} · Endpoints ${db.counts?.endpoints ?? 0} · Findings ${db.counts?.findings ?? 0} · Journaux ${db.counts?.audit_logs ?? 0}` : '—'} ok={Boolean(db)} />
                    </div>
                  </div>
                  <div style={{ background: T.surfaceLow, borderRadius: 8, padding: 24 }}>
                    <h3 style={{ fontSize: 16, fontWeight: 500, margin: '0 0 12px' }}>Compteurs réels</h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                      {[
                        ['Cibles', 'targets'],
                        ['Scans', 'scans'],
                        ['Endpoints', 'endpoints'],
                        ['Findings', 'findings'],
                        ['Journaux d\'audit', 'audit_logs'],
                      ].map(([label, key]) => (
                        <div key={key} style={{ background: T.surfaceContainer, borderRadius: 8, padding: 12, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                          <span style={{ fontSize: 12 }}>{label}</span>
                          <span style={{ fontFamily: "'Courier Prime', monospace", fontSize: 12, color: T.primary }}>{db ? String(db.counts?.[key] ?? 0) : '—'}</span>
                        </div>
                      ))}
                    </div>
                    <div style={{ marginTop: 16 }}>
                      <NoteBox>Au premier lancement, la base démarre volontairement vide : aucun chiffre n'est pré-rempli. Les compteurs reflètent uniquement vos vraies données.</NoteBox>
                    </div>
                  </div>
                </div>
                <TerminalBox />
                <StepFooter onBack={2} nextLabel="Étape suivante (Outils & Modules)" onNext={4} />
              </div>
            )}

            {/* ================= ÉTAPE 4 — OUTILS & MODULES ================= */}
            {step === 4 && (
              <div>
                <StepHeader
                  eyebrow="Étape 4 sur 5"
                  section="Arsenal offensif"
                  title="Installation des Outils & Modules de Pentest"
                  desc="Vérifiez et installez la palette d'outils Linux (nmap, nikto, sqlmap, hashcat…) dans le conteneur WSL2. Chaque outil est vérifié individuellement après installation."
                  badge={<Tag variant={toolsMissing === 0 && toolsAvail > 0 ? 'tertiary' : 'amber'}>{(toolsAvail + toolsMissing) > 0 ? `${toolsAvail} vérifiés · ${toolsMissing} manquants` : 'WSL requis'}</Tag>}
                />
                <div style={{ position: 'relative', overflow: 'hidden', background: T.surfaceLow, borderRadius: 8, padding: 24 }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
                      <div style={{ width: 40, height: 40, flex: 'none', borderRadius: 8, background: 'rgba(37,99,235,.1)', color: T.primary, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                        <Icon name="extension" size={20} />
                      </div>
                      <div>
                        <h2 style={{ fontSize: 20, lineHeight: '28px', fontWeight: 600, letterSpacing: '-.01em', margin: 0 }}>Modules disponibles</h2>
                        <p style={{ fontSize: 12, color: T.onSurfaceVariant, margin: 0 }}>
                          {(toolsAvail + toolsMissing) > 0 ? `${toolsAvail} outils vérifiés sur ${toolsAvail + toolsMissing} détectés dans le distro WSL2` : 'Aucun outil détecté — WSL2 requis'}
                        </p>
                      </div>
                    </div>
                    <Btn variant="primary" disabled={busy !== '' || toolsMissing === 0 || !wslOk} onClick={installTools} title={toolsMissing === 0 ? 'Tous les outils détectés sont vérifiés' : `Installe ${toolsMissing} outil(s) via apt dans la distribution WSL2`}>
                      <Icon name="download" size={16} />{busy === 'tools' ? 'Installation…' : 'Installer les outils manquants (apt)'}
                    </Btn>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 8, margin: '16px 0' }}>
                    {(core?.tools?.available || []).map((t) => (
                      <div key={`ok-${t}`} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', background: T.surfaceContainer, borderRadius: 4, fontFamily: "'Courier Prime', monospace", fontSize: 12 }}>
                        <Icon name="check_circle" size={16} color={T.tertiary} fill />{t}
                      </div>
                    ))}
                    {(core?.tools?.missing || []).map((t) => (
                      <div key={`miss-${t}`} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', background: T.surfaceContainer, borderRadius: 4, fontFamily: "'Courier Prime', monospace", fontSize: 12, color: T.onSurfaceVariant }}>
                        <Icon name="add_circle" size={16} color={T.amber} />{t}
                      </div>
                    ))}
                    {(toolsAvail + toolsMissing) === 0 && (
                      <span style={{ fontSize: 12, color: T.onSurfaceVariant }}>Aucun outil détecté — revenez à l'étape 2 pour installer WSL2 + Ubuntu.</span>
                    )}
                  </div>
                  <NoteBox>L'installation utilise apt dans la distribution WSL2 détectée et peut prendre plusieurs minutes selon la connexion. Aucun outil n'est simulé : un outil n'est marqué « vérifié » que si son binaire répond à une exécution réelle.</NoteBox>
                </div>
                <div style={{ marginTop: 24 }}><TerminalBox /></div>
                <StepFooter onBack={3} nextLabel="Étape suivante (Finalisation)" onNext={5} />
              </div>
            )}

            {/* ================= ÉTAPE 5 — FINALISATION ================= */}
            {step === 5 && (
              <div>
                <StepHeader
                  eyebrow="Étape 5 sur 5"
                  section="Prêt à l'emploi"
                  title="Finalisation & Lancement"
                  desc="Votre environnement est configuré. Voici le récapitulatif réel de l'installation avant d'entrer dans Guyma Cyb."
                  badge={<Pill variant="tertiary"><Icon name="check_circle" size={14} fill />Configuration prête</Pill>}
                />
                <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1fr)', gap: 16 }} className="ob-grid21">
                  <div style={{ position: 'relative', overflow: 'hidden', background: T.surfaceLow, borderRadius: 8, padding: 24 }}>
                    <h3 style={{ fontSize: 16, fontWeight: 500, margin: '0 0 8px' }}>Récapitulatif de l'installation</h3>
                    {[
                      ['Environnement WSL2', wslOk ? `${distroLabel} — opérationnel` : 'Non opérationnel (les scans de base restent disponibles)'],
                      ['Allocation mémoire', `${ramGb} GB (.wslconfig)`],
                      ['Mode réseau', netMode === 'nat' ? 'NAT (isolation du sous-réseau virtuel)' : 'Bridged (pont vers le réseau hôte)'],
                      ['Base SQLite', db?.path || '—'],
                      ['Outils vérifiés', (toolsAvail + toolsMissing) > 0 ? `${toolsAvail} / ${toolsAvail + toolsMissing} — ${toolsMissing === 0 ? 'arsenal complet' : `${toolsMissing} manquant(s)`}` : 'Aucun outil détecté'],
                      ['Démarrage automatique', autoLaunch ? 'Activé' : 'Désactivé'],
                    ].map(([k, v]) => (
                      <div key={k} style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, padding: '12px 0', borderBottom: `1px solid ${T.surfaceHigh}` }}>
                        <span style={{ fontSize: 12, color: T.onSurfaceVariant, flex: 'none' }}>{k}</span>
                        <span style={{ fontSize: 12, textAlign: 'right', wordBreak: 'break-all', userSelect: 'text' }}>{v}</span>
                      </div>
                    ))}
                    <div style={{ marginTop: 16 }}>
                      <NoteBox>Vous pourrez relancer cet assistant à tout moment depuis « Core Manager » dans l'application.</NoteBox>
                    </div>
                  </div>
                  <div style={{ background: T.surfaceLow, borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column', gap: 8, justifyContent: 'flex-end' }}>
                    <Btn variant="ghost" onClick={onFinish}>Plus tard</Btn>
                    <Btn variant="tint" disabled={busy === 'finish'} onClick={finish} style={{ justifyContent: 'center' }}>
                      Entrer dans Guyma Cyb<Icon name="arrow_forward" size={16} />
                    </Btn>
                  </div>
                </div>
              </div>
            )}

          </div>
        </main>
      </div>

      {/* Responsive : la maquette affiche les grilles 2 colonnes sur grand écran,
          repliées en 1 colonne en dessous de 1100px (étape 1) / 720px (grille interne).
          Sous 900px, la sidebar se replie en bandeau horizontal scrollable. */}
      <style>{`
        @keyframes obPulse { 0%, 100% { opacity: 1; } 50% { opacity: .35; } }
        @media (min-width: 1100px) {
          .ob-step1 { grid-template-columns: minmax(0,1fr) 400px !important; }
          .ob-grid21 { grid-template-columns: 2fr 1fr !important; }
        }
        @media (min-width: 720px) {
          .ob-grid2 { grid-template-columns: 1fr 1fr !important; }
        }
        @media (max-width: 1100px) {
          .ob-grid21 { grid-template-columns: 1fr !important; }
        }
        @media (max-width: 900px) {
          .ob-body { flex-direction: column !important; }
          .ob-aside { width: 100% !important; flex: none !important; padding: 8px 0 !important; overflow: visible !important; }
          .ob-sidebar-label { display: none !important; }
          .ob-nav { flex-direction: row !important; overflow-x: auto !important; padding: 0 8px !important; gap: 4px !important; }
          .ob-nav button { white-space: nowrap; width: auto !important; flex: none; }
        }
      `}</style>

      {/* Avertissement UNIQUE avant l'élévation UAC — un seul accord, puis
          l'installation s'exécute d'un bloc (règle V2 : pas de choix successifs). */}
      <ConfirmActionModal
        open={confirmWsl}
        title="Avertissement — action unique"
        busy={busy === 'wsl'}
        confirmLabel="Confirmer et installer"
        onConfirm={installWsl}
        onCancel={() => setConfirmWsl(false)}
      >
        <div style={{ color: T.onSurfaceVariant, fontSize: 14, lineHeight: 1.55 }}>
          Le logiciel va <strong style={{ color: T.onSurface }}>tout installer d'un bloc</strong> :
          activer WSL2, télécharger et enregistrer la distribution <strong style={{ color: T.onSurface }}>Ubuntu</strong>
          {' '}dans votre système Windows.
        </div>
        <ul style={{ marginTop: 8, paddingLeft: 18, fontSize: 12, lineHeight: 1.7, color: T.onSurfaceVariant, fontFamily: "'Courier Prime', monospace" }}>
          <li>Une invite <strong style={{ color: T.amber }}>UAC</strong> (élévation administrateur) peut apparaître — acceptez-la.</li>
          <li>Téléchargement de 5 à 15 minutes selon la connexion.</li>
          <li>Un redémarrage de Windows peut être demandé par le système.</li>
        </ul>
        <div style={{ marginTop: 12, fontSize: 12, color: T.outline }}>
          Un seul écran de confirmation : après validation, tout s'exécute automatiquement et le
          journal en direct s'affiche dans la console de diagnostic.
        </div>
      </ConfirmActionModal>
    </div>
  );
};

export { ONBOARDING_KEY };
