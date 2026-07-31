import React, { useState, useMemo, useEffect, useRef } from 'react';
import './App.css';
import { Panel }              from './components/Panel';
import { HakamStatus }      from './components/HakamStatus';
import { EventLog }           from './components/EventLog';
import { InterceptSplash }    from './components/InterceptSplash';
import { TopologyMap }        from './components/TopologyMap';
import { KeyboardOverlay }    from './components/KeyboardOverlay';
import { AttackTimeline }     from './components/AttackTimeline';
import { SplitView }          from './components/SplitView';
import { MobileView }         from './components/MobileView';
import { useHakamData, FAMILY_COLOR, RecentAttack } from './utils/websocket';
import { Maximize2, Minimize2, Volume2, VolumeX, X } from 'lucide-react';
import { unlockAudio, playIntercept } from './utils/sound';
import { motion, AnimatePresence } from 'framer-motion';

// Below this width the HUD grid is swapped for the MobileView fallback.
const MOBILE_MAX_WIDTH_PX = 900;

function useIsMobile(): boolean {
  const query = `(max-width: ${MOBILE_MAX_WIDTH_PX}px)`;
  const [matches, setMatches] = useState(() => window.matchMedia(query).matches);
  useEffect(() => {
    const mql = window.matchMedia(query);
    const handler = (e: MediaQueryListEvent) => setMatches(e.matches);
    mql.addEventListener('change', handler);
    return () => mql.removeEventListener('change', handler);
  }, [query]);
  return matches;
}

// Ambient tint + header border color per threat level — subtle, not alarming
const THREAT_AMBIENT: Record<number, string> = {
  5: 'transparent',
  4: 'rgba(251,191,36,0.018)',
  3: 'rgba(251,191,36,0.030)',
  2: 'rgba(249,115,22,0.038)',
  1: 'rgba(239,68,68,0.048)',
};
const THREAT_BORDER: Record<number, string> = {
  5: 'var(--border-dim)',
  4: 'rgba(251,191,36,0.22)',
  3: 'rgba(251,191,36,0.30)',
  2: 'rgba(249,115,22,0.40)',
  1: 'rgba(239,68,68,0.55)',
};

export default function App() {
  const {
    logs, metrics, threatState,
    familyCounts, threatLevel, splash, lastBlockTick, lastBenignTick, scenario,
    recentAttacks, benignRate, sendDemoCommand,
    wsConnected, isStale,
  } = useHakamData();

  const isMobile = useIsMobile();

  const connected  = wsConnected && !isStale;
  const anyBlocked = Object.values(threatState.nodes).some(n => n.blocked);

  const threatsBlocked = useMemo(
    () => Object.values(familyCounts).reduce((a, b) => a + (b ?? 0), 0),
    [familyCounts]
  );

  // Detection rate — attacks in last 30 s
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setTick(t => t + 1), 1000);
    return () => clearInterval(id);
  }, []);
  const blockTs = useRef<number[]>([]);
  useEffect(() => {
    if (lastBlockTick) blockTs.current.push(lastBlockTick);
    blockTs.current = blockTs.current.filter(t => Date.now() - t <= 30_000);
  }, [lastBlockTick, tick]);
  const detectionRate = blockTs.current.length / 30;

  const startedAt = useRef<number>(Date.now()).current;

  // ── Session clock ──────────────────────────────────────────────────────────
  const [sessionClock, setSessionClock] = useState('00:00:00');
  const [sessionLong, setSessionLong] = useState(false);
  useEffect(() => {
    const id = setInterval(() => {
      const s = Math.floor((Date.now() - startedAt) / 1000);
      const h = Math.floor(s / 3600).toString().padStart(2, '0');
      const m = Math.floor((s % 3600) / 60).toString().padStart(2, '0');
      const sec = (s % 60).toString().padStart(2, '0');
      setSessionClock(`${h}:${m}:${sec}`);
      setSessionLong(s > 1800); // amber after 30 min
    }, 1000);
    return () => clearInterval(id);
  }, [startedAt]);

  // ── Split view (V key) ────────────────────────────────────────────────────
  const [splitOpen, setSplitOpen] = useState(false);

  // ── Event-log fullscreen toggle ───────────────────────────────────────────
  const [logFullscreen, setLogFullscreen] = useState(false);

  // Track session peak rate for the split view center panel
  const peakRateRef = useRef(0);
  useEffect(() => {
    if (detectionRate > peakRateRef.current) peakRateRef.current = detectionRate;
  }, [detectionRate]);

  // ── Sound ─────────────────────────────────────────────────────────────────
  const [soundOn, setSoundOn] = useState(false);
  useEffect(() => {
    if (lastBlockTick && soundOn) playIntercept();
  }, [lastBlockTick]);

  // ── Fullscreen ─────────────────────────────────────────────────────────────
  const [isFullscreen, setIsFullscreen] = useState(false);
  useEffect(() => {
    const handler = () => setIsFullscreen(!!document.fullscreenElement);
    document.addEventListener('fullscreenchange', handler);
    return () => document.removeEventListener('fullscreenchange', handler);
  }, []);
  const toggleFullscreen = () => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().catch(() => {});
    } else {
      document.exitFullscreen().catch(() => {});
    }
  };

  // ── Keyboard overlay (press `?` to toggle) + fullscreen (F) ───────────────
  const [helpOpen, setHelpOpen] = useState(false);
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      if (target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable)) return;

      // UI-only shortcuts — don't forward to demo-cycle.sh.
      if (e.key === '?' || e.key === '/') {
        e.preventDefault();
        setHelpOpen(o => !o);
        return;
      }
      if (e.key === 'Escape') {
        setHelpOpen(false);
        setLogFullscreen(false);
        return;
      }
      if (e.key === 'f' || e.key === 'F') {
        e.preventDefault();
        toggleFullscreen();
        return;
      }
      if (e.key === 'm' || e.key === 'M') {
        e.preventDefault();
        unlockAudio();
        setSoundOn(s => !s);
        return;
      }
      if (e.key === 'v' || e.key === 'V') {
        e.preventDefault();
        setSplitOpen(o => !o);
        return;
      }

      // Demo controls — forwarded to demo-cycle.sh via the WS. Pre-filtered
      // here so unrelated keystrokes don't flood the socket; server validates.
      if (e.key === ' ') {
        e.preventDefault();
        sendDemoCommand(' ');
        return;
      }
      if (e.key === 'n' || e.key === 'N') {
        e.preventDefault();
        sendDemoCommand('n');
        return;
      }
      if (e.key === 'r' || e.key === 'R') {
        e.preventDefault();
        sendDemoCommand('r');
        return;
      }
      if (e.key === 'q' || e.key === 'Q') {
        // No preventDefault — Q has no native browser binding to intercept.
        sendDemoCommand('q');
        return;
      }
      if (/^[0-6]$/.test(e.key)) {
        e.preventDefault();
        sendDemoCommand(e.key);
        return;
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [sendDemoCommand]);

  const ambientColor  = THREAT_AMBIENT[threatLevel] ?? 'transparent';
  const headerBorder  = THREAT_BORDER[threatLevel] ?? 'var(--border-dim)';

  if (isMobile) {
    return (
      <MobileView
        threatsBlocked={threatsBlocked}
        recentAttacks={recentAttacks}
        wsConnected={wsConnected}
        isStale={isStale}
      />
    );
  }

  return (
    <div onClick={unlockAudio} style={{ display: 'flex', flexDirection: 'column', height: '100vh', width: '100vw', overflow: 'hidden' }}>

      <div style={{ position: 'fixed', inset: 0, background: 'var(--bg)', zIndex: 0 }} />
      <div className="dot-grid" style={{ position: 'fixed', inset: 0, zIndex: 1, pointerEvents: 'none', opacity: 0.30 }} />

      {/* ── Threat-level ambient color wash ── */}
      <div style={{
        position: 'fixed', inset: 0, zIndex: 2, pointerEvents: 'none',
        background: ambientColor,
        transition: 'background 1.2s ease',
      }} />

      {/* ── Header ── */}
      <header style={{
        position: 'relative', zIndex: 30, flexShrink: 0,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: `0 var(--sp-5)`, height: 44,
        borderBottom: `1px solid ${headerBorder}`,
        background: 'rgba(7,10,13,0.92)', backdropFilter: 'blur(16px)',
        transition: 'border-color 1.2s ease',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-4)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-2)' }}>
            <svg width="18" height="18" viewBox="0 0 16 16" fill="none">
              <rect x="1" y="1" width="6" height="6" stroke="var(--text-bright)" strokeWidth="1.4"/>
              <rect x="9" y="1" width="6" height="6" stroke="var(--text-bright)" strokeWidth="1.4" opacity=".5"/>
              <rect x="1" y="9" width="6" height="6" stroke="var(--text-bright)" strokeWidth="1.4" opacity=".5"/>
              <rect x="9" y="9" width="6" height="6" stroke="var(--text-bright)" strokeWidth="1.4" opacity=".25"/>
            </svg>
            <span style={{ fontSize: 'var(--fs-body)', fontWeight: 700, color: 'var(--text-bright)', letterSpacing: 'var(--ls-label)' }}>
              HAKAM
            </span>
            <span style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-dim)', letterSpacing: 'var(--ls-label)', marginLeft: 'var(--sp-2)', fontWeight: 500 }}>
              KERNEL-RESIDENT eBPF FIREWALL
            </span>
          </div>
          <div style={{ display: 'flex', gap: 2, marginLeft: 'var(--sp-3)' }}>
            {['[01] STATUS', '[02] STREAM', '[03] TACTICS'].map(t => (
              <span key={t} className="hk-tab active">{t}</span>
            ))}
          </div>
          {/* Fires ONE real attack at the kernel datapath (via the VM's
              attack-on-demand.sh watcher) so the interception below is genuine. */}
          <button
            onClick={() => sendDemoCommand('a')}
            title="Fire one real attack at the kernel datapath and watch Hakam block it live"
            style={{
              marginLeft: 'var(--sp-4)',
              display: 'inline-flex', alignItems: 'center', gap: 'var(--sp-1)',
              padding: '5px 12px',
              background: 'rgba(255,82,82,0.10)',
              border: '1px solid rgba(255,82,82,0.45)',
              borderRadius: 'var(--r-chip)',
              color: 'var(--danger)',
              fontSize: 'var(--fs-micro)', fontWeight: 700,
              letterSpacing: 'var(--ls-label)', cursor: 'pointer',
              textTransform: 'uppercase', whiteSpace: 'nowrap',
            }}
          >
            ⚡ Simulate Attack
          </button>
          {/* Fires a documented EVASION payload (double-encoded) the DPI can't
              catch; the target reports it reached through → shown as EVADED. */}
          <button
            onClick={() => sendDemoCommand('e')}
            title="Fire an attack Hakam cannot detect (documented evasion) and watch it reach the target undetected"
            style={{
              marginLeft: 'var(--sp-2)',
              display: 'inline-flex', alignItems: 'center', gap: 'var(--sp-1)',
              padding: '5px 12px',
              background: 'rgba(245,179,92,0.10)',
              border: '1px solid rgba(245,179,92,0.45)',
              borderRadius: 'var(--r-chip)',
              color: 'var(--warn)',
              fontSize: 'var(--fs-micro)', fontWeight: 700,
              letterSpacing: 'var(--ls-label)', cursor: 'pointer',
              textTransform: 'uppercase', whiteSpace: 'nowrap',
            }}
          >
            ⚠ Simulate Evasion
          </button>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-5)' }}>
          {/* Session uptime */}
          <span className="hk-num" style={{
            fontSize: 'var(--fs-micro)',
            letterSpacing: 'var(--ls-label)', fontWeight: 500,
            color: sessionLong ? 'var(--warn)' : 'var(--text-muted)',
            transition: 'color 1s ease',
          }}>
            SESSION {sessionClock}
          </span>

          {scenario && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 'var(--sp-2)',
              padding: '3px var(--sp-2)',
              background: 'rgba(255,255,255,0.030)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--r-chip)',
            }}>
              <span style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-muted)', letterSpacing: 'var(--ls-label)' }}>SCENARIO</span>
              <span style={{ fontSize: 'var(--fs-micro)', fontWeight: 700, letterSpacing: 'var(--ls-label)', color: 'var(--text-bright)' }}>
                {scenario.label}
              </span>
              <span style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-muted)' }}>
                {scenario.phase}/{scenario.total}
              </span>
            </div>
          )}

          <NowPlaying recentAttacks={recentAttacks} anyBlocked={anyBlocked} tick={tick} />

          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-1)' }}>
            <span className={`status-dot ${
              !wsConnected ? 'bad pulse' : isStale ? 'warn' : ''
            }`} />
            <span style={{
              fontSize: 'var(--fs-micro)', letterSpacing: 'var(--ls-label)', fontWeight: 600,
              color: !wsConnected ? 'var(--danger)'
                   : isStale     ? 'var(--warn)'
                                 : 'var(--accent-2)',
            }}>
              {!wsConnected ? 'RECONNECTING' : isStale ? 'STALE_FEED' : 'KERNEL_LINK'}
            </span>
          </div>
          <span style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-dim)', letterSpacing: 'var(--ls-label)' }}>v0.1.0</span>
        </div>
      </header>

      <main style={{
        position: 'relative',
        flex: 1,
        overflow: 'hidden',
        zIndex: 20,
        display: 'grid',
        gridTemplateColumns: 'minmax(360px, 26%) minmax(0, 1fr)',
        gridTemplateRows: 'minmax(0, 1fr) 220px 116px',
        gridTemplateAreas: `
          "status   topology"
          "status   eventlog"
          "timeline timeline"
        `,
        gap: 'var(--sp-3)',
        padding: 'var(--sp-3)',
      }}>

        <Panel
          label="HAKAM_STATUS"
          tag={!wsConnected ? '◯ OFFLINE' : isStale ? '◌ STALE' : '◉ LIVE'}
          scrollable
          style={{ gridArea: 'status' }}
        >
          <HakamStatus
            connected={connected}
            metrics={metrics}
            threatLevel={threatLevel}
            threatsBlocked={threatsBlocked}
            familyCounts={familyCounts}
            detectionRate={detectionRate}
            benignRate={benignRate}
            anyBlocked={anyBlocked}
            logs={logs}
            lastBlockTick={lastBlockTick}
            startedAt={startedAt}
            recentAttacks={recentAttacks}
          />
        </Panel>

        {/* ── NETWORK TOPOLOGY ── */}
        <Panel
          label="NETWORK_TOPOLOGY"
          tag="LIVE_MAP"
          style={{ gridArea: 'topology' }}
        >
          <TopologyMap threatState={threatState} blockTick={lastBlockTick} benignTick={lastBenignTick} />
        </Panel>

        {/* ── ATTACK TIMELINE ── */}
        <Panel
          label="ATTACK_TIMELINE"
          tag={`${recentAttacks.length} INTERCEPTS`}
          style={{ gridArea: 'timeline' }}
        >
          <AttackTimeline events={recentAttacks} startedAt={startedAt} />
        </Panel>

        <Panel
          label="EVENT_LOG"
          style={{ gridArea: 'eventlog' }}
          actions={
            <button
              onClick={() => setLogFullscreen(true)}
              title="Expand (Esc to close)"
              className="hk-footer-btn"
              style={{ padding: '2px 6px' }}
            >
              <Maximize2 size={9} strokeWidth={2} />
              <span>FULL</span>
            </button>
          }
        >
          <EventLog logs={logs} />
        </Panel>
      </main>

      {/* ── Footer ── */}
      <footer style={{
        position: 'relative', zIndex: 30, flexShrink: 0,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '0 var(--sp-5)', height: 28,
        borderTop: '1px solid var(--border-dim)',
        background: 'rgba(7,10,13,0.92)', backdropFilter: 'blur(16px)',
        fontSize: 'var(--fs-micro)', letterSpacing: 'var(--ls-label)', color: 'var(--text-dim)', fontWeight: 500,
      }}>
        <span>[NULL_SAFETY_REJECTED] © HAKAM_KRNEL</span>
        <span style={{ display: 'flex', gap: 'var(--sp-4)', alignItems: 'center' }}>
          <button
            onClick={e => { e.stopPropagation(); setSplitOpen(o => !o); }}
            title="Protected vs Vulnerable (V)"
            className={`hk-footer-btn is-danger ${splitOpen ? 'is-on' : ''}`}
          >
            <span>⚔</span>
            <span>COMPARE</span>
          </button>

          <button
            onClick={e => { e.stopPropagation(); unlockAudio(); setSoundOn(s => !s); }}
            title="Toggle intercept sound (M)"
            className={`hk-footer-btn ${soundOn ? 'is-on' : ''}`}
          >
            {soundOn ? <Volume2 size={9} strokeWidth={2} /> : <VolumeX size={9} strokeWidth={2} />}
            <span>{soundOn ? 'SOUND' : 'MUTED'}</span>
          </button>

          <button
            onClick={toggleFullscreen}
            title="Toggle fullscreen (F)"
            className="hk-footer-btn"
          >
            {isFullscreen
              ? <Minimize2 size={9} strokeWidth={2} />
              : <Maximize2 size={9} strokeWidth={2} />
            }
            <span>{isFullscreen ? 'EXIT' : 'FULLSCREEN'}</span>
          </button>

          <button
            onClick={() => setHelpOpen(true)}
            className="hk-footer-btn"
          >
            <kbd style={{
              fontSize: 'var(--fs-micro)', fontWeight: 700,
              padding: '1px 5px',
              border: '1px solid var(--border)',
              borderRadius: 'var(--r-chip)',
              color: 'var(--text-bright)',
              letterSpacing: 0,
            }}>?</kbd>
            <span>KEYS</span>
          </button>
          <span>SRC_CODE</span>
          <span>LOG_DUMP</span>
          <span>EBPF_SPEC</span>
        </span>
      </footer>

      <InterceptSplash splash={splash} />

      {/* Fullscreen EventLog modal */}
      <AnimatePresence>
        {logFullscreen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.18, ease: 'easeOut' }}
            onClick={() => setLogFullscreen(false)}
            style={{
              position: 'fixed',
              inset: 0,
              zIndex: 80,
              background: 'rgba(3, 5, 8, 0.88)',
              backdropFilter: 'blur(8px)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              padding: 'var(--sp-6)',
            }}
          >
            <motion.div
              initial={{ y: 8, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              exit={{ y: 4, opacity: 0 }}
              transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
              onClick={e => e.stopPropagation()}
              style={{
                width: '100%',
                maxWidth: 1200,
                height: '100%',
                display: 'flex',
                flexDirection: 'column',
                background: 'var(--surface)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--r-large)',
                overflow: 'hidden',
                boxShadow: '0 24px 80px -12px rgba(0,0,0,0.8)',
              }}
            >
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: 'var(--sp-3) var(--sp-4)',
                borderBottom: '1px solid var(--border-dim)',
                background: 'rgba(255,255,255,0.012)',
              }}>
                <span className="hk-label" style={{ fontSize: 'var(--fs-small)' }}>EVENT_LOG · FULLSCREEN</span>
                <button
                  onClick={() => setLogFullscreen(false)}
                  title="Close (Esc)"
                  className="hk-footer-btn"
                  style={{ padding: '3px 8px' }}
                >
                  <X size={10} strokeWidth={2} />
                  <span>CLOSE</span>
                </button>
              </div>
              <div style={{ flex: 1, minHeight: 0 }}>
                <EventLog logs={logs} />
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      <KeyboardOverlay open={helpOpen} onClose={() => setHelpOpen(false)} />
      <SplitView
        open={splitOpen}
        onClose={() => setSplitOpen(false)}
        threatsBlocked={threatsBlocked}
        familyCounts={familyCounts}
        detectionRate={detectionRate}
        peakRate={peakRateRef.current}
        threatLevel={threatLevel}
      />
    </div>
  );
}

// `tick` is read-only here — it forces a re-render every second so the
// freshness check stays current between WS events.
const FRESH_MS = 5_000;

const NowPlaying: React.FC<{
  recentAttacks: RecentAttack[];
  anyBlocked: boolean;
  tick: number;
}> = ({ recentAttacks, anyBlocked, tick }) => {
  void tick;
  const latest = recentAttacks[0];
  const isFresh = latest && (Date.now() - latest.ts) < FRESH_MS;

  if (isFresh) {
    const color = FAMILY_COLOR[latest.category];
    return (
      <span style={{
        display: 'flex', alignItems: 'center', gap: 'var(--sp-2)',
        fontSize: 'var(--fs-micro)', letterSpacing: 'var(--ls-label)', fontWeight: 600,
        maxWidth: 360, overflow: 'hidden', whiteSpace: 'nowrap', textOverflow: 'ellipsis',
      }}>
        <span style={{ color, fontWeight: 700 }}>▶ {latest.category}</span>
        {latest.pattern && (
          <>
            <span style={{ color: 'var(--text-muted)' }}>·</span>
            <span style={{ color: 'var(--text)', fontFamily: 'var(--font-mono)', fontWeight: 500, letterSpacing: 0 }}>
              {latest.pattern.slice(0, 24)}
            </span>
          </>
        )}
        <span style={{ color: 'var(--text-muted)' }}>·</span>
        <span style={{
          color: 'var(--text-dim)', fontFamily: 'var(--font-mono)',
          fontVariantNumeric: 'tabular-nums', letterSpacing: 0,
        }}>
          {latest.source}
        </span>
      </span>
    );
  }

  return (
    <span style={{
      fontSize: 'var(--fs-micro)', letterSpacing: 'var(--ls-label)', fontWeight: 600,
      color: anyBlocked ? 'var(--danger)' : 'var(--text-dim)',
    }}>
      {anyBlocked ? '◄ INTERCEPT_ACTIVE ►' : 'ALL_SEGMENTS_NOMINAL'}
    </span>
  );
};
