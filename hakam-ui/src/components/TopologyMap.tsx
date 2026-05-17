import React, { useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ThreatState, NodeRole, NODE_META, FAMILY_COLOR } from '../utils/websocket';

interface Props {
  threatState: ThreatState;
  blockTick: number;
  benignTick: { ts: number; dst: NodeRole };
}

// Node positions inside the topology canvas (% of viewBox 100x100).
const POS: Record<NodeRole, { x: number; y: number }> = {
  attacker: { x: 50, y: 14 },
  firewall: { x: 50, y: 44 },
  pc1:      { x: 22, y: 78 },
  pc2:      { x: 50, y: 78 },
  db:       { x: 78, y: 78 },
};

const EDGES: { a: NodeRole; b: NodeRole }[] = [
  { a: 'attacker', b: 'firewall' },
  { a: 'firewall', b: 'pc1' },
  { a: 'firewall', b: 'pc2' },
  { a: 'firewall', b: 'db'  },
];

const IconExternal: React.FC<{ size?: number }> = ({ size = 24 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
       stroke="currentColor" strokeWidth="1.6" strokeLinecap="square" strokeLinejoin="miter">
    <rect x="3" y="3" width="18" height="18" />
    <path d="M3 9 H21 M3 15 H21 M9 3 V21 M15 3 V21" opacity="0.5" />
  </svg>
);

const IconWorkstation: React.FC<{ size?: number }> = ({ size = 24 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
       stroke="currentColor" strokeWidth="1.6" strokeLinecap="square" strokeLinejoin="miter">
    <rect x="2" y="4" width="20" height="13" />
    <path d="M8 21 H16" />
    <path d="M12 17 V21" />
    <rect x="5" y="7" width="14" height="7" opacity="0.45" />
  </svg>
);

const IconDatabase: React.FC<{ size?: number }> = ({ size = 24 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
       stroke="currentColor" strokeWidth="1.6" strokeLinecap="square" strokeLinejoin="miter">
    <rect x="3" y="4"  width="18" height="5" />
    <rect x="3" y="10" width="18" height="5" />
    <rect x="3" y="16" width="18" height="5" />
    <circle cx="6.5" cy="6.5" r="0.7" fill="currentColor" stroke="none" />
    <circle cx="6.5" cy="12.5" r="0.7" fill="currentColor" stroke="none" />
    <circle cx="6.5" cy="18.5" r="0.7" fill="currentColor" stroke="none" />
  </svg>
);

const IconKernel: React.FC<{ size?: number }> = ({ size = 28 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
       stroke="currentColor" strokeWidth="1.7" strokeLinecap="square" strokeLinejoin="miter">
    {/* Chip body */}
    <rect x="6" y="6" width="12" height="12" />
    {/* Inner core */}
    <rect x="9.5" y="9.5" width="5" height="5" opacity="0.55" />
    {/* Pins */}
    <path d="M9 6 V3   M12 6 V3   M15 6 V3" />
    <path d="M9 21 V18  M12 21 V18  M15 21 V18" />
    <path d="M6 9 H3   M6 12 H3   M6 15 H3" />
    <path d="M21 9 H18  M21 12 H18  M21 15 H18" />
  </svg>
);

const ICON: Record<NodeRole, React.ReactNode> = {
  attacker: <IconExternal    size={22} />,
  pc1:      <IconWorkstation size={22} />,
  pc2:      <IconWorkstation size={22} />,
  db:       <IconDatabase    size={22} />,
  firewall: <IconKernel      size={28} />,
};

export const TopologyMap: React.FC<Props> = ({ threatState, blockTick, benignTick }) => {
  const edgeKey = (a: NodeRole, b: NodeRole) => [a, b].sort().join('|');

  // Drives the time-decay visual on attacked nodes (~13 s fade per phase).
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 500);
    return () => clearInterval(id);
  }, []);

  // Zone legend — auto-fades after 10 s
  const [legendVisible, setLegendVisible] = useState(true);
  useEffect(() => {
    const t = setTimeout(() => setLegendVisible(false), 10_000);
    return () => clearTimeout(t);
  }, []);

  // Track last 3 unique attacker IPs across blocks
  const [attackerIpHistory, setAttackerIpHistory] = useState<string[]>([]);
  const prevIpRef = useRef('');
  useEffect(() => {
    const ip = threatState.nodes.attacker.lastIp;
    if (ip && ip !== prevIpRef.current) {
      prevIpRef.current = ip;
      setAttackerIpHistory(prev => [ip, ...prev.filter(x => x !== ip)].slice(0, 3));
    }
  }, [blockTick, threatState.nodes.attacker.lastIp]);

  const litEdges     = new Set<string>();
  const severedEdges = new Set<string>();
  if (threatState.edge) {
    const { from, to, blocked } = threatState.edge;
    if (from !== 'firewall') litEdges.add(edgeKey(from, 'firewall'));
    if (to   !== 'firewall' && to !== from) litEdges.add(edgeKey('firewall', to));
    if (blocked && from !== 'firewall') severedEdges.add(edgeKey(from, 'firewall'));
  }

  const [particles, setParticles] = useState<Array<{
    id: string; from: NodeRole; to: NodeRole; color: string; kind: 'attack' | 'benign';
  }>>([]);

  useEffect(() => {
    if (!threatState.edge || blockTick === 0) return;
    const id    = `${blockTick}-${Math.random().toString(36).slice(2, 7)}`;
    const cat   = threatState.edge.category ?? 'CVE';
    const color = FAMILY_COLOR[cat] ?? '#ff3b3b';
    setParticles(prev => [
      ...prev.slice(-8),
      { id, from: threatState.edge!.from, to: 'firewall', color, kind: 'attack' },
    ]);
    const t = setTimeout(() => setParticles(prev => prev.filter(p => p.id !== id)), 1100);
    return () => clearTimeout(t);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [blockTick]);

  // Benign particles throttled to ~1 per 600 ms so bursts don't flood the SVG.
  const lastBenignParticleRef = useRef(0);
  useEffect(() => {
    if (benignTick.ts === 0) return;
    if (benignTick.ts - lastBenignParticleRef.current < 600) return;
    lastBenignParticleRef.current = benignTick.ts;

    const idA = `b1-${benignTick.ts}`;
    const idB = `b2-${benignTick.ts}`;
    setParticles(prev => [
      ...prev.slice(-8),
      { id: idA, from: 'attacker', to: 'firewall', color: '#00e5cc', kind: 'benign' },
    ]);
    const t1 = setTimeout(() => {
      setParticles(prev => [
        ...prev.filter(p => p.id !== idA),
        { id: idB, from: 'firewall', to: benignTick.dst, color: '#00e5cc', kind: 'benign' },
      ]);
    }, 700);
    const t2 = setTimeout(() => {
      setParticles(prev => prev.filter(p => p.id !== idB));
    }, 1500);
    return () => { clearTimeout(t1); clearTimeout(t2); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [benignTick.ts]);

  return (
    <div style={{ position: 'relative', width: '100%', height: '100%', overflow: 'hidden' }}>

      {/* ── Zone backgrounds (UNTRUSTED → PERIMETER → INTERNAL) ─────── */}
      <div style={{ position: 'absolute', inset: 0, zIndex: 0 }}>
        <div style={{
          position: 'absolute', left: 0, right: 0, top: 0, height: '30%',
          background: 'linear-gradient(180deg, rgba(255,59,59,0.06) 0%, rgba(255,59,59,0.01) 100%)',
          borderBottom: '1px dashed rgba(255,59,59,0.15)',
        }} />
        <div style={{
          position: 'absolute', left: 0, right: 0, top: '30%', height: '28%',
          background: 'linear-gradient(180deg, rgba(0,229,204,0.10) 0%, rgba(0,229,204,0.04) 100%)',
          borderBottom: '1px dashed rgba(0,229,204,0.18)',
        }} />
        <div style={{
          position: 'absolute', left: 0, right: 0, top: '58%', bottom: 0,
          background: 'linear-gradient(180deg, rgba(0,229,204,0.02) 0%, rgba(0,229,204,0.005) 100%)',
        }} />

        {/* Zone labels — vertical text on the left edge */}
        <ZoneLabel y="2%"  color="rgba(255,59,59,0.55)"  text="UNTRUSTED · INTERNET" />
        <ZoneLabel y="33%" color="rgba(0,229,204,0.7)"   text="HAKAM_PERIMETER" />
        <ZoneLabel y="60%" color="rgba(0,229,204,0.45)"  text="INTERNAL · 10.99.0.0/16" />
      </div>

      {/* ── Edges + particles (SVG, on top of zones, below nodes) ─── */}
      <svg
        style={{ position: 'absolute', inset: 0, zIndex: 10 }}
        width="100%" height="100%"
        viewBox="0 0 100 100"
        preserveAspectRatio="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        {EDGES.map(({ a, b }) => {
          const k = edgeKey(a, b);
          const lit     = litEdges.has(k);
          const severed = severedEdges.has(k);
          const pa = POS[a], pb = POS[b];
          let stroke = 'rgba(0,229,204,0.20)';
          let dash: string | undefined = undefined;
          let width = 0.45;
          if (lit && !severed) { stroke = '#00e5cc'; dash = '1.2 0.8'; width = 0.75; }
          if (severed)         { stroke = '#ff3b3b'; dash = '0.6 1.2'; width = 0.85; }

          return (
            <g key={k}>
              <line
                x1={pa.x} y1={pa.y} x2={pb.x} y2={pb.y}
                stroke={stroke} strokeWidth={width} strokeDasharray={dash}
                vectorEffect="non-scaling-stroke"
                style={lit && !severed ? { animation: 'dash-flow 1.1s linear infinite' } : undefined}
              />
            </g>
          );
        })}

        {/* Radar sweep when an attack is in flight */}
        {threatState.edge && !threatState.edge.blocked && (
          <g transform={`translate(${POS.firewall.x}, ${POS.firewall.y})`}>
            <motion.circle
              fill="none" stroke="rgba(0,229,204,0.5)" strokeWidth="0.5"
              vectorEffect="non-scaling-stroke"
              initial={{ r: 0.5, opacity: 0.8 }}
              animate={{ r: 10, opacity: 0 }}
              transition={{ duration: 1.4, repeat: Infinity, ease: 'easeOut' }}
            />
          </g>
        )}

        {particles.map(p => {
          const a = POS[p.from], b = POS[p.to];
          const isBenign = p.kind === 'benign';
          return (
            <motion.circle
              key={p.id}
              r={isBenign ? '0.7' : '0.9'}
              fill={p.color}
              vectorEffect="non-scaling-stroke"
              initial={{ cx: a.x, cy: a.y, opacity: 0 }}
              animate={{
                cx: b.x, cy: b.y,
                opacity: isBenign ? [0, 0.65, 0.65, 0] : [0, 0.95, 0.95, 0],
              }}
              transition={{
                duration: isBenign ? 0.75 : 0.95,
                ease: 'linear',
                opacity: { times: [0, 0.15, 0.85, 1] },
              }}
            />
          );
        })}

        {/* Firewall halo */}
        <defs>
          <radialGradient id="hakamGlow">
            <stop offset="0%"   stopColor="#00e5cc" stopOpacity="0.25" />
            <stop offset="100%" stopColor="#00e5cc" stopOpacity="0"    />
          </radialGradient>
        </defs>
        <circle cx={POS.firewall.x} cy={POS.firewall.y} r="9" fill="url(#hakamGlow)" />
      </svg>

      {/* ── Severed-edge markers (HTML overlay so they stay circular) ── */}
      {EDGES.map(({ a, b }) => {
        const k = edgeKey(a, b);
        if (!severedEdges.has(k)) return null;
        const pa = POS[a], pb = POS[b];
        const midX = (pa.x + pb.x) / 2;
        const midY = (pa.y + pb.y) / 2;
        return <SeveredMarker key={`sev-${k}`} x={midX} y={midY} />;
      })}

      {/* ── Nodes (HTML, on top) ───────────────────────────────────── */}
      {(Object.keys(POS) as NodeRole[]).map(role => (
        <TopologyNode
          key={role} role={role}
          x={POS[role].x} y={POS[role].y}
          state={threatState.nodes[role]}
          now={now}
          ipHistory={role === 'attacker' ? attackerIpHistory : undefined}
        />
      ))}

      {/* ── Zone legend — fades after 10 s ───────────────────────── */}
      <AnimatePresence>
        {legendVisible && (
          <motion.div
            initial={{ opacity: 0, x: 8 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 8, transition: { duration: 1.8 } }}
            transition={{ duration: 0.4 }}
            style={{
              position: 'absolute', top: 14, right: 14, zIndex: 35,
              background: 'rgba(5,6,8,0.94)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--r-panel)',
              padding: '10px 14px',
              minWidth: 200,
            }}
          >
            <div style={{
              fontSize: 8, fontWeight: 700, letterSpacing: '0.26em',
              color: 'var(--text-dim)', marginBottom: 9,
            }}>
              MAP_LEGEND
            </div>
            {([
              { color: 'rgba(255,59,59,0.75)',  label: 'UNTRUSTED',          desc: 'Internet / threat origin' },
              { color: 'rgba(0,229,204,0.80)',  label: 'HAKAM_PERIMETER',  desc: 'eBPF enforcement layer' },
              { color: 'rgba(0,229,204,0.40)',  label: 'INTERNAL · LAN',     desc: 'Protected assets' },
            ] as const).map(({ color, label, desc }) => (
              <div key={label} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, marginBottom: 6 }}>
                <div style={{ width: 8, height: 8, background: color, borderRadius: 1, flexShrink: 0, marginTop: 2 }} />
                <div>
                  <div style={{ fontSize: 9, fontWeight: 700, color: 'var(--text)', letterSpacing: '0.10em' }}>{label}</div>
                  <div style={{ fontSize: 8, color: 'var(--text-dim)', marginTop: 1 }}>{desc}</div>
                </div>
              </div>
            ))}
            <div style={{
              marginTop: 8, paddingTop: 7,
              borderTop: '1px solid var(--border-dim)',
              fontSize: 8, color: 'var(--text-muted)',
              display: 'flex', gap: 14,
            }}>
              <span><span style={{ color: '#f5a623' }}>─ ─</span> ACTIVE FLOW</span>
              <span><span style={{ color: '#ff3b3b' }}>─ ─</span> BLOCKED</span>
            </div>
            <div style={{ marginTop: 7, fontSize: 8, color: 'var(--text-muted)', letterSpacing: '0.08em' }}>
              auto-hides in 10 s
            </div>
          </motion.div>
        )}
      </AnimatePresence>

    </div>
  );
};

// ── Zone label ───────────────────────────────────────────────────────────────

const ZoneLabel: React.FC<{ y: string; color: string; text: string }> = ({ y, color, text }) => (
  <div style={{
    position: 'absolute', left: 12, top: y,
    fontSize: 9, fontWeight: 600, letterSpacing: '0.22em',
    color, fontFamily: 'inherit',
  }}>
    {text}
  </div>
);

// ── Node rendering ─────────────────────────────────────────────────────────

interface NodeProps {
  role: NodeRole;
  x: number; y: number;
  state: { active: boolean; blocked: boolean; lastBlockedAt?: number; lastBenignAt?: number; lastAction?: string; lastIp?: string };
  now: number;
  ipHistory?: string[];
}

const BENIGN_PULSE_MS = 1500;

// Time-decayed visual phases. Hakam blocks an IP in the kernel for 120s
// (the BLOCKLIST TTL) — that's the *enforcement* state. The *visual* state
// fades much faster so the UI doesn't look frozen after every attack.
//
//   0 –  3 s   "hot"     bright red border + one-shot ring on each new block
//   3 – 13 s   "warm"    dim red border, no ring
//  13 s +      "cool"    neutral (kernel block may still be active)
type DecayPhase = 'hot' | 'warm' | 'cool';
const HOT_MS  = 3_000;
const WARM_MS = 13_000;

const decayPhase = (lastBlockedAt: number | undefined, now: number): DecayPhase => {
  if (!lastBlockedAt) return 'cool';
  const dt = now - lastBlockedAt;
  if (dt < HOT_MS)  return 'hot';
  if (dt < WARM_MS) return 'warm';
  return 'cool';
};

const TopologyNode: React.FC<NodeProps> = ({ role, x, y, state, now, ipHistory }) => {
  const meta = NODE_META[role];
  const isFirewall = role === 'firewall';
  const isAttacker = role === 'attacker';

  const phase = decayPhase(state.lastBlockedAt, now);
  const visBlocked = phase === 'hot';
  const visRecent  = phase === 'warm';
  const visBenign = !visBlocked && !visRecent && !state.active
    && state.lastBenignAt !== undefined
    && (now - state.lastBenignAt) < BENIGN_PULSE_MS;

  const accent =
    visBlocked      ? '#ff3b3b' :
    visRecent       ? '#c2727f' :
    state.active    ? '#f5a623' :
    isFirewall      ? '#00e5cc' :
    isAttacker      ? '#ff3b3b' :
                      'rgba(178,191,204,0.85)';

  const borderCol =
    visBlocked      ? 'rgba(255,59,59,0.85)' :
    visRecent       ? 'rgba(255,59,59,0.32)' :
    state.active    ? 'rgba(245,166,35,0.75)' :
    isFirewall      ? 'rgba(0,229,204,0.7)' :
    isAttacker      ? 'rgba(255,59,59,0.35)' :
                      'rgba(0,229,204,0.25)';

  const bgCol =
    visBlocked      ? 'rgba(255,59,59,0.10)' :
    visRecent       ? 'rgba(255,59,59,0.035)' :
    state.active    ? 'rgba(245,166,35,0.10)' :
    isFirewall      ? 'rgba(0,229,204,0.10)' :
                      'rgba(12,16,24,0.92)';

  // Calm baseline. Block/attack states emit a single-shot ring (rendered
  // below) on each lastBlockedAt change rather than looping forever — that
  // was the source of the "shaky" feel during attack bursts. Firewall keeps
  // a static glow (no breath) so the panel reads steady at idle.
  const pulseAnim: React.CSSProperties =
    isFirewall
      ? { boxShadow: '0 0 22px rgba(0, 229, 204, 0.28), inset 0 0 12px rgba(0, 229, 204, 0.08)' }
      : visBenign
        ? { animation: 'node-benign-pulse 1.4s ease-out' }
        : {};

  const size = isFirewall ? 88 : 76;

  return (
    <div style={{
      position: 'absolute',
      zIndex: 20,
      left: `${x}%`, top: `${y}%`,
      transform: 'translate(-50%, -50%)',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
    }}>
      <div style={{
        position: 'relative',
        width: size, height: size,
        borderRadius: 'var(--r-large)',
        border: `1.5px solid ${borderCol}`,
        background: bgCol,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        transition: 'border-color 1.2s ease, background-color 1.2s ease',
        ...pulseAnim,
      }}>
        {/* Re-mounts on each new block so bursts produce discrete pulses. */}
        {visBlocked && state.lastBlockedAt && !isFirewall && (
          <motion.div
            key={state.lastBlockedAt}
            initial={{ scale: 1,    opacity: 0.55 }}
            animate={{ scale: 1.45, opacity: 0    }}
            transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
            style={{
              position: 'absolute',
              inset: -2,
              borderRadius: 'var(--r-large)',
              border: '1.5px solid #ff3b3b',
              pointerEvents: 'none',
            }}
          />
        )}
        <span style={{ color: accent }}>{ICON[role]}</span>

        <AnimatePresence>
          {(visBlocked || visRecent) && !isFirewall && (
            <motion.div
              key={visBlocked ? 'blocked' : 'recent'}
              initial={{ opacity: 0, y: -4, scale: 0.9 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -4, scale: 0.9, transition: { duration: 0.5 } }}
              transition={{ duration: 0.2 }}
              style={{
                position: 'absolute', top: -11, right: -11,
                fontSize: 8, fontWeight: 700,
                letterSpacing: '0.18em',
                padding: '2px 7px',
                borderRadius: 2,
                background: visBlocked ? '#ff3b3b' : 'rgba(255,59,59,0.18)',
                color: visBlocked ? '#fff' : 'rgba(255,170,170,0.95)',
                border: visBlocked ? '1px solid rgba(255,59,59,0.9)' : '1px solid rgba(255,59,59,0.45)',
                boxShadow: visBlocked ? '0 0 10px rgba(255,59,59,0.45)' : 'none',
              }}
            >
              {visBlocked ? 'BLOCKED' : 'RECENT'}
            </motion.div>
          )}
        </AnimatePresence>

        {/* Tag chip — firewall label */}
        {isFirewall && (
          <div style={{
            position: 'absolute', top: -10, left: '50%', transform: 'translateX(-50%)',
            fontSize: 8, padding: '2px 8px',
            background: 'var(--bg)',
            border: '1px solid var(--accent)',
            color: 'var(--accent)',
            borderRadius: 2,
            letterSpacing: '0.16em', fontWeight: 700,
            whiteSpace: 'nowrap',
          }}>
            eBPF · KERNEL
          </div>
        )}
      </div>

      <div style={{ marginTop: 10, textAlign: 'center' }}>
        <div style={{
          fontSize: 11, fontWeight: 700, letterSpacing: '0.06em',
          color: visBlocked ? '#ff3b3b' : visRecent ? '#c2727f' : isFirewall ? '#6fe7d4' : 'var(--text-bright)',
          transition: 'color 1.2s ease',
        }}>
          {meta.label}
        </div>
        <div style={{
          fontSize: 9, color: 'var(--text-dim)', marginTop: 2,
          letterSpacing: '0.04em',
        }}>
          {state.lastIp || meta.ip}
        </div>

        {/* Attacker IP history — last 3 unique source IPs */}
        {ipHistory && ipHistory.length > 0 && (
          <div style={{ marginTop: 6, display: 'flex', flexDirection: 'column', gap: 2, alignItems: 'center' }}>
            {ipHistory.map((ip, i) => (
              <span key={ip} style={{
                fontSize: 8,
                fontVariantNumeric: 'tabular-nums',
                letterSpacing: '0.04em',
                color: i === 0 ? '#ff5252' : 'var(--text-dim)',
                opacity: 1 - i * 0.28,
                transition: 'all 0.4s',
              }}>
                {ip}
              </span>
            ))}
          </div>
        )}

        {/* eBPF program chips — only on the firewall node */}
        {isFirewall && (
          <div style={{
            marginTop: 8,
            display: 'flex',
            gap: 4,
            justifyContent: 'center',
          }}>
            {[
              { name: 'XDP', label: 'XDP_INGRESS' },
              { name: 'TC',  label: 'TC_EGRESS'   },
              { name: 'TP',  label: 'TRACEPOINT'  },
            ].map(({ name, label }) => (
              <span key={name}
                title={label}
                style={{
                  fontSize: 8,
                  padding: '2px 6px',
                  background: 'rgba(111,231,212,0.08)',
                  border: '1px solid rgba(111,231,212,0.30)',
                  color: '#6fe7d4',
                  borderRadius: 2,
                  letterSpacing: '0.18em',
                  fontWeight: 700,
                  fontFamily: 'var(--font-sans)',
                }}>
                {name}
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

// HTML overlay keeps the marker perfectly circular; the SVG version
// stretched into an ellipse under non-uniform scaling.
const SeveredMarker: React.FC<{ x: number; y: number }> = ({ x, y }) => (
  <div style={{
    position: 'absolute',
    left: `${x}%`, top: `${y}%`,
    transform: 'translate(-50%, -50%)',
    width: 22, height: 22,
    borderRadius: '50%',
    background: '#070a0d',
    border: '1.5px solid #ff3b3b',
    boxShadow: '0 0 10px rgba(255,59,59,0.55)',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    zIndex: 15,
    pointerEvents: 'none',
  }}>
    <svg width="10" height="10" viewBox="0 0 10 10">
      <line x1="2" y1="2" x2="8" y2="8" stroke="#ff3b3b" strokeWidth="1.4" strokeLinecap="round" />
      <line x1="2" y1="8" x2="8" y2="2" stroke="#ff3b3b" strokeWidth="1.4" strokeLinecap="round" />
    </svg>
  </div>
);


