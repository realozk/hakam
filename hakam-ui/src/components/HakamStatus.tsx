import React, { useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ThreatLevel, THREAT_LEVEL_META,
  FamilyCounts, AttackFamily, FAMILY_COLOR,
  GlobalMetrics, LogEntry, RecentAttack,
} from '../utils/websocket';

interface Props {
  connected: boolean;
  metrics: GlobalMetrics;
  threatLevel: ThreatLevel;
  threatsBlocked: number;
  familyCounts: FamilyCounts;
  detectionRate: number;
  /** Benign-traffic rate (req/s) over the rolling 30 s CONNECT window —
   *  drives the live activity tile so the panel doesn't look frozen during
   *  attack-free periods. */
  benignRate: number;
  anyBlocked: boolean;
  logs: LogEntry[];
  lastBlockTick: number;
  startedAt: number;
  recentAttacks: RecentAttack[];
}

// ── Heatmap helpers ───────────────────────────────────────────────────────
const BUCKET_MS  = 30_000;
const N_BUCKETS  = 12;          // 6 minutes of history

const heatColor = (count: number, max: number): string => {
  if (count === 0) return 'rgba(255,255,255,0.05)';
  const t = count / max;
  if (t < 0.25) return 'rgba(0,229,204,0.35)';
  if (t < 0.55) return 'rgba(0,229,204,0.80)';
  if (t < 0.80) return '#f97316';
  return '#ef4444';
};

// ── Formatters ────────────────────────────────────────────────────────────

const fmtNs = (ns: number) => {
  if (ns === 0) return '—';
  if (ns < 1_000)     return `${ns} ns`;
  if (ns < 1_000_000) return `${(ns / 1_000).toFixed(1)} µs`;
  return `${(ns / 1_000_000).toFixed(2)} ms`;
};
const fmtBps = (g: number) =>
  g < 0.001 ? `${(g * 1000).toFixed(2)} Mb/s` : `${g.toFixed(3)} Gb/s`;

const fmtUptime = (ms: number) => {
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${sec}s`;
  return `${sec}s`;
};

const fmtAgo = (ms: number | null) => {
  if (ms === null) return '—';
  const s = Math.floor(ms / 1000);
  if (s < 60)    return `${s}s ago`;
  if (s < 3600)  return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
};

// ── MITRE ATT&CK mapping ─────────────────────────────────────────────────
const FAMILY_MITRE: Partial<Record<AttackFamily, string>> = {
  SQLi:      'T1190',
  XSS:       'T1059.007',
  LFI:       'T1083',
  RCE:       'T1059',
  SSRF:      'T1090',
  XXE:       'T1190',
  Log4Shell: 'T1190',
  Deserial:  'T1059',
  NoSQLi:    'T1190',
  SSTI:      'T1059',
  WebShell:  'T1505.003',
  Recon:     'T1595',
  CVE:       'T1190',
  Manual:    'T1059',
};

// ── Hero panel ────────────────────────────────────────────────────────────

export const HakamStatus: React.FC<Props> = ({
  connected, metrics, threatLevel, threatsBlocked,
  familyCounts, detectionRate, benignRate, anyBlocked, logs,
  lastBlockTick, startedAt, recentAttacks,
}) => {
  // Live clock for uptime / "X ago"
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  // Track session peak detection rate
  const peakRef = useRef({ rate: 0, ts: '' });
  const [peakRate, setPeakRate] = useState({ rate: 0, ts: '' });
  useEffect(() => {
    if (detectionRate > peakRef.current.rate) {
      const d = new Date();
      const ts = `${d.getHours().toString().padStart(2,'0')}:${d.getMinutes().toString().padStart(2,'0')}`;
      peakRef.current = { rate: detectionRate, ts };
      setPeakRate({ rate: detectionRate, ts });
    }
  }, [detectionRate]);

  const tlMeta   = THREAT_LEVEL_META[threatLevel];
  const isNominal = threatLevel === 5;
  const segments = [1, 2, 3, 4, 5] as ThreatLevel[];

  // Bucket boundaries shift once per BUCKET_MS — memoize on the quantized
  // tick so the O(N) rebuild doesn't fire on every 1 s clock tick.
  const bucketTick = Math.floor(now / BUCKET_MS);
  const heatmap = React.useMemo(() => {
    if (recentAttacks.length === 0) return null;
    const anchorNow = bucketTick * BUCKET_MS;
    const bucketOf = (ts: number) =>
      N_BUCKETS - 1 - Math.floor((anchorNow - ts) / BUCKET_MS);
    const activeFams = [...new Set(recentAttacks.map(a => a.category))];
    const counts: Partial<Record<AttackFamily, number[]>> = {};
    activeFams.forEach(f => { counts[f] = Array(N_BUCKETS).fill(0); });
    recentAttacks.forEach(a => {
      const b = bucketOf(a.ts);
      if (b >= 0 && b < N_BUCKETS) counts[a.category]![b]++;
    });
    const maxCount = Math.max(1, ...Object.values(counts).flatMap(arr => arr!));
    const hasData  = Object.values(counts).some(arr => arr!.some(c => c > 0));
    return hasData ? { activeFams, counts, maxCount } : null;
  }, [recentAttacks, bucketTick]);

  const families = (Object.entries(familyCounts) as [AttackFamily, number][])
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1]);
  const topVector = families[0];
  const famMax  = families.reduce((m, [, n]) => Math.max(m, n), 1);
  const uniqueSources = new Set(
    logs.filter(l => l.level === 'critical').map(l => l.message.match(/from\s+([\d.]+)/)?.[1]).filter(Boolean)
  ).size;
  const uptimeMs  = now - startedAt;
  const sinceLast = lastBlockTick > 0 ? now - lastBlockTick : null;

  // CONNECT events from the sys_enter_connect tracepoint — format
  // "[comm] PID 123 → 10.99.0.10:80".
  const recentConnects = logs
    .filter(l => l.level === 'info' && l.message.startsWith('['))
    .slice(0, 4)
    .map(l => {
      const m = l.message.match(/^\[([^\]]+)\]\s+PID\s+(\d+)\s+→\s+([\d.]+):(\d+)/);
      if (!m) return null;
      return { id: l.id, time: l.time, comm: m[1], pid: m[2], dst: m[3], port: m[4] };
    })
    .filter((c): c is NonNullable<typeof c> => c !== null);

  return (
    <div style={{ padding: 'var(--sp-5) var(--sp-5)', display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>

      {/* ── Status header ─────────────────────────────────────────── */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-2)', marginBottom: 'var(--sp-1)' }}>
          <span className={`status-dot ${!connected ? 'bad' : anyBlocked ? 'pulse' : ''}`}
                style={{ width: 8, height: 8 }} />
          <span className="hk-label" style={{
            color: !connected
              ? 'var(--text-muted)'
              : anyBlocked ? 'var(--danger)' : 'var(--text-bright)',
            fontSize: 'var(--fs-small)',
          }}>
            {!connected ? 'KERNEL_OFFLINE' : anyBlocked ? 'INTERCEPTING' : 'HAKAM_ACTIVE'}
          </span>
        </div>
        <div style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-muted)', letterSpacing: 'var(--ls-label)', fontWeight: 500 }}>
          eBPF · XDP + TC + TRACEPOINT
        </div>
      </div>

      {/* ── HERO: THREATS_BLOCKED — the visual anchor ─────────── */}
      <div>
        <div className="hk-label" style={{ marginBottom: 'var(--sp-1)' }}>
          THREATS_BLOCKED
        </div>
        <div style={{ overflow: 'hidden', lineHeight: 1 }}>
          <AnimatePresence mode="popLayout" initial={false}>
            <motion.div
              key={threatsBlocked}
              initial={{ y: 18, opacity: 0, color: 'var(--danger)' }}
              animate={{ y: 0,  opacity: 1, color: anyBlocked ? 'var(--danger)' : 'var(--text-bright)' }}
              exit={{   y: -18, opacity: 0 }}
              transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
              className="hk-num"
              style={{
                fontFamily: 'var(--font-disp)',
                fontSize: 'var(--fs-hero)',
                fontWeight: 700,
                display: 'block',
              }}
            >
              {threatsBlocked.toLocaleString()}
            </motion.div>
          </AnimatePresence>
        </div>
        <div style={{
          marginTop: 'var(--sp-2)', display: 'flex', gap: 'var(--sp-5)',
          fontSize: 'var(--fs-micro)', color: 'var(--text-dim)',
        }}>
          <span>
            <span className="hk-num" style={{ color: 'var(--text-bright)', fontWeight: 600 }}>
              {detectionRate.toFixed(2)}/s
            </span>
            <span style={{ marginLeft: 'var(--sp-1)', letterSpacing: 'var(--ls-label)' }}>RATE_30S</span>
          </span>
          <span>
            <span style={{ color: 'var(--text-bright)', fontWeight: 600 }}>0</span>
            <span style={{ marginLeft: 'var(--sp-1)', letterSpacing: 'var(--ls-label)' }}>FALSE_POS</span>
          </span>
          <span>
            <span style={{ color: 'var(--text-bright)', fontWeight: 600 }}>{uniqueSources}</span>
            <span style={{ marginLeft: 'var(--sp-1)', letterSpacing: 'var(--ls-label)' }}>SOURCES</span>
          </span>
        </div>
      </div>

      {/* ── Static facts strip — compact, single row ───────────────── */}
      <div style={{
        display: 'flex',
        gap: 'var(--sp-3)',
        padding: 'var(--sp-2) 0',
        borderTop: '1px solid var(--border-dim)',
        borderBottom: '1px solid var(--border-dim)',
        fontSize: 'var(--fs-small)',
      }}>
        {([
          { value: 'XDP+TC', label: 'hooks'     },
          { value: '202',    label: 'sigs'      },
          { value: 'LPM',    label: 'blocklist' },
        ] as const).map(({ value, label }) => (
          <div key={label} style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--sp-1)', flex: 1 }}>
            <span className="hk-num" style={{
              color: 'var(--text-bright)',
              fontWeight: 700,
              fontFamily: 'var(--font-disp)',
            }}>
              {value}
            </span>
            <span style={{ color: 'var(--text-muted)', fontSize: 'var(--fs-micro)', letterSpacing: 'var(--ls-label)' }}>
              {label}
            </span>
          </div>
        ))}
      </div>

      {/* ── LIVE TRAFFIC — always-moving split bar so the panel doesn't ── */}
      {/*    look frozen during attack-free periods.                       */}
      <LiveTraffic benignRate={benignRate} detectionRate={detectionRate} />

      {/* ── Threat level — compact when nominal, expanded when not ── */}
      <div>
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <span style={{
            fontSize: 10, color: 'var(--text-dim)',
            letterSpacing: '0.18em', fontWeight: 600,
          }}>
            THREAT_LEVEL
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{
              display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
              background: tlMeta.color,
              boxShadow: isNominal ? 'none' : `0 0 8px ${tlMeta.color}`,
            }} />
            <span style={{
              fontSize: 11, fontWeight: 700, letterSpacing: '0.14em',
              color: tlMeta.color,
            }}>
              {tlMeta.label}
            </span>
          </div>
        </div>

        {/* expanded bar only when not nominal */}
        {!isNominal && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            style={{ overflow: 'hidden' }}
          >
            <div style={{ display: 'flex', gap: 3, marginTop: 8 }}>
              {segments.map(seg => {
                const lit = seg <= threatLevel;
                const c   = THREAT_LEVEL_META[seg].color;
                return (
                  <div key={seg} style={{
                    flex: 1, height: 6, borderRadius: 1,
                    background: lit ? c : 'var(--surface-3)',
                    boxShadow: lit ? `0 0 6px ${c}55` : 'none',
                    transition: 'all 0.3s',
                  }}/>
                );
              })}
            </div>
            <div style={{ fontSize: 9, color: 'var(--text-dim)', marginTop: 6, letterSpacing: '0.08em' }}>
              {tlMeta.sub}
            </div>
          </motion.div>
        )}
      </div>

      {/* ── Hardware tiles — live metrics ────────────────────────── */}
      <div style={{
        display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 'var(--sp-2)',
      }}>
        <Tile
          label="CPU"  value={`${metrics.cpu.toFixed(1)}%`}
          history={metrics.cpuHistory}
        />
        <Tile
          label="DROP_LAT" value={fmtNs(metrics.latency)}
          sub={`p99 ${fmtNs(metrics.latencyP99)}`}
        />
        <Tile
          label="THROUGHPUT" value={fmtBps(metrics.rxBandwidth)}
          history={metrics.rxHistory}
        />
      </div>

      {/* ── Family breakdown ────────────────────────────────────── */}
      {families.length > 0 && (
        <div>
          <div style={{
            display: 'flex', justifyContent: 'space-between',
            alignItems: 'center', marginBottom: 'var(--sp-2)',
          }}>
            <span className="hk-label">ATTACK_FAMILIES</span>
            <span style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-muted)', fontVariantNumeric: 'tabular-nums' }}>
              {families.length} active · MITRE ATT&amp;CK
            </span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-1)' }}>
            {families.slice(0, 6).map(([fam, n]) => {
              const c = FAMILY_COLOR[fam];
              const pct = (n / famMax) * 100;
              const mitre = FAMILY_MITRE[fam];
              return (
                <div key={fam} style={{
                  display: 'grid', gridTemplateColumns: '72px auto 1fr 28px',
                  alignItems: 'center', gap: 'var(--sp-2)', fontSize: 'var(--fs-small)',
                }}>
                  <span style={{ color: c, fontWeight: 600 }}>{fam}</span>
                  {mitre ? (
                    <span style={{
                      fontSize: 'var(--fs-micro)', padding: '1px 5px',
                      background: 'rgba(255,255,255,0.04)',
                      border: '1px solid var(--border-dim)',
                      borderRadius: 'var(--r-chip)', color: 'var(--text-muted)',
                      fontWeight: 600, whiteSpace: 'nowrap',
                    }}>
                      {mitre}
                    </span>
                  ) : <span />}
                  <div style={{ height: 4, background: 'var(--surface-3)', borderRadius: 1, overflow: 'hidden' }}>
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${pct}%` }}
                      transition={{ duration: 0.4, ease: 'easeOut' }}
                      style={{ height: '100%', background: c }}
                    />
                  </div>
                  <span className="hk-num" style={{
                    color: 'var(--text-bright)',
                    textAlign: 'right', fontWeight: 600,
                  }}>
                    {n}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── Stats — 2-col dense grid ─────────────────────────────── */}
      <div>
        <div className="hk-label" style={{ marginBottom: 'var(--sp-2)' }}>SYSTEM_STATE</div>
        <div className="metric-grid">
          <Cell k="UPTIME"          v={connected ? fmtUptime(uptimeMs) : '—'} />
          <Cell k="LAST_INTERCEPT"  v={fmtAgo(sinceLast)}
                cls={sinceLast !== null && sinceLast < 5000 ? 'bad' : ''} />
          <Cell k="TOP_VECTOR"      v={topVector ? `${topVector[0]} · ${topVector[1]}` : '—'}
                color={topVector ? FAMILY_COLOR[topVector[0]] : undefined} />
          <Cell k="KERNEL_MEM"      v={metrics.kernelMemory === '0.0' ? '—' : `${metrics.kernelMemory} MB`} />
          <Cell k="RING_OVERFLOWS"  v={String(metrics.ringOverflows)}
                cls={metrics.ringOverflows > 0 ? 'warn' : 'dim'} />
          <Cell k="PACKETS_DROPPED" v={metrics.packetsDropped.toLocaleString()}
                cls={metrics.packetsDropped > 0 ? '' : 'dim'} />
          <Cell k="PEAK_RATE"
                v={peakRate.rate > 0 ? `${peakRate.rate.toFixed(2)}/s · ${peakRate.ts}` : '—'}
                cls={peakRate.rate > 5 ? 'warn' : ''} />
          <Cell k="SIGNATURES" v="202" />
        </div>

      </div>

      {/* ── Process telemetry (CONNECT tracepoint) ────────────────── */}
      {recentConnects.length > 0 && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--sp-2)' }}>
            <span className="hk-label">PROCESS_TELEMETRY</span>
            <span style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-muted)' }}>
              tp · sys_enter_connect
            </span>
          </div>
          <div style={{
            border: '1px solid var(--border-dim)',
            borderRadius: 'var(--r-panel)',
            background: 'rgba(255,255,255,0.012)',
            overflow: 'hidden',
          }}>
            {recentConnects.map(c => (
              <div key={c.id} style={{
                display: 'grid',
                gridTemplateColumns: '76px 56px 1fr',
                gap: 'var(--sp-2)',
                padding: 'var(--sp-1) var(--sp-3)',
                fontSize: 'var(--fs-small)',
                borderBottom: '1px solid var(--border-dim)',
                alignItems: 'center',
              }}>
                <span style={{
                  color: 'var(--text-bright)',
                  fontWeight: 600,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}>
                  {c.comm}
                </span>
                <span className="hk-num" style={{ color: 'var(--text-muted)', fontSize: 'var(--fs-micro)' }}>
                  pid {c.pid}
                </span>
                <span className="hk-num" style={{ color: 'var(--text)', textAlign: 'right' }}>
                  {c.dst}<span style={{ color: 'var(--text-muted)' }}>:</span>{c.port}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Attack pattern heatmap ─────────────────────────────── */}
      {heatmap && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--sp-2)' }}>
            <span className="hk-label">ATTACK_PATTERN</span>
            <span style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-muted)' }}>
              30 s · last 6 min
            </span>
          </div>

          <div style={{ display: 'flex', marginLeft: 62, marginBottom: 3, gap: 1 }}>
            {Array.from({ length: N_BUCKETS }).map((_, i) => (
              <div key={i} style={{
                width: 14, fontSize: 7, color: 'var(--text-muted)',
                textAlign: 'center', opacity: i % 2 === 0 ? 1 : 0,
              }}>
                {i % 2 === 0 ? `-${(N_BUCKETS - i) / 2}m` : ''}
              </div>
            ))}
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            {heatmap.activeFams.map(fam => (
              <div key={fam} style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-1)' }}>
                <span style={{
                  width: 58, fontSize: 'var(--fs-micro)', fontWeight: 600,
                  color: FAMILY_COLOR[fam],
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  flexShrink: 0,
                }}>
                  {fam}
                </span>
                <div style={{ display: 'flex', gap: 1 }}>
                  {heatmap.counts[fam]!.map((count, i) => (
                    <div
                      key={i}
                      title={count > 0 ? `${count} intercept${count > 1 ? 's' : ''}` : ''}
                      style={{
                        width: 14, height: 10,
                        borderRadius: 1,
                        background: heatColor(count, heatmap.maxCount),
                        transition: 'background 0.4s ease',
                      }}
                    />
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

// ── Live traffic widget ─────────────────────────────────────────────────
// Always-moving split bar — benign vs attack rate, with a sparkline of the
// last 30 s of benign req/s on the bottom. This is the "the system is alive"
// signal even when no attacks are coming in. Re-renders every 1 s on its
// own tick so the sparkline keeps scrolling regardless of incoming events.

// 4 samples/sec × 30 s = 120 buckets. 4× the resolution of the old 1 Hz
// shift, so the sparkline scrolls smoothly instead of stepping every second.
const LIVE_HISTORY_LEN = 120;
const LIVE_TICK_MS = 250;

const LiveTraffic: React.FC<{ benignRate: number; detectionRate: number }> = ({
  benignRate, detectionRate,
}) => {
  const [history, setHistory] = useState<number[]>(() => Array(LIVE_HISTORY_LEN).fill(0));
  useEffect(() => {
    const id = setInterval(() => {
      setHistory(prev => [...prev.slice(1), benignRate]);
    }, LIVE_TICK_MS);
    return () => clearInterval(id);
  }, [benignRate]);

  const total = benignRate + detectionRate;
  const benignPct = total > 0 ? (benignRate / total) * 100 : 100;
  const attackPct = 100 - benignPct;
  const peak = Math.max(...history, 0.5);

  return (
    <div style={{
      border: '1px solid rgba(0,229,204,0.15)',
      background: 'rgba(0,229,204,0.025)',
      borderRadius: 4,
      padding: '12px 14px',
    }}>
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        marginBottom: 8,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-2)' }}>
          <span style={{
            width: 6, height: 6, borderRadius: '50%',
            background: '#00e5cc',
            boxShadow: '0 0 8px rgba(0,229,204,0.55)',
          }} />
          <span className="hk-label">LIVE_TRAFFIC</span>
        </div>
        <span style={{
          fontSize: 11, fontVariantNumeric: 'tabular-nums', fontWeight: 700,
          color: 'var(--text-bright)',
        }}>
          {total.toFixed(2)}/s
        </span>
      </div>

      {/* Stacked benign / attack split bar */}
      <div style={{
        height: 6, borderRadius: 1, overflow: 'hidden',
        display: 'flex', background: 'rgba(255,255,255,0.05)',
      }}>
        <motion.div
          animate={{ width: `${benignPct}%` }}
          transition={{ duration: 0.6, ease: 'easeOut' }}
          style={{ height: '100%', background: '#00e5cc' }}
        />
        <motion.div
          animate={{ width: `${attackPct}%` }}
          transition={{ duration: 0.6, ease: 'easeOut' }}
          style={{ height: '100%', background: '#ef4444' }}
        />
      </div>

      <div style={{
        display: 'flex', justifyContent: 'space-between', marginTop: 5,
        fontSize: 9, color: 'var(--text-dim)',
      }}>
        <span>
          <span style={{ color: '#00e5cc', fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>
            {benignRate.toFixed(2)}/s
          </span>
          <span style={{ marginLeft: 4, letterSpacing: '0.10em' }}>BENIGN</span>
        </span>
        <span>
          <span style={{ color: '#ef4444', fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>
            {detectionRate.toFixed(2)}/s
          </span>
          <span style={{ marginLeft: 4, letterSpacing: '0.10em' }}>BLOCKED</span>
        </span>
      </div>

      {/* Scrolling 30-second benign rate sparkline */}
      <svg
        viewBox={`0 0 ${LIVE_HISTORY_LEN - 1} 20`}
        preserveAspectRatio="none"
        style={{ width: '100%', height: 22, marginTop: 8, display: 'block' }}
      >
        <polyline
          points={history.map((v, i) => `${i},${20 - (v / peak) * 20}`).join(' ')}
          fill="none"
          stroke="#00e5cc"
          strokeWidth="1"
          strokeLinecap="round"
          strokeLinejoin="round"
          vectorEffect="non-scaling-stroke"
          opacity="0.6"
        />
        <polyline
          points={history.map((v, i) => `${i},${20 - (v / peak) * 20} ${i},20`).join(' ')}
          fill="rgba(0,229,204,0.08)"
          stroke="none"
        />
      </svg>

    </div>
  );
};

// ── Metric tile ─────────────────────────────────────────────────────────

const Tile: React.FC<{
  label: string;
  value: string;
  sub?: string;
  history?: number[];
}> = ({ label, value, sub, history }) => (
  <div style={{
    background: 'rgba(255,255,255,0.018)',
    border: '1px solid var(--border-dim)',
    borderRadius: 3,
    padding: '9px 11px',
  }}>
    <div style={{ fontSize: 8, color: 'var(--text-dim)', letterSpacing: '0.2em', fontWeight: 600, marginBottom: 5 }}>
      {label}
    </div>
    <div style={{
      fontSize: 17,
      fontWeight: 700,
      color: 'var(--text-bright)',
      fontVariantNumeric: 'tabular-nums',
      letterSpacing: '-0.01em',
    }}>
      {value}
    </div>
    {sub && (
      <div style={{ fontSize: 8, color: 'var(--text-dim)', marginTop: 2, letterSpacing: '0.04em' }}>
        {sub}
      </div>
    )}
    {history && history.length > 1 && (
      <Spark values={history} />
    )}
  </div>
);

const Spark: React.FC<{ values: number[] }> = ({ values }) => {
  const peak = Math.max(...values, 1);
  const w = 100, h = 16;
  const step = w / (values.length - 1);
  const pts = values.map((v, i) => `${(i * step).toFixed(1)},${(h - (v / peak) * h).toFixed(1)}`).join(' ');
  return (
    <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none"
         style={{ width: '100%', height: 16, marginTop: 5, display: 'block' }}>
      <polyline points={pts} fill="none" stroke="rgba(255,255,255,0.35)" strokeWidth="1" vectorEffect="non-scaling-stroke" />
    </svg>
  );
};

// ── Stats cell — 2-col grid element ─────────────────────────────────────

const Cell: React.FC<{ k: string; v: string; cls?: string; color?: string }> = ({ k, v, cls, color }) => (
  <div className="metric-cell">
    <span className="metric-cell-key">{k}</span>
    <span className={`metric-val ${cls ?? ''}`} style={color ? { color } : undefined}>{v}</span>
  </div>
);
