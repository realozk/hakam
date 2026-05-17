import React, { useEffect, useMemo, useRef, useState } from 'react';
import { RecentAttack, FAMILY_COLOR } from '../utils/websocket';

interface Props {
  events: RecentAttack[];
  startedAt: number;
}

// Operation-monitor strip — aggregate readouts on the left, temporal tick
// stream on the right. Uniform 2px ticks, color carries family meaning,
// no severity-height variation. Calm + scannable from across the room.
export const AttackTimeline: React.FC<Props> = ({ events, startedAt }) => {
  const [now, setNow] = useState(Date.now());
  const [hovered, setHovered] = useState<RecentAttack | null>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const svgRef = useRef<SVGSVGElement>(null);

  // 250 ms tick so the NOW cursor + tick positions slide smoothly. The
  // aggregates re-filter is O(N) over recent events — cheap.
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(id);
  }, []);

  // ── Aggregates ─────────────────────────────────────────────────────────
  const aggregates = useMemo(() => {
    const total = events.length;
    const last30 = events.filter(e => now - e.ts <= 30_000).length;
    const rate = last30 / 30;
    const lastTs = events.length ? Math.max(...events.map(e => e.ts)) : 0;
    const lastAgo = lastTs ? Math.floor((now - lastTs) / 1000) : null;
    const activeFams = new Set(events.filter(e => now - e.ts <= 60_000).map(e => e.category)).size;
    return { total, rate, lastAgo, activeFams };
  }, [events, now]);

  // ── Time axis ──────────────────────────────────────────────────────────
  const duration = Math.max(now - startedAt, 60_000);
  const H = 28;
  const MID = H / 2;

  const xPct = (ts: number) =>
    Math.min(100, Math.max(0, ((ts - startedAt) / duration) * 100));

  // Major time labels — show -10m / -5m / -1m / now style, only ones that fit
  const labels = useMemo(() => {
    const candidates = [600_000, 300_000, 60_000, 30_000, 10_000];
    return candidates
      .map(ms => ({ ms, pct: ((duration - ms) / duration) * 100 }))
      .filter(({ ms, pct }) => ms <= duration && pct >= 0 && pct <= 96)
      .map(({ ms, pct }) => ({
        pct,
        label: ms >= 60_000 ? `-${ms / 60_000}m` : `-${ms / 1_000}s`,
      }));
  }, [duration]);

  const fmtAgo = (s: number | null) => {
    if (s === null) return '—';
    if (s < 60) return `${s}s`;
    if (s < 3600) return `${Math.floor(s / 60)}m`;
    return `${Math.floor(s / 3600)}h`;
  };

  return (
    <div style={{
      position: 'relative',
      height: '100%',
      display: 'flex',
      alignItems: 'stretch',
      gap: 'var(--sp-4)',
      padding: '0 var(--sp-3)',
    }}>
      {/* ── Tooltip ── */}
      {hovered && (
        <div style={{
          position: 'fixed',
          left: tooltipPos.x,
          top: tooltipPos.y - 12,
          transform: 'translate(-50%, -100%)',
          background: 'rgba(5,6,8,0.97)',
          border: `1px solid ${FAMILY_COLOR[hovered.category]}55`,
          borderRadius: 'var(--r-chip)',
          padding: 'var(--sp-1) var(--sp-2)',
          fontSize: 'var(--fs-micro)',
          whiteSpace: 'nowrap',
          zIndex: 9999,
          pointerEvents: 'none',
          boxShadow: '0 8px 24px -6px rgba(0,0,0,0.7)',
        }}>
          <div style={{ color: FAMILY_COLOR[hovered.category], fontWeight: 700, marginBottom: 3 }}>
            {hovered.category} · {hovered.severity}
          </div>
          <div style={{ color: 'var(--text-dim)' }}>{hovered.source} · {hovered.time}</div>
          {hovered.pattern && (
            <div style={{
              color: 'var(--text-muted)', marginTop: 2,
              maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis',
            }}>
              {hovered.pattern}
            </div>
          )}
        </div>
      )}

      {/* ── LEFT: 4 readouts ── */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, minmax(70px, auto))',
        alignItems: 'center',
        gap: 'var(--sp-4)',
        paddingRight: 'var(--sp-4)',
        borderRight: '1px solid var(--border-dim)',
      }}>
        <Readout label="INTERCEPTS" value={aggregates.total.toLocaleString()} />
        <Readout label="RATE"       value={`${aggregates.rate.toFixed(2)}/s`}
                 tone={aggregates.rate > 1 ? 'warn' : 'normal'} />
        <Readout label="LAST"       value={fmtAgo(aggregates.lastAgo)}
                 tone={aggregates.lastAgo !== null && aggregates.lastAgo < 5 ? 'hot' : 'normal'} />
        <Readout label="ACTIVE"     value={String(aggregates.activeFams)} sub="fams" />
      </div>

      {/* ── RIGHT: timeline strip ── */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', minWidth: 0 }}>
        <svg
          ref={svgRef}
          width="100%"
          height={H}
          style={{ display: 'block', overflow: 'visible', cursor: 'crosshair' }}
          onMouseLeave={() => setHovered(null)}
        >
          {/* Baseline */}
          <line x1="0" y1={MID} x2="100%" y2={MID}
            stroke="rgba(255,255,255,0.08)" strokeWidth="1" />

          {/* Major time markers */}
          {labels.map(({ pct }) => (
            <line key={pct}
              x1={`${pct}%`} y1={MID - 4}
              x2={`${pct}%`} y2={MID + 4}
              stroke="rgba(255,255,255,0.12)" strokeWidth="1"
            />
          ))}

          {/* Attack ticks — uniform height, color by family */}
          {events.map(e => {
            const x = `${xPct(e.ts)}%`;
            const color = FAMILY_COLOR[e.category];
            const tickH = 14;
            return (
              <rect
                key={e.id}
                x={x} y={MID - tickH / 2}
                width={2} height={tickH}
                rx={1}
                fill={color}
                opacity={0.92}
                style={{ cursor: 'pointer' }}
                onMouseEnter={ev => {
                  setHovered(e);
                  setTooltipPos({ x: ev.clientX, y: ev.clientY });
                }}
                onMouseMove={ev => {
                  setTooltipPos({ x: ev.clientX, y: ev.clientY });
                }}
                onMouseLeave={() => setHovered(null)}
              />
            );
          })}

          {/* "Now" cursor */}
          <line
            x1="100%" y1={2}
            x2="100%" y2={H - 2}
            stroke="rgba(111,231,212,0.45)"
            strokeWidth="1"
          />
        </svg>

        {/* Axis labels */}
        <div style={{
          position: 'relative',
          height: 12,
          marginTop: 2,
          fontSize: 'var(--fs-micro)',
          color: 'var(--text-muted)',
        }}>
          {labels.map(({ pct, label }) => (
            <span key={label} style={{
              position: 'absolute',
              left: `${pct}%`,
              transform: 'translateX(-50%)',
              letterSpacing: 'var(--ls-label)',
            }}>
              {label}
            </span>
          ))}
          <span style={{
            position: 'absolute',
            right: 0,
            color: 'var(--accent-2)',
            letterSpacing: 'var(--ls-label)',
            fontWeight: 600,
          }}>
            NOW
          </span>
        </div>
      </div>
    </div>
  );
};

// ── Readout — operation-monitor style label / value pair ────────────────

interface ReadoutProps {
  label: string;
  value: string;
  sub?: string;
  tone?: 'normal' | 'warn' | 'hot';
}

const TONE_COLOR: Record<NonNullable<ReadoutProps['tone']>, string> = {
  normal: 'var(--text-bright)',
  warn:   'var(--warn)',
  hot:    'var(--danger)',
};

const Readout: React.FC<ReadoutProps> = ({ label, value, sub, tone = 'normal' }) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
    <span className="hk-label">{label}</span>
    <span style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--sp-1)' }}>
      <span className="hk-num" style={{
        fontFamily: 'var(--font-disp)',
        fontSize: 'var(--fs-h)',
        fontWeight: 700,
        color: TONE_COLOR[tone],
        lineHeight: 1,
        transition: 'color 0.4s ease',
      }}>
        {value}
      </span>
      {sub && (
        <span style={{
          fontSize: 'var(--fs-micro)',
          color: 'var(--text-muted)',
          letterSpacing: 'var(--ls-label)',
          textTransform: 'uppercase',
        }}>
          {sub}
        </span>
      )}
    </span>
  </div>
);
