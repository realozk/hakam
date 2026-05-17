import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { RecentAttack, FAMILY_COLOR } from '../utils/websocket';

interface Props {
  threatsBlocked: number;
  recentAttacks: RecentAttack[];
  wsConnected: boolean;
  isStale: boolean;
}

export const MobileView: React.FC<Props> = ({ threatsBlocked, recentAttacks, wsConnected, isStale }) => {
  const statusLabel = !wsConnected ? 'OFFLINE' : isStale ? 'STALE' : 'LIVE';
  const statusClass = !wsConnected ? 'bad pulse' : isStale ? 'warn' : '';
  const statusColor = !wsConnected ? 'var(--danger)'
                    : isStale     ? 'var(--warn)'
                                  : 'var(--accent-2)';
  return (
    <div style={{
      minHeight: '100vh',
      background: 'var(--bg)',
      color: 'var(--text)',
      display: 'flex',
      flexDirection: 'column',
      padding: '24px 20px 32px',
      gap: 28,
    }}>
      <div className="dot-grid" style={{
        position: 'fixed', inset: 0, zIndex: 0, pointerEvents: 'none', opacity: 0.25,
      }} />

      {/* ── Brand ── */}
      <header style={{ position: 'relative', zIndex: 1, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <svg width="22" height="22" viewBox="0 0 16 16" fill="none">
            <rect x="1" y="1" width="6" height="6" stroke="var(--text-bright)" strokeWidth="1.4"/>
            <rect x="9" y="1" width="6" height="6" stroke="var(--text-bright)" strokeWidth="1.4" opacity=".5"/>
            <rect x="1" y="9" width="6" height="6" stroke="var(--text-bright)" strokeWidth="1.4" opacity=".5"/>
            <rect x="9" y="9" width="6" height="6" stroke="var(--text-bright)" strokeWidth="1.4" opacity=".25"/>
          </svg>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-bright)', letterSpacing: 'var(--ls-label)' }}>
              HAKAM
            </div>
            <div style={{ fontSize: 9, color: 'var(--text-dim)', letterSpacing: 'var(--ls-label)', fontWeight: 500, marginTop: 2 }}>
              KERNEL-RESIDENT eBPF FIREWALL
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span className={`status-dot ${statusClass}`} />
          <span style={{
            fontSize: 9, letterSpacing: 'var(--ls-label)', fontWeight: 600,
            color: statusColor,
          }}>
            {statusLabel}
          </span>
        </div>
      </header>

      {/* ── Hero counter ── */}
      <section style={{
        position: 'relative', zIndex: 1,
        padding: '28px 22px',
        background: 'var(--surface)',
        border: '1px solid var(--border-dim)',
        borderRadius: 'var(--r-large)',
        textAlign: 'center',
      }}>
        <div className="hk-label" style={{ marginBottom: 8 }}>THREATS_NEUTRALIZED</div>
        <AnimatePresence mode="popLayout" initial={false}>
          <motion.div
            key={threatsBlocked}
            initial={{ y: 14, opacity: 0 }}
            animate={{ y: 0,  opacity: 1 }}
            exit={{    y: -14, opacity: 0 }}
            transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
            className="hk-num"
            style={{
              fontFamily: 'var(--font-disp)',
              fontSize: 56,
              fontWeight: 700,
              color: 'var(--text-bright)',
              lineHeight: 1,
            }}
          >
            {threatsBlocked.toLocaleString()}
          </motion.div>
        </AnimatePresence>
      </section>

      {/* ── How it works ── */}
      <section style={{ position: 'relative', zIndex: 1 }}>
        <div className="hk-label" style={{ marginBottom: 10 }}>HOW_IT_WORKS</div>
        <ul style={{
          listStyle: 'none', padding: 0, margin: 0,
          display: 'flex', flexDirection: 'column', gap: 10,
          fontSize: 13, color: 'var(--text)',
        }}>
          <Bullet>XDP drops malicious packets in <Strong>&lt;10 ns</Strong>, before a socket buffer is allocated.</Bullet>
          <Bullet><Strong>203 signatures</Strong> across 12 attack families: SQLi, XSS, RCE, LFI, SSRF, Log4Shell, more.</Bullet>
          <Bullet>Kernel-resident — runs as <Strong>eBPF</Strong> (XDP + TC + tracepoint). Zero userspace cost on the hot path.</Bullet>
        </ul>
      </section>

      {/* ── Recent intercepts ── */}
      {recentAttacks.length > 0 && (
        <section style={{ position: 'relative', zIndex: 1 }}>
          <div className="hk-label" style={{ marginBottom: 10 }}>RECENT_INTERCEPTS</div>
          <div style={{
            background: 'var(--surface)',
            border: '1px solid var(--border-dim)',
            borderRadius: 'var(--r-panel)',
            overflow: 'hidden',
          }}>
            {recentAttacks.slice(0, 5).map(a => (
              <div key={a.id} style={{
                display: 'grid',
                gridTemplateColumns: '64px 1fr',
                alignItems: 'center',
                gap: 10,
                padding: '8px 12px',
                fontSize: 12,
                borderBottom: '1px solid var(--border-dim)',
              }}>
                <span style={{ color: FAMILY_COLOR[a.category], fontWeight: 700, letterSpacing: 'var(--ls-label)' }}>
                  {a.category}
                </span>
                <span style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
                  <span style={{
                    color: 'var(--text-bright)', fontFamily: 'var(--font-mono)',
                    fontVariantNumeric: 'tabular-nums', fontWeight: 500,
                  }}>
                    {a.source}
                  </span>
                  {a.pattern && (
                    <>
                      <span style={{ color: 'var(--text-muted)' }}>·</span>
                      <span style={{
                        color: 'var(--text-dim)', fontFamily: 'var(--font-mono)',
                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                      }}>
                        {a.pattern.slice(0, 28)}
                      </span>
                    </>
                  )}
                </span>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* ── Desktop hint ── */}
      <footer style={{
        position: 'relative', zIndex: 1, marginTop: 'auto',
        paddingTop: 18, borderTop: '1px solid var(--border-dim)',
        textAlign: 'center', fontSize: 11, color: 'var(--text-dim)',
        letterSpacing: 'var(--ls-label)', lineHeight: 1.55,
      }}>
        <div style={{ marginBottom: 4 }}>Live HUD best viewed on desktop</div>
        <div style={{ color: 'var(--text-muted)' }}>
          open the same URL on a wider screen
        </div>
      </footer>
    </div>
  );
};

const Bullet: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <li style={{ display: 'flex', gap: 10, lineHeight: 1.5 }}>
    <span style={{ color: 'var(--accent-2)', flexShrink: 0 }}>▸</span>
    <span>{children}</span>
  </li>
);

const Strong: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <span style={{ color: 'var(--text-bright)', fontWeight: 600 }}>{children}</span>
);
