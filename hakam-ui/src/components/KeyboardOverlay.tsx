import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';

interface Props {
  open: boolean;
  onClose: () => void;
}

type KeyEntry = { combo: string; desc: string; group: 'demo' | 'ui' };

const KEYS: KeyEntry[] = [
  { combo: '?',     desc: 'Toggle this help overlay',     group: 'ui'   },
  { combo: 'Esc',   desc: 'Close this overlay',           group: 'ui'   },
  { combo: 'F',     desc: 'Toggle fullscreen',            group: 'ui'   },
  { combo: 'M',     desc: 'Toggle intercept sound',       group: 'ui'   },
  { combo: 'V',     desc: 'Protected vs Vulnerable view', group: 'ui'   },
  { combo: 'Space', desc: 'Pause / resume demo cycle',    group: 'demo' },
  { combo: 'N',     desc: 'Skip to next attack phase',    group: 'demo' },
  { combo: 'R',     desc: 'Restart current phase',        group: 'demo' },
  { combo: '0–6',   desc: 'Jump to a specific demo phase', group: 'demo' },
  { combo: 'Q',     desc: 'Quit demo cycle',              group: 'demo' },
];

export const KeyboardOverlay: React.FC<Props> = ({ open, onClose }) => (
  <AnimatePresence>
    {open && (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.18 }}
        onClick={onClose}
        style={{
          position: 'fixed', inset: 0, zIndex: 100,
          background: 'rgba(0, 0, 0, 0.72)',
          backdropFilter: 'blur(10px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: 20,
        }}
      >
        <motion.div
          initial={{ scale: 0.95, y: 14, opacity: 0 }}
          animate={{ scale: 1,    y: 0,  opacity: 1 }}
          exit={{    scale: 0.96, y: 10, opacity: 0 }}
          transition={{ type: 'spring', stiffness: 240, damping: 22 }}
          onClick={e => e.stopPropagation()}
          style={{
            width: 480,
            maxWidth: '100%',
            background: 'rgba(10, 12, 16, 0.96)',
            border: '1px solid var(--border)',
            borderRadius: 4,
            boxShadow: '0 28px 80px rgba(0,0,0,0.6), 0 0 0 1px rgba(111,231,212,0.12)',
            overflow: 'hidden',
          }}
        >
          {/* Header */}
          <div style={{
            padding: '13px 20px',
            borderBottom: '1px solid var(--border-dim)',
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span className="status-dot pulse" style={{ background: 'var(--accent-2)' }} />
              <span style={{
                fontSize: 11, fontWeight: 700, letterSpacing: '0.20em',
                color: 'var(--text-bright)',
              }}>
                PRESENTER_KEYS
              </span>
            </div>
            <span style={{ fontSize: 9, color: 'var(--text-dim)', letterSpacing: '0.16em' }}>
              demo-cycle.sh
            </span>
          </div>

          {/* Body */}
          <div style={{ padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 14 }}>
            <Section title="DEMO_CONTROL" subtitle="works here OR in the demo-cycle.sh terminal">
              {KEYS.filter(k => k.group === 'demo').map(k => <KeyRow key={k.combo} combo={k.combo} desc={k.desc} />)}
            </Section>
            <Section title="OVERLAY">
              {KEYS.filter(k => k.group === 'ui').map(k => <KeyRow key={k.combo} combo={k.combo} desc={k.desc} />)}
            </Section>
          </div>

          {/* Footer */}
          <div style={{
            padding: '10px 20px',
            borderTop: '1px solid var(--border-dim)',
            fontSize: 9,
            color: 'var(--text-muted)',
            letterSpacing: '0.14em',
            background: 'rgba(255,255,255,0.012)',
          }}>
            click anywhere outside to close · same shortcut to toggle
          </div>
        </motion.div>
      </motion.div>
    )}
  </AnimatePresence>
);

// ── Subcomponents ──────────────────────────────────────────────────────────

const Section: React.FC<{ title: string; subtitle?: string; children: React.ReactNode }>
  = ({ title, subtitle, children }) => (
  <div>
    <div style={{
      fontSize: 9, fontWeight: 600, letterSpacing: '0.20em',
      color: 'var(--text-muted)', marginBottom: 6,
    }}>
      {title}
      {subtitle && (
        <span style={{ marginLeft: 8, letterSpacing: '0.06em', textTransform: 'none', color: 'var(--text-muted)', opacity: 0.7 }}>
          · {subtitle}
        </span>
      )}
    </div>
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      {children}
    </div>
  </div>
);

const KeyRow: React.FC<{ combo: string; desc: string }> = ({ combo, desc }) => (
  <div style={{
    display: 'grid', gridTemplateColumns: '72px 1fr',
    gap: 16, alignItems: 'center', padding: '2px 0',
  }}>
    <kbd style={{
      fontFamily: 'var(--font-sans)',
      fontSize: 'var(--fs-small)',
      fontWeight: 700,
      letterSpacing: 0,
      background: 'var(--surface-2)',
      border: '1px solid var(--border)',
      borderBottom: '2px solid rgba(255,255,255,0.10)',
      borderRadius: 'var(--r-chip)',
      padding: 'var(--sp-1) var(--sp-2)',
      textAlign: 'center',
      color: 'var(--text-bright)',
      display: 'inline-block',
    }}>
      {combo}
    </kbd>
    <span style={{ fontSize: 11, color: 'var(--text)' }}>
      {desc}
    </span>
  </div>
);
