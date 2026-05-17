import React from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { AttackFamily, FAMILY_COLOR, Severity } from '../utils/websocket';

interface SplashData {
  id: string;
  source: string;
  category: AttackFamily;
  severity: Severity;
  pattern?: string;
  action: string;
}

interface Props {
  splash: SplashData | null;
}

// Headline card for critical / high severity blocks. Top-right of the
// viewport so it never overlaps the topology nodes.
export const InterceptSplash: React.FC<Props> = ({ splash }) => {
  return (
    <AnimatePresence>
      {splash && (
        <motion.div
          key={splash.id}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1, transition: { duration: 0.18, ease: 'easeOut' } }}
          exit={{ opacity: 0,    transition: { duration: 0.22, ease: 'easeIn'  } }}
          className="pointer-events-none fixed z-40"
          style={{ top: 60, right: 20 }}
        >
          <Card splash={splash} />
        </motion.div>
      )}
    </AnimatePresence>
  );
};

const Card: React.FC<{ splash: SplashData }> = ({ splash }) => {
  const color = FAMILY_COLOR[splash.category];

  return (
    <motion.div
      initial={{ x: 16, opacity: 0 }}
      animate={{ x: 0,  opacity: 1 }}
      exit={{    x: 12, opacity: 0 }}
      transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
      style={{
        position: 'relative',
        display: 'flex',
        alignItems: 'center',
        gap: 22,
        padding: '14px 22px 14px 26px',
        borderRadius: 6,
        border: `1px solid ${color}55`,
        background: 'rgba(8, 10, 14, 0.96)',
        boxShadow: `0 0 18px -6px ${color}99, 0 16px 32px -12px rgba(0,0,0,0.65)`,
        minWidth: 380,
        maxWidth: 460,
      }}
    >
      <span style={{
        position: 'absolute',
        left: 0, top: 10, bottom: 10,
        width: 3,
        background: color,
        borderRadius: '0 2px 2px 0',
      }} />

      <div style={{ display: 'flex', flexDirection: 'column', gap: 3, minWidth: 96 }}>
        <span style={{
          fontFamily: 'var(--font-disp)',
          fontSize: 26,
          fontWeight: 700,
          color,
          lineHeight: 1,
          letterSpacing: '-0.02em',
        }}>
          {splash.category}
        </span>
        <span style={{
          fontSize: 'var(--fs-micro)',
          fontWeight: 700,
          letterSpacing: 'var(--ls-label)',
          color: 'var(--text-dim)',
          textTransform: 'uppercase',
        }}>
          {splash.severity} · blocked
        </span>
      </div>

      <span style={{
        width: 1,
        alignSelf: 'stretch',
        background: 'var(--border-dim)',
      }} />

      <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, minWidth: 0 }}>
        <span style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 14,
          fontWeight: 600,
          color: 'var(--text-bright)',
          fontVariantNumeric: 'tabular-nums',
          letterSpacing: 0,
        }}>
          {splash.source}
        </span>
        <span style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 'var(--fs-small)',
          color: 'var(--text-dim)',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}>
          {splash.pattern ?? '—'}
        </span>
      </div>
    </motion.div>
  );
};
