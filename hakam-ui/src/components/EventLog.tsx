import React, { useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { LogEntry, FAMILY_COLOR } from '../utils/websocket';

type Filter = 'all' | 'block' | 'connect';

interface Props {
  logs: LogEntry[];
}

export const EventLog: React.FC<Props> = ({ logs }) => {
  const [filter, setFilter] = useState<Filter>('all');

  const visible = logs.filter(l => {
    if (filter === 'block')   return l.level === 'critical';
    if (filter === 'connect') return l.message.startsWith('[');
    return true;
  }).slice(0, 80);

  const critCount = logs.filter(l => l.level === 'critical').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', padding: '10px 12px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
        {(['all', 'block', 'connect'] as Filter[]).map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`hk-tab ${filter === f ? 'active' : ''}`}
            style={{ padding: '3px 8px' }}
          >
            [{f === 'all' ? 'ALL' : f === 'block' ? `BLOCKS·${critCount}` : 'CONNECTS'}]
          </button>
        ))}
        <span style={{ marginLeft: 'auto', fontSize: 9, color: 'var(--text-dim)' }}>
          {logs.length} events
        </span>
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: '80px 68px 56px 1fr',
        gap: 8,
        padding: '3px 0',
        fontSize: 8,
        letterSpacing: '0.14em',
        color: 'var(--text-dim)',
        borderBottom: '1px solid var(--border-dim)',
        marginBottom: 4,
      }}>
        <span>TIME</span>
        <span>TYPE</span>
        <span>FAMILY</span>
        <span>DETAIL</span>
      </div>

      <div style={{ flex: 1, overflowY: 'auto' }}>
        <AnimatePresence initial={false}>
          {visible.map(log => (
            <LogRow key={log.id} log={log} />
          ))}
        </AnimatePresence>
        {visible.length === 0 && (
          <div style={{ color: 'var(--text-dim)', fontSize: 10, padding: '12px 0' }}>
            waiting for events…
          </div>
        )}
      </div>
    </div>
  );
};

const LogRow: React.FC<{ log: LogEntry }> = ({ log }) => {
  const isBlock   = log.level === 'critical';
  const isConnect = log.message.startsWith('[');
  const typeStr   = isBlock ? 'BLOCK' : isConnect ? 'CONNECT' : 'INFO';
  const typeColor = isBlock ? 'var(--danger)' : isConnect ? 'var(--accent)' : 'var(--text-dim)';
  const famColor  = log.category ? FAMILY_COLOR[log.category] : 'var(--text-dim)';

  return (
    <motion.div
      initial={{ opacity: 0, y: -4 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.15 }}
      style={{
        display: 'grid',
        gridTemplateColumns: '80px 68px 56px 1fr',
        gap: 8,
        padding: '4px 0',
        fontSize: 10,
        borderBottom: '1px solid var(--border-dim)',
        alignItems: 'center',
        background: isBlock ? 'rgba(255,59,59,0.04)' : 'transparent',
      }}
    >
      <span style={{ color: 'var(--text-dim)', fontSize: 9, fontVariantNumeric: 'tabular-nums' }}>
        {log.time.slice(0, 12)}
      </span>
      <span style={{ color: typeColor, fontSize: 9, letterSpacing: '0.08em', fontWeight: 600 }}>
        {typeStr}
      </span>
      <span style={{ color: famColor, fontSize: 9, letterSpacing: '0.04em' }}>
        {log.category ?? '—'}
      </span>
      <span style={{ color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {log.message}
      </span>
    </motion.div>
  );
};
