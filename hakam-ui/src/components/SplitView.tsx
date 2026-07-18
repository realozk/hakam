import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, ShieldOff } from 'lucide-react';
import { FamilyCounts, AttackFamily, FAMILY_COLOR, ThreatLevel, THREAT_LEVEL_META } from '../utils/websocket';

interface Props {
  open: boolean;
  onClose: () => void;
  threatsBlocked: number;
  familyCounts: FamilyCounts;
  detectionRate: number;
  peakRate: number;
  threatLevel: ThreatLevel;
}

export const SplitView: React.FC<Props> = ({
  open, onClose, threatsBlocked, familyCounts, detectionRate, peakRate, threatLevel,
}) => {
  // Animate the "breach" counter on the vulnerable side counting up when opened
  const [breachCount, setBreachCount] = useState(0);
  useEffect(() => {
    if (!open) { setBreachCount(0); return; }
    const target = threatsBlocked;
    if (target === 0) return;
    let current = 0;
    const steps = 40;
    const increment = target / steps;
    const id = setInterval(() => {
      current += increment;
      if (current >= target) { setBreachCount(target); clearInterval(id); }
      else setBreachCount(Math.round(current));
    }, 40);
    return () => clearInterval(id);
  }, [open, threatsBlocked]);

  const activeFamilies = (Object.entries(familyCounts) as [AttackFamily, number][])
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);

  const tlMeta = THREAT_LEVEL_META[threatLevel];

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          key="split"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.22 }}
          onClick={onClose}
          style={{
            position: 'fixed', inset: 0, zIndex: 80,
            background: 'rgba(2,3,4,0.96)',
            backdropFilter: 'blur(20px)',
            display: 'flex',
            flexDirection: 'column',
          }}
        >
          {/* ── Top bar ── */}
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            padding: '14px 32px', borderBottom: '1px solid rgba(255,255,255,0.06)',
            flexShrink: 0, gap: 24,
          }}>
            <span style={{ fontSize: 9, letterSpacing: '0.28em', color: 'rgba(255,255,255,0.25)', fontWeight: 600 }}>
              HAKAM · PROTECTION_DELTA
            </span>
            <span style={{ fontSize: 8, color: 'rgba(255,255,255,0.18)', letterSpacing: '0.16em' }}>
              press V or ESC to close
            </span>
          </div>

          {/* ── Main split ── */}
          <div
            onClick={e => e.stopPropagation()}
            style={{
              display: 'flex', flex: 1, overflow: 'hidden',
            }}
          >
            {/* ══ LEFT — Protected ══ */}
            <motion.div
              initial={{ x: -40, opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              transition={{ delay: 0.08, type: 'spring', stiffness: 200, damping: 26 }}
              style={{
                flex: 1, display: 'flex', flexDirection: 'column',
                padding: '40px 48px',
                background: 'linear-gradient(180deg, rgba(0,229,204,0.04) 0%, transparent 60%)',
                borderRight: '1px solid rgba(255,255,255,0.05)',
                overflow: 'hidden',
              }}
            >
              {/* Header */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 32 }}>
                <div style={{
                  width: 36, height: 36, borderRadius: 6,
                  background: 'rgba(0,229,204,0.12)',
                  border: '1px solid rgba(0,229,204,0.35)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  <Shield size={18} color="#00e5cc" strokeWidth={1.8} />
                </div>
                <div>
                  <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.20em', color: '#00e5cc' }}>
                    HAKAM ACTIVE
                  </div>
                  <div style={{ fontSize: 9, color: 'rgba(255,255,255,0.30)', letterSpacing: '0.14em', marginTop: 2 }}>
                    eBPF kernel-resident firewall
                  </div>
                </div>
              </div>

              {/* Big counter */}
              <div style={{ marginBottom: 12 }}>
                <div style={{
                  fontFamily: 'var(--font-disp)', fontSize: 96,
                  fontWeight: 700, lineHeight: 1,
                  letterSpacing: '-0.03em', color: '#f0f4f8',
                  fontVariantNumeric: 'tabular-nums',
                }}>
                  0
                </div>
                <div style={{
                  fontSize: 11, letterSpacing: '0.24em', fontWeight: 700,
                  color: '#00e5cc', marginTop: 8,
                }}>
                  BREACHES
                </div>
                <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.30)', marginTop: 6, letterSpacing: '0.08em' }}>
                  All {threatsBlocked} attacks blocked in kernel space
                </div>
              </div>

              {/* Key stats */}
              <div style={{ display: 'flex', gap: 12, marginBottom: 32 }}>
                {[
                  { v: '< 10 ns', l: 'DROP LATENCY' },
                  { v: '202',     l: 'SIGNATURES'   },
                  { v: 'ZERO',    l: 'USERSPACE'    },
                ].map(({ v, l }) => (
                  <div key={l} style={{
                    flex: 1, padding: '10px 12px',
                    background: 'rgba(0,229,204,0.06)',
                    border: '1px solid rgba(0,229,204,0.18)',
                    borderRadius: 4, textAlign: 'center',
                  }}>
                    <div style={{ fontFamily: 'var(--font-disp)', fontSize: 18, fontWeight: 700, color: '#00e5cc' }}>{v}</div>
                    <div style={{ fontSize: 8, color: 'rgba(255,255,255,0.30)', letterSpacing: '0.18em', marginTop: 4 }}>{l}</div>
                  </div>
                ))}
              </div>

              {/* Rate */}
              <div style={{
                padding: '10px 14px', marginBottom: 24,
                background: 'rgba(0,229,204,0.04)',
                border: '1px solid rgba(0,229,204,0.12)',
                borderRadius: 4,
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              }}>
                <span style={{ fontSize: 9, color: 'rgba(255,255,255,0.30)', letterSpacing: '0.14em' }}>DETECTION RATE</span>
                <span style={{ fontSize: 14, fontWeight: 700, color: '#00e5cc', fontVariantNumeric: 'tabular-nums' }}>
                  {detectionRate.toFixed(2)}/s
                </span>
              </div>

              {/* Family list — protected */}
              {activeFamilies.length > 0 && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {activeFamilies.map(([fam, n]) => (
                    <div key={fam} style={{
                      display: 'flex', alignItems: 'center',
                      justifyContent: 'space-between', fontSize: 10,
                    }}>
                      <span style={{ color: FAMILY_COLOR[fam], fontWeight: 600 }}>{fam}</span>
                      <span style={{
                        fontSize: 8, padding: '2px 8px',
                        background: 'rgba(0,229,204,0.08)',
                        border: '1px solid rgba(0,229,204,0.20)',
                        color: '#00e5cc', borderRadius: 2,
                        letterSpacing: '0.14em', fontWeight: 700,
                      }}>
                        {n} BLOCKED
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </motion.div>

            {/* ══ CENTER DIVIDER ══ */}
            <div style={{
              width: 160, flexShrink: 0,
              display: 'flex', flexDirection: 'column',
              alignItems: 'center', justifyContent: 'center',
              gap: 16, padding: '0 8px',
              position: 'relative',
            }}>
              <div style={{
                position: 'absolute', top: 0, bottom: 0, left: '50%',
                width: 1, background: 'rgba(255,255,255,0.06)',
              }} />
              <div style={{
                position: 'relative', zIndex: 1,
                display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12,
                background: 'rgba(2,3,4,0.96)', padding: '20px 12px', borderRadius: 8,
              }}>
                <div style={{
                  fontSize: 8, letterSpacing: '0.22em', fontWeight: 700,
                  color: 'rgba(255,255,255,0.22)',
                }}>
                  DELTA
                </div>
                <motion.div
                  initial={{ scale: 0.8, opacity: 0 }}
                  animate={{ scale: 1, opacity: 1 }}
                  transition={{ delay: 0.4, type: 'spring', stiffness: 200, damping: 20 }}
                  style={{
                    fontFamily: 'var(--font-disp)',
                    fontSize: 44, fontWeight: 700,
                    color: '#f0f4f8',
                    lineHeight: 1,
                    fontVariantNumeric: 'tabular-nums',
                    textAlign: 'center',
                  }}
                >
                  {threatsBlocked.toLocaleString()}
                </motion.div>
                <div style={{
                  fontSize: 9, letterSpacing: '0.16em', fontWeight: 700,
                  color: '#00e5cc', textAlign: 'center',
                }}>
                  ATTACKS<br />STOPPED
                </div>
                <div style={{
                  width: 32, height: 1, background: 'rgba(255,255,255,0.12)',
                }} />
                <div style={{ fontSize: 8, color: 'rgba(255,255,255,0.28)', letterSpacing: '0.10em', textAlign: 'center' }}>
                  THREAT<br />LEVEL
                </div>
                <div style={{
                  fontSize: 10, fontWeight: 700, letterSpacing: '0.14em',
                  color: tlMeta.color,
                }}>
                  {tlMeta.label}
                </div>
                {peakRate > 0 && (
                  <>
                    <div style={{ width: 32, height: 1, background: 'rgba(255,255,255,0.12)' }} />
                    <div style={{ fontSize: 8, color: 'rgba(255,255,255,0.28)', letterSpacing: '0.10em', textAlign: 'center' }}>
                      PEAK RATE
                    </div>
                    <div style={{ fontSize: 10, fontWeight: 700, color: '#f5b35c', fontVariantNumeric: 'tabular-nums' }}>
                      {peakRate.toFixed(1)}/s
                    </div>
                  </>
                )}
              </div>
            </div>

            {/* ══ RIGHT — Vulnerable ══ */}
            <motion.div
              initial={{ x: 40, opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              transition={{ delay: 0.08, type: 'spring', stiffness: 200, damping: 26 }}
              style={{
                flex: 1, display: 'flex', flexDirection: 'column',
                padding: '40px 48px',
                background: 'linear-gradient(180deg, rgba(239,68,68,0.06) 0%, transparent 60%)',
                borderLeft: '1px solid rgba(255,255,255,0.05)',
                overflow: 'hidden',
              }}
            >
              {/* Header */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 32 }}>
                <div style={{
                  width: 36, height: 36, borderRadius: 6,
                  background: 'rgba(239,68,68,0.12)',
                  border: '1px solid rgba(239,68,68,0.35)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  <ShieldOff size={18} color="#ef4444" strokeWidth={1.8} />
                </div>
                <div>
                  <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.20em', color: '#ef4444' }}>
                    UNPROTECTED
                  </div>
                  <div style={{ fontSize: 9, color: 'rgba(255,255,255,0.30)', letterSpacing: '0.14em', marginTop: 2 }}>
                    no kernel firewall — full exposure
                  </div>
                </div>
              </div>

              {/* Breach counter */}
              <div style={{ marginBottom: 12 }}>
                <motion.div
                  style={{
                    fontFamily: 'var(--font-disp)', fontSize: 96,
                    fontWeight: 700, lineHeight: 1,
                    letterSpacing: '-0.03em', color: '#ef4444',
                    fontVariantNumeric: 'tabular-nums',
                  }}
                >
                  {breachCount.toLocaleString()}
                </motion.div>
                <div style={{
                  fontSize: 11, letterSpacing: '0.24em', fontWeight: 700,
                  color: '#ef4444', marginTop: 8,
                }}>
                  BREACHES
                </div>
                <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.30)', marginTop: 6, letterSpacing: '0.08em' }}>
                  Every attack reached the application layer
                </div>
              </div>

              {/* Key stats */}
              <div style={{ display: 'flex', gap: 12, marginBottom: 32 }}>
                {[
                  { v: '~1.2 µs', l: 'DETECT LATENCY' },
                  { v: '0',       l: 'SIGNATURES'     },
                  { v: '100%',    l: 'USERSPACE HIT'  },
                ].map(({ v, l }) => (
                  <div key={l} style={{
                    flex: 1, padding: '10px 12px',
                    background: 'rgba(239,68,68,0.06)',
                    border: '1px solid rgba(239,68,68,0.18)',
                    borderRadius: 4, textAlign: 'center',
                  }}>
                    <div style={{ fontFamily: 'var(--font-disp)', fontSize: 18, fontWeight: 700, color: '#ef4444' }}>{v}</div>
                    <div style={{ fontSize: 8, color: 'rgba(255,255,255,0.30)', letterSpacing: '0.18em', marginTop: 4 }}>{l}</div>
                  </div>
                ))}
              </div>

              {/* Rate */}
              <div style={{
                padding: '10px 14px', marginBottom: 24,
                background: 'rgba(239,68,68,0.04)',
                border: '1px solid rgba(239,68,68,0.12)',
                borderRadius: 4,
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              }}>
                <span style={{ fontSize: 9, color: 'rgba(255,255,255,0.30)', letterSpacing: '0.14em' }}>BREACH RATE</span>
                <span style={{ fontSize: 14, fontWeight: 700, color: '#ef4444', fontVariantNumeric: 'tabular-nums' }}>
                  {detectionRate.toFixed(2)}/s
                </span>
              </div>

              {/* Family list — compromised */}
              {activeFamilies.length > 0 && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {activeFamilies.map(([fam, n]) => (
                    <div key={fam} style={{
                      display: 'flex', alignItems: 'center',
                      justifyContent: 'space-between', fontSize: 10,
                    }}>
                      <span style={{ color: FAMILY_COLOR[fam], fontWeight: 600 }}>{fam}</span>
                      <span style={{
                        fontSize: 8, padding: '2px 8px',
                        background: 'rgba(239,68,68,0.10)',
                        border: '1px solid rgba(239,68,68,0.25)',
                        color: '#ef4444', borderRadius: 2,
                        letterSpacing: '0.14em', fontWeight: 700,
                      }}>
                        {n} BREACHED
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </motion.div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};
