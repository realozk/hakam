import { useState, useEffect, useRef } from 'react';

// Reconnect delay doubles after each failure up to MAX. Stale indicator
// fires when the WS is open but no events arrive for STALE_THRESHOLD_MS.
const INITIAL_RECONNECT_MS = 3_000;
const MAX_RECONNECT_MS     = 60_000;
const STALE_THRESHOLD_MS   = 30_000;

export type LogLevel = 'info' | 'warn' | 'critical';
export type Severity = 'critical' | 'high' | 'medium' | 'low';

// Keep in sync with hakam-node/src/signatures.rs CATEGORIES.
export const ATTACK_FAMILIES = [
  'SQLi', 'XSS', 'LFI', 'RCE', 'SSRF', 'XXE',
  'Log4Shell', 'Deserial', 'NoSQLi', 'SSTI',
  'WebShell', 'Recon', 'CVE', 'Manual',
] as const;
export type AttackFamily = typeof ATTACK_FAMILIES[number];

export const FAMILY_COLOR: Record<AttackFamily, string> = {
  SQLi:      '#ef4444', // red
  XSS:       '#f97316', // orange
  LFI:       '#eab308', // yellow
  RCE:       '#dc2626', // dark red
  SSRF:      '#a855f7', // purple
  XXE:       '#8b5cf6', // violet
  Log4Shell: '#f43f5e', // rose — flagship CVE
  Deserial:  '#ec4899', // pink
  NoSQLi:    '#06b6d4', // cyan
  SSTI:      '#10b981', // emerald
  WebShell:  '#b91c1c', // dark red
  Recon:     '#64748b', // slate
  CVE:       '#0ea5e9', // sky
  Manual:    '#6366f1', // indigo
};

export interface LogEntry {
  id: string;
  time: string;
  message: string;
  level: LogLevel;
  role?: NodeRole;
  /** When level==='critical' from a BLOCK, this carries the attack family. */
  category?: AttackFamily;
  severity?: Severity;
  pattern?: string;
}

// ── Network topology model ───────────────────────────────────────────────────
export type NodeRole = 'attacker' | 'pc1' | 'pc2' | 'db' | 'firewall';

export interface NodeState {
  active: boolean;
  blocked: boolean;
  /** ms-epoch of the most recent BLOCK whose source resolved to this role.
   *  Drives the time-decayed visual state in TopologyMap. */
  lastBlockedAt?: number;
  /** ms-epoch of the most recent CONNECT to this role. Drives a subtle
   *  cyan "live traffic" pulse so the HUD doesn't look frozen during
   *  benign-only periods. */
  lastBenignAt?: number;
  lastAction?: string;
  lastPayload?: string;
  lastIp?: string;
}

export type NodesState = Record<NodeRole, NodeState>;

export const NODE_META: Record<NodeRole, { label: string; sub: string; ip: string }> = {
  attacker: { label: 'External Vector',     sub: 'Internet / unknown origin', ip: '198.51.100.x' },
  pc1:      { label: 'PC #1 — Sales',       sub: 'Workstation, Sales subnet', ip: '10.99.1.10'   },
  pc2:      { label: 'PC #2 — Engineering', sub: 'Workstation, Engineering',  ip: '10.99.2.10'   },
  db:       { label: 'Database Server',     sub: 'Crown jewel, 10.99.0.0/24', ip: '10.99.0.10'   },
  firewall: { label: 'Hakam Kernel',      sub: 'XDP + TC + Tracepoint',     ip: 'kernel-space' },
};

export function roleForIp(ip: string | undefined): NodeRole {
  if (!ip) return 'attacker';
  if (ip.startsWith('10.99.0.')) return 'db';
  if (ip.startsWith('10.99.1.')) return 'pc1';
  if (ip.startsWith('10.99.2.')) return 'pc2';
  return 'attacker';
}

export interface AttackEdge {
  from: NodeRole;
  to: NodeRole;
  action?: string;
  payload?: string;
  category?: AttackFamily;
  severity?: Severity;
  blocked: boolean;
}

export interface ThreatState {
  nodes: NodesState;
  edge: AttackEdge | null;
  /** Floating threat card visibility — auto-clears 4.5 s after a BLOCK. */
  showCard: boolean;
}

// Last-N attacks, used by the side panel and the family bar chart.
export interface RecentAttack {
  id: string;
  time: string;
  ts: number;        // epoch ms — for timeline x-axis positioning
  source: string;
  category: AttackFamily;
  severity: Severity;
  action: string;
  pattern?: string;
}

// Threat level — DEFCON-style 5..1 (5 = calm, 1 = under heavy attack).
export type ThreatLevel = 1 | 2 | 3 | 4 | 5;

export const THREAT_LEVEL_META: Record<ThreatLevel, { label: string; color: string; sub: string }> = {
  5: { label: 'NOMINAL',  color: '#10b981', sub: 'No active threats' },
  4: { label: 'ELEVATED', color: '#22d3ee', sub: 'Light recon traffic'  },
  3: { label: 'GUARDED',  color: '#fbbf24', sub: 'Multiple intercepts in progress'  },
  2: { label: 'HIGH',     color: '#f97316', sub: 'Sustained inbound attacks'  },
  1: { label: 'SEVERE',   color: '#ef4444', sub: 'Multiple attack families active'  },
};

export type GlobalMetrics = {
  cpuHistory: number[];
  cpu: number;
  latency: number;          // p50 ns
  latencyP99: number;       // p99 ns
  packetsDropped: number;
  rxBandwidth: number;      // Gbps
  txBandwidth: number;      // Gbps
  rxHistory: number[];      // Gbps history (last 30 ticks)
  kernelMemory: string;
  /** Sum of per-CPU RING_OVERFLOW eBPF map — samples lost when ring was full. */
  ringOverflows: number;
};

export type FamilyCounts = Partial<Record<AttackFamily, number>>;

const ALL_ROLES: NodeRole[] = ['attacker', 'pc1', 'pc2', 'db', 'firewall'];

const initialNodes = (): NodesState =>
  ALL_ROLES.reduce((acc, role) => {
    acc[role] = { active: false, blocked: false };
    return acc;
  }, {} as NodesState);

const formatTime = () => {
  const d = new Date();
  return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}:${d.getSeconds().toString().padStart(2, '0')}.${d.getMilliseconds().toString().padStart(3, '0')}`;
};

const HISTORY_LEN = 60;

export function useHakamData() {
  const [logs, setLogs] = useState<LogEntry[]>([{
    id: 'init',
    time: formatTime(),
    message: 'Connecting to Hakam Kernel over WebSocket…',
    level: 'info'
  }]);

  const [metrics, setMetrics] = useState<GlobalMetrics>({
    cpuHistory: Array(HISTORY_LEN).fill(0),
    cpu: 0,
    latency: 0,
    latencyP99: 0,
    packetsDropped: 0,
    rxBandwidth: 0,
    txBandwidth: 0,
    rxHistory: Array(HISTORY_LEN).fill(0),
    kernelMemory: '0.0',
    ringOverflows: 0,
  });

  const [threatState, setThreatState] = useState<ThreatState>({
    nodes: initialNodes(),
    edge: null,
    showCard: false,
  });

  const [recentAttacks, setRecentAttacks] = useState<RecentAttack[]>([]);
  const [familyCounts, setFamilyCounts] = useState<FamilyCounts>({});
  const [threatLevel, setThreatLevel] = useState<ThreatLevel>(5);

  // Rolling 30 s windows of attack / CONNECT timestamps.
  const attackWindowRef = useRef<number[]>([]);
  const benignWindowRef = useRef<number[]>([]);
  const [benignRate, setBenignRate] = useState(0);

  const [splash, setSplash] = useState<{
    id: string;
    source: string;
    category: AttackFamily;
    severity: Severity;
    pattern?: string;
    action: string;
  } | null>(null);

  const [lastBlockTick, setLastBlockTick] = useState(0);
  const [lastBenignTick, setLastBenignTick] = useState<{ ts: number; dst: NodeRole }>({
    ts: 0, dst: 'db',
  });

  const [scenario, setScenario] = useState<{ phase: number; total: number; label: string } | null>(null);

  const wsRef = useRef<WebSocket | null>(null);

  // wsConnected drives the header status; don't infer from stale metric
  // history (last values linger after the socket dies). isStale catches the
  // "hakam-node is up but the demo script crashed" case.
  const [wsConnected, setWsConnected] = useState(false);
  const [isStale, setIsStale] = useState(false);
  const lastEventAtRef = useRef(0);

  const reconnectDelayRef = useRef(INITIAL_RECONNECT_MS);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Forwarded to demo-cycle.sh via hakam-node → /tmp/hakam-demo.cmd.
  const sendDemoCommand = (action: string) => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    ws.send(JSON.stringify({ type: 'DEMO_CMD', action }));
  };

  const cardTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const splashTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // The kernel blocklist holds an IP for 120 s, but the operator only needs
  // the red edge for ~3 s — past that it reads as a stuck UI.
  const edgeTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const activePulseRef = useRef<Map<NodeRole, ReturnType<typeof setTimeout>>>(new Map());

  const pulseActive = (role: NodeRole) => {
    setThreatState(prev => ({
      ...prev,
      nodes: { ...prev.nodes, [role]: { ...prev.nodes[role], active: true } },
    }));
    const existing = activePulseRef.current.get(role);
    if (existing) clearTimeout(existing);
    const t = setTimeout(() => {
      setThreatState(prev => ({
        ...prev,
        nodes: { ...prev.nodes, [role]: { ...prev.nodes[role], active: false } },
      }));
      activePulseRef.current.delete(role);
    }, 1200);
    activePulseRef.current.set(role, t);
  };

  // Threat level from the rolling 30-second attack window.
  const recomputeThreatLevel = (now: number) => {
    const cutoff = now - 30_000;
    attackWindowRef.current = attackWindowRef.current.filter(t => t >= cutoff);
    const n = attackWindowRef.current.length;
    let lvl: ThreatLevel = 5;
    if (n >= 12)      lvl = 1;
    else if (n >= 6)  lvl = 2;
    else if (n >= 3)  lvl = 3;
    else if (n >= 1)  lvl = 4;
    setThreatLevel(lvl);
  };

  useEffect(() => {
    // Decay threat level / benign rate, and flip isStale when events dry up.
    const id = setInterval(() => {
      const now = Date.now();
      recomputeThreatLevel(now);
      const cutoff = now - 30_000;
      benignWindowRef.current = benignWindowRef.current.filter(t => t >= cutoff);
      setBenignRate(benignWindowRef.current.length / 30);

      if (lastEventAtRef.current > 0
          && now - lastEventAtRef.current > STALE_THRESHOLD_MS) {
        setIsStale(true);
      }
    }, 1500);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    const wsUrl =
      (import.meta.env.VITE_HAKAM_WS_URL as string | undefined)
      || 'ws://localhost:8080/ws';

    const scheduleReconnect = () => {
      const delay = reconnectDelayRef.current;
      reconnectTimerRef.current = setTimeout(connectWS, delay);
      reconnectDelayRef.current = Math.min(delay * 2, MAX_RECONNECT_MS);
    };

    const connectWS = () => {
      try {
        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          setWsConnected(true);
          reconnectDelayRef.current = INITIAL_RECONNECT_MS;
          lastEventAtRef.current = Date.now();
          setIsStale(false);
          setLogs(prev => [{
            id: Math.random().toString(),
            time: formatTime(),
            message: '── Kernel WebSocket connected ──',
            level: 'info' as LogLevel,
          }, ...prev].slice(0, 200));
        };

        ws.onmessage = (event) => {
          lastEventAtRef.current = Date.now();
          setIsStale(false);
          try {
            const data = JSON.parse(event.data);

            if (data.type === 'METRICS') {
              setMetrics(prev => {
                const cpu = typeof data.cpu === 'number' ? data.cpu : prev.cpu;
                const cpuHistory = [...prev.cpuHistory.slice(1), cpu];
                const toGbps = (bps: number) => +((bps * 8) / 1_000_000_000).toFixed(2);
                const toMb   = (kb: number)  => ((kb) / 1024).toFixed(1);

                const rxGbps = data.rx_bps !== undefined ? toGbps(data.rx_bps) : prev.rxBandwidth;
                const txGbps = data.tx_bps !== undefined ? toGbps(data.tx_bps) : prev.txBandwidth;
                const rxHistory = [...prev.rxHistory.slice(1), rxGbps];

                // Rough pps estimate — 90 B average packet. Visual signal only.
                const rxBytes = data.rx_bps ?? 0;
                const pps = Math.round(rxBytes / 90);

                return {
                  cpuHistory,
                  cpu,
                  latency: data.latency_p50_ns ?? prev.latency,
                  latencyP99: data.latency_p99_ns ?? prev.latencyP99,
                  packetsDropped: data.dropped !== undefined ? data.dropped : prev.packetsDropped,
                  rxBandwidth: rxGbps,
                  txBandwidth: txGbps,
                  rxHistory,
                  kernelMemory: data.mem_kb !== undefined ? toMb(data.mem_kb) : prev.kernelMemory,
                  pps,
                  ringOverflows: data.ring_overflows !== undefined ? data.ring_overflows : prev.ringOverflows,
                };
              });
            } else if (data.type === 'CONNECT') {
              const dstRole = roleForIp(data.dst);
              const tsNow = Date.now();

              // Only count HTTP-target connects so DNS / WS / etc don't skew
              // the live-traffic rate.
              const isDemoTraffic = data.port === 80 || data.port === 443;

              if (isDemoTraffic) {
                benignWindowRef.current.push(tsNow);
                const cutoff = tsNow - 30_000;
                benignWindowRef.current = benignWindowRef.current.filter(t => t >= cutoff);
                setBenignRate(benignWindowRef.current.length / 30);

                setThreatState(prev => ({
                  ...prev,
                  nodes: {
                    ...prev.nodes,
                    [dstRole]: { ...prev.nodes[dstRole], lastBenignAt: tsNow },
                  },
                }));

                setLastBenignTick({ ts: tsNow, dst: dstRole });
              }

              setLogs(prev => [{
                id: Math.random().toString(),
                time: formatTime(),
                message: `[${data.comm}] PID ${data.pid} → ${data.dst}:${data.port}`,
                level: 'info' as LogLevel,
                role: dstRole,
              }, ...prev].slice(0, 200));
            } else if (data.type === 'EVENT') {
              setLogs(prev => [{
                id: Math.random().toString(),
                time: formatTime(),
                message: data.message || 'Unknown kernel event',
                level: data.level || 'info',
              }, ...prev].slice(0, 200));
            } else if (data.type === 'BLOCK') {
              const fromRole = roleForIp(data.source);
              const toRole   = roleForIp(data.target);
              const category = (data.category || 'Manual') as AttackFamily;
              const severity = (data.severity || 'high') as Severity;
              const id = Math.random().toString(36).slice(2);
              pulseActive(fromRole);

              setThreatState(prev => ({
                ...prev,
                nodes: {
                  ...prev.nodes,
                  [fromRole]: {
                    active: true,
                    blocked: true,
                    lastBlockedAt: Date.now(),
                    lastAction: data.action,
                    lastPayload: data.payload,
                    lastIp: data.source,
                  },
                },
                edge: {
                  from: fromRole,
                  to: toRole === 'attacker' ? 'firewall' : toRole,
                  action: data.action,
                  payload: data.payload,
                  category,
                  severity,
                  blocked: true,
                },
                showCard: true,
              }));

              setLastBlockTick(Date.now());
              attackWindowRef.current.push(Date.now());
              recomputeThreatLevel(Date.now());

              setRecentAttacks(prev => [{
                id,
                time: formatTime(),
                ts: Date.now(),
                source: data.source,
                category,
                severity,
                action: data.action || 'XDP_DROP',
                pattern: data.payload,
              }, ...prev].slice(0, 200));

              setFamilyCounts(prev => ({
                ...prev,
                [category]: (prev[category] ?? 0) + 1,
              }));

              setLogs(prev => [{
                id,
                time: formatTime(),
                message: `${category} (${severity}) blocked: ${data.payload ?? data.action} from ${data.source}${data.pid ? ` · origin PID ${data.pid}/${data.comm}` : ''}`,
                level: 'critical' as LogLevel,
                role: fromRole,
                category,
                severity,
                pattern: data.payload,
              }, ...prev].slice(0, 200));

              // Splash only for genuine threats — Recon / low-severity probes
              // are routine noise and would feel like panic at peak phase.
              if (severity === 'critical' || severity === 'high') {
                setSplash({ id, source: data.source, category, severity, pattern: data.payload, action: data.action || 'XDP_DROP' });
                if (splashTimeoutRef.current) clearTimeout(splashTimeoutRef.current);
                splashTimeoutRef.current = setTimeout(() => setSplash(null), 1700);
              }

              if (cardTimeoutRef.current) clearTimeout(cardTimeoutRef.current);
              cardTimeoutRef.current = setTimeout(() => {
                setThreatState(prev => ({ ...prev, showCard: false }));
              }, 4500);

              // Edge fades after 2.5 s so isolated attacks don't leave a red
              // line hanging; bursts refresh and stay lit.
              if (edgeTimeoutRef.current) clearTimeout(edgeTimeoutRef.current);
              edgeTimeoutRef.current = setTimeout(() => {
                setThreatState(prev => ({ ...prev, edge: null }));
              }, 2500);
            } else if (data.type === 'SCENARIO') {
              setScenario({
                phase: data.phase ?? 0,
                total: data.total ?? 6,
                label: data.label ?? '',
              });
            } else if (data.type === 'UNBLOCK') {
              const role = roleForIp(data.source);
              setThreatState(prev => ({
                ...prev,
                nodes: {
                  ...prev.nodes,
                  [role]: { active: false, blocked: false },
                },
                edge: prev.edge && prev.edge.from === role ? null : prev.edge,
                showCard: false,
              }));
            }
          } catch (err) {
            console.error('Failed to parse WS data', err);
          }
        };

        ws.onclose = () => {
          setWsConnected(false);
          console.warn(`WebSocket closed. Reconnecting in ${reconnectDelayRef.current}ms…`);
          scheduleReconnect();
        };

        wsRef.current = ws;
      } catch (e) {
        console.error('WS connection error', e);
        setWsConnected(false);
        scheduleReconnect();
      }
    };

    connectWS();

    return () => {
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      if (wsRef.current) wsRef.current.close();
      if (cardTimeoutRef.current) clearTimeout(cardTimeoutRef.current);
      if (splashTimeoutRef.current) clearTimeout(splashTimeoutRef.current);
      if (edgeTimeoutRef.current) clearTimeout(edgeTimeoutRef.current);
      activePulseRef.current.forEach(t => clearTimeout(t));
      activePulseRef.current.clear();
    };
  }, []);

  return {
    logs,
    metrics,
    threatState,
    recentAttacks,
    familyCounts,
    threatLevel,
    splash,
    lastBlockTick,
    lastBenignTick,
    scenario,
    benignRate,
    sendDemoCommand,
    wsConnected,
    isStale,
  };
}
