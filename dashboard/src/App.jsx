import { useState, useEffect, useCallback, useRef } from "react";
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Legend
} from "recharts";

// ── Config ─────────────────────────────────────────────────────────────────
const API = "http://localhost:5000/api";
const POLL_MS = 2000;

// ── Severity colours ────────────────────────────────────────────────────────
const SEV = {
  CRITICAL: { bg: "#ff2d55", text: "#fff",      label: "CRITICAL" },
  HIGH:     { bg: "#ff9500", text: "#000",      label: "HIGH"     },
  MEDIUM:   { bg: "#ffd60a", text: "#000",      label: "MEDIUM"   },
  LOW:      { bg: "#30d158", text: "#000",      label: "LOW"      },
};

const PROTO_COLOR = {
  TCP: "#0a84ff", UDP: "#32d74b", ICMP: "#ff9f0a",
  DNS: "#bf5af2", ARP: "#64d2ff", OTHER: "#636366",
};

// ── Utility ─────────────────────────────────────────────────────────────────
const fmt = (n) => (n ?? 0).toLocaleString();
const ago = (iso) => {
  if (!iso) return "—";
  const d = Math.floor((Date.now() - new Date(iso + "Z").getTime()) / 1000);
  if (d < 60)  return `${d}s ago`;
  if (d < 3600) return `${Math.floor(d/60)}m ago`;
  return `${Math.floor(d/3600)}h ago`;
};

// ── Sub-components ───────────────────────────────────────────────────────────

function StatCard({ label, value, sub, accent }) {
  return (
    <div style={{
      background: "#1c1c1e", border: `1px solid ${accent}33`,
      borderRadius: 12, padding: "18px 22px", position: "relative", overflow: "hidden"
    }}>
      <div style={{
        position: "absolute", top: 0, left: 0, right: 0, height: 3,
        background: accent
      }} />
      <div style={{ color: "#8e8e93", fontSize: 11, letterSpacing: 1, textTransform: "uppercase", marginBottom: 8 }}>
        {label}
      </div>
      <div style={{ color: "#fff", fontSize: 32, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", lineHeight: 1 }}>
        {value}
      </div>
      {sub && <div style={{ color: "#636366", fontSize: 12, marginTop: 6 }}>{sub}</div>}
    </div>
  );
}

function SeverityBadge({ sev }) {
  const s = SEV[sev] || SEV.LOW;
  return (
    <span style={{
      background: s.bg, color: s.text,
      fontSize: 10, fontWeight: 700, padding: "2px 8px",
      borderRadius: 4, letterSpacing: 1,
      fontFamily: "'JetBrains Mono', monospace"
    }}>
      {s.label}
    </span>
  );
}

function AlertRow({ a, isNew }) {
  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "130px 90px 1fr 120px 80px",
      gap: 12, padding: "10px 16px",
      background: isNew ? "#1c1c1e" : "transparent",
      borderBottom: "1px solid #2c2c2e",
      alignItems: "center",
      transition: "background 0.4s",
      animation: isNew ? "flashRow 0.6s ease" : "none",
    }}>
      <span style={{ color: "#636366", fontSize: 12, fontFamily: "'JetBrains Mono', monospace" }}>
        {a.timestamp ? new Date(a.timestamp + "Z").toLocaleTimeString() : "—"}
      </span>
      <SeverityBadge sev={a.severity} />
      <span style={{ color: "#fff", fontSize: 13 }}>{a.alert_type?.replace(/_/g," ")}</span>
      <span style={{ color: "#8e8e93", fontSize: 12, fontFamily: "'JetBrains Mono', monospace" }}>
        {a.src_ip || "—"}
      </span>
      <span style={{ color: "#636366", fontSize: 11 }}>{a.protocol || "—"}</span>
    </div>
  );
}

function PacketRow({ p }) {
  const col = PROTO_COLOR[p.protocol] || PROTO_COLOR.OTHER;
  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "110px 70px 140px 140px 70px 60px",
      gap: 8, padding: "7px 16px",
      borderBottom: "1px solid #1c1c1e",
      alignItems: "center",
      fontSize: 12,
    }}>
      <span style={{ color: "#636366", fontFamily: "'JetBrains Mono', monospace" }}>
        {p.timestamp ? new Date(p.timestamp + "Z").toLocaleTimeString() : "—"}
      </span>
      <span style={{
        color: col, fontWeight: 700, fontSize: 11,
        fontFamily: "'JetBrains Mono', monospace"
      }}>{p.protocol}</span>
      <span style={{ color: "#ebebf5cc", fontFamily: "'JetBrains Mono', monospace" }}>{p.src_ip || "—"}</span>
      <span style={{ color: "#ebebf5cc", fontFamily: "'JetBrains Mono', monospace" }}>{p.dst_ip || "—"}</span>
      <span style={{ color: "#636366" }}>{p.dst_port || "—"}</span>
      <span style={{ color: "#636366" }}>{p.size}B</span>
    </div>
  );
}

// ── Main Dashboard ───────────────────────────────────────────────────────────

export default function App() {
  const [alerts, setAlerts]         = useState([]);
  const [packets, setPackets]       = useState([]);
  const [stats, setStats]           = useState(null);
  const [liveStats, setLiveStats]   = useState({ total: 0, TCP: 0, UDP: 0, ICMP: 0, DNS: 0 });
  const [topIPs, setTopIPs]         = useState([]);
  const [alertBreakdown, setBreakdown] = useState([]);
  const [totalAlerts, setTotalAlerts] = useState(0);
  const [trafficHistory, setHistory]  = useState([]);
  const [newAlertIds, setNewAlertIds] = useState(new Set());
  const [tab, setTab]               = useState("dashboard");
  const [connected, setConnected]   = useState(false);
  const prevAlertCount = useRef(0);

  const fetchAll = useCallback(async () => {
    try {
      const [aRes, pRes, sRes] = await Promise.all([
        fetch(`${API}/alerts?limit=50`),
        fetch(`${API}/packets?limit=80`),
        fetch(`${API}/stats`),
      ]);
      if (!aRes.ok) throw new Error("Not connected");

      const [aData, pData, sData] = await Promise.all([
        aRes.json(), pRes.json(), sRes.json()
      ]);

      setAlerts(aData);
      setPackets(pData);
      setTopIPs(sData.top_ips || []);
      setBreakdown(sData.alert_breakdown || []);
      setLiveStats(sData.live_counters || {});
      setTotalAlerts(sData.total_alerts || 0);
      setConnected(true);

      // Mark new alerts
      if (aData.length > prevAlertCount.current) {
        const newIds = new Set(aData.slice(0, aData.length - prevAlertCount.current).map(a => a.id));
        setNewAlertIds(newIds);
        setTimeout(() => setNewAlertIds(new Set()), 3000);
      }
      prevAlertCount.current = aData.length;

      // Build traffic sparkline (last 20 data points)
      setHistory(h => {
        const next = [...h, {
          t:    new Date().toLocaleTimeString("en", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" }),
          TCP:  sData.live_counters?.TCP  || 0,
          UDP:  sData.live_counters?.UDP  || 0,
          ICMP: sData.live_counters?.ICMP || 0,
        }].slice(-20);
        return next;
      });

    } catch {
      setConnected(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const id = setInterval(fetchAll, POLL_MS);
    return () => clearInterval(id);
  }, [fetchAll]);

  const clearData = async () => {
    await fetch(`${API}/clear`, { method: "POST" });
    setAlerts([]); setPackets([]); setHistory([]);
    prevAlertCount.current = 0;
  };

  // ── Proto pie data
  const protoPie = ["TCP","UDP","ICMP","DNS","OTHER"].map(k => ({
    name: k, value: liveStats[k] || 0, color: PROTO_COLOR[k]
  })).filter(d => d.value > 0);

  // ── Severity breakdown bar
  const sevBar = ["CRITICAL","HIGH","MEDIUM","LOW"].map(s => ({
    name: s,
    count: alertBreakdown.filter(a => a.severity === s).reduce((n, a) => n + a.count, 0),
    fill: SEV[s]?.bg
  }));

  const critCount = alertBreakdown.filter(a => a.severity === "CRITICAL").reduce((sum, a) => sum + a.count, 0);
  const highCount = alertBreakdown.filter(a => a.severity === "HIGH").reduce((sum, a) => sum + a.count, 0);

  return (
    <div style={{
      background: "#000", minHeight: "100vh", color: "#fff",
      fontFamily: "-apple-system, 'SF Pro Display', 'Helvetica Neue', sans-serif",
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #1c1c1e; }
        ::-webkit-scrollbar-thumb { background: #3a3a3c; border-radius: 3px; }
        @keyframes flashRow {
          0%   { background: #ff2d5530; }
          100% { background: #1c1c1e; }
        }
        @keyframes pulse {
          0%,100% { opacity: 1; }
          50%      { opacity: 0.4; }
        }
      `}</style>

      {/* ── Header */}
      <div style={{
        borderBottom: "1px solid #1c1c1e",
        padding: "0 32px",
        display: "flex", alignItems: "center", justifyContent: "space-between",
        height: 56,
        background: "#0d0d0f",
        position: "sticky", top: 0, zIndex: 100,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          {/* Shield icon */}
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
            <path d="M12 2L3 6v6c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V6L12 2z"
              fill="#0a84ff" opacity="0.2" stroke="#0a84ff" strokeWidth="1.5"/>
            <path d="M9 12l2 2 4-4" stroke="#0a84ff" strokeWidth="1.5" strokeLinecap="round"/>
          </svg>
          <span style={{ fontSize: 18, fontWeight: 700, letterSpacing: -0.5 }}>
            NetWatch IDS
          </span>
          <span style={{
            background: "#1c1c1e", border: "1px solid #2c2c2e",
            borderRadius: 6, padding: "2px 10px", fontSize: 11, color: "#8e8e93"
          }}>v1.0</span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
          {/* Status indicator */}
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{
              width: 8, height: 8, borderRadius: "50%",
              background: connected ? "#30d158" : "#ff453a",
              animation: connected ? "pulse 2s infinite" : "none",
            }} />
            <span style={{ fontSize: 12, color: connected ? "#30d158" : "#ff453a" }}>
              {connected ? "Connected" : "Offline — start server"}
            </span>
          </div>

          {critCount > 0 && (
            <div style={{
              background: "#ff2d55", borderRadius: 6,
              padding: "3px 10px", fontSize: 12, fontWeight: 700
            }}>
              ⚠ {critCount} CRITICAL
            </div>
          )}

          <button onClick={clearData} style={{
            background: "#1c1c1e", border: "1px solid #3a3a3c",
            color: "#ff453a", borderRadius: 8, padding: "6px 14px",
            fontSize: 12, cursor: "pointer"
          }}>Clear</button>
        </div>
      </div>

      {/* ── Nav tabs */}
      <div style={{
        borderBottom: "1px solid #1c1c1e", padding: "0 32px",
        display: "flex", gap: 0,
      }}>
        {[["dashboard","Dashboard"],["alerts","Alerts"],["packets","Packets"]].map(([id, label]) => (
          <button key={id} onClick={() => setTab(id)} style={{
            background: "none", border: "none", color: tab===id ? "#0a84ff" : "#636366",
            borderBottom: tab===id ? "2px solid #0a84ff" : "2px solid transparent",
            padding: "12px 20px", cursor: "pointer", fontSize: 14, fontWeight: tab===id ? 600 : 400,
            marginBottom: -1,
          }}>{label}</button>
        ))}
      </div>

      <div style={{ padding: "24px 32px", maxWidth: 1400, margin: "0 auto" }}>

        {/* ════ DASHBOARD TAB ══════════════════════════════════════════════ */}
        {tab === "dashboard" && (<>

          {/* Stat cards */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 16, marginBottom: 24 }}>
            <StatCard label="Total Packets" value={fmt(liveStats.total)} sub="captured" accent="#0a84ff" />
            <StatCard label="Alerts" value={fmt(totalAlerts)} sub={`${highCount} high severity`} accent="#ff9500" />
            <StatCard label="Unique IPs" value={fmt(topIPs.length)} sub="seen so far" accent="#32d74b" />
            <StatCard label="Threat Types" value={fmt([...new Set(alertBreakdown.map(a=>a.alert_type))].length)} sub="distinct" accent="#ff2d55" />
          </div>

          {/* Two-column charts */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>

            {/* Traffic area chart */}
            <div style={{ background: "#1c1c1e", borderRadius: 12, padding: "20px 16px" }}>
              <div style={{ color: "#8e8e93", fontSize: 11, letterSpacing: 1, textTransform: "uppercase", marginBottom: 16 }}>
                Live Traffic
              </div>
              <ResponsiveContainer width="100%" height={180}>
                <AreaChart data={trafficHistory}>
                  <defs>
                    {["TCP","UDP","ICMP"].map(k => (
                      <linearGradient key={k} id={`g${k}`} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor={PROTO_COLOR[k]} stopOpacity={0.3}/>
                        <stop offset="95%" stopColor={PROTO_COLOR[k]} stopOpacity={0}/>
                      </linearGradient>
                    ))}
                  </defs>
                  <XAxis dataKey="t" tick={{ fill:"#636366", fontSize:10 }} />
                  <YAxis tick={{ fill:"#636366", fontSize:10 }} />
                  <Tooltip contentStyle={{ background:"#2c2c2e", border:"none", borderRadius:8, color:"#fff" }} />
                  {["TCP","UDP","ICMP"].map(k => (
                    <Area key={k} type="monotone" dataKey={k}
                      stroke={PROTO_COLOR[k]} fill={`url(#g${k})`} strokeWidth={1.5} dot={false} />
                  ))}
                </AreaChart>
              </ResponsiveContainer>
            </div>

            {/* Protocol pie */}
            <div style={{ background: "#1c1c1e", borderRadius: 12, padding: "20px 16px" }}>
              <div style={{ color: "#8e8e93", fontSize: 11, letterSpacing: 1, textTransform: "uppercase", marginBottom: 16 }}>
                Protocol Distribution
              </div>
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie data={protoPie} dataKey="value" nameKey="name"
                    cx="50%" cy="50%" innerRadius={50} outerRadius={80}
                    paddingAngle={3}>
                    {protoPie.map((e, i) => <Cell key={i} fill={e.color} />)}
                  </Pie>
                  <Tooltip contentStyle={{ background:"#2c2c2e", border:"none", borderRadius:8, color:"#fff" }} />
                  <Legend iconType="circle" iconSize={8}
                    formatter={(v) => <span style={{ color:"#8e8e93", fontSize:12 }}>{v}</span>} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Two-column: top IPs + alert breakdown */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>

            {/* Top IPs bar */}
            <div style={{ background: "#1c1c1e", borderRadius: 12, padding: "20px 16px" }}>
              <div style={{ color: "#8e8e93", fontSize: 11, letterSpacing: 1, textTransform: "uppercase", marginBottom: 16 }}>
                Top Source IPs
              </div>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={topIPs.slice(0,8)} layout="vertical">
                  <XAxis type="number" tick={{ fill:"#636366", fontSize:10 }} />
                  <YAxis dataKey="src_ip" type="category"
                    tick={{ fill:"#8e8e93", fontSize:11, fontFamily:"'JetBrains Mono',monospace" }}
                    width={120} />
                  <Tooltip contentStyle={{ background:"#2c2c2e", border:"none", borderRadius:8, color:"#fff" }} />
                  <Bar dataKey="count" fill="#0a84ff" radius={[0,4,4,0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>

            {/* Alert severity bar */}
            <div style={{ background: "#1c1c1e", borderRadius: 12, padding: "20px 16px" }}>
              <div style={{ color: "#8e8e93", fontSize: 11, letterSpacing: 1, textTransform: "uppercase", marginBottom: 16 }}>
                Alert Severity
              </div>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={sevBar}>
                  <XAxis dataKey="name" tick={{ fill:"#636366", fontSize:11 }} />
                  <YAxis tick={{ fill:"#636366", fontSize:10 }} />
                  <Tooltip contentStyle={{ background:"#2c2c2e", border:"none", borderRadius:8, color:"#fff" }} />
                  <Bar dataKey="count" radius={[4,4,0,0]}>
                    {sevBar.map((e,i) => <Cell key={i} fill={e.fill} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Recent alerts preview */}
          <div style={{ background: "#1c1c1e", borderRadius: 12, overflow: "hidden" }}>
            <div style={{ padding: "16px 20px", borderBottom: "1px solid #2c2c2e",
              display:"flex", justifyContent:"space-between", alignItems:"center" }}>
              <span style={{ color:"#8e8e93", fontSize:11, letterSpacing:1, textTransform:"uppercase" }}>
                Recent Alerts
              </span>
              <button onClick={() => setTab("alerts")} style={{
                background:"none", border:"none", color:"#0a84ff", fontSize:13, cursor:"pointer"
              }}>View all →</button>
            </div>
            <div style={{
              display:"grid",
              gridTemplateColumns:"130px 90px 1fr 120px 80px",
              gap:12, padding:"8px 16px",
              background:"#111113",
              color:"#636366", fontSize:11, letterSpacing:1, textTransform:"uppercase"
            }}>
              {["Time","Severity","Type","Source IP","Proto"].map(h=><span key={h}>{h}</span>)}
            </div>
            {alerts.slice(0,8).map((a,i) => (
              <AlertRow key={a.id ?? i} a={a} isNew={newAlertIds.has(a.id)} />
            ))}
            {alerts.length === 0 && (
              <div style={{ padding:32, textAlign:"center", color:"#636366" }}>
                No alerts yet. Traffic is clean ✓
              </div>
            )}
          </div>
        </>)}

        {/* ════ ALERTS TAB ═════════════════════════════════════════════════ */}
        {tab === "alerts" && (
          <div style={{ background: "#1c1c1e", borderRadius: 12, overflow: "hidden" }}>
            <div style={{ padding: "16px 20px", borderBottom: "1px solid #2c2c2e",
              display:"flex", justifyContent:"space-between", alignItems:"center" }}>
              <span style={{ fontWeight:600 }}>All Alerts ({alerts.length})</span>
              <div style={{ display:"flex", gap:8 }}>
                {["CRITICAL","HIGH","MEDIUM","LOW"].map(s => (
                  <span key={s} style={{
                    background: SEV[s]?.bg+"22", color: SEV[s]?.bg,
                    border: `1px solid ${SEV[s]?.bg}44`,
                    borderRadius:6, padding:"2px 10px", fontSize:11, fontWeight:700
                  }}>
                    {s}: {alerts.filter(a=>a.severity===s).length}
                  </span>
                ))}
              </div>
            </div>
            <div style={{
              display:"grid",
              gridTemplateColumns:"130px 90px 1fr 120px 80px",
              gap:12, padding:"8px 16px",
              background:"#111113",
              color:"#636366", fontSize:11, letterSpacing:1, textTransform:"uppercase"
            }}>
              {["Time","Severity","Type","Source IP","Proto"].map(h=><span key={h}>{h}</span>)}
            </div>
            <div style={{ maxHeight: "65vh", overflowY: "auto" }}>
              {alerts.map((a,i) => (
                <div key={a.id ?? i}>
                  <AlertRow a={a} isNew={newAlertIds.has(a.id)} />
                  {a.detail && (
                    <div style={{ padding:"4px 16px 10px 16px",
                      color:"#636366", fontSize:12, fontFamily:"'JetBrains Mono',monospace" }}>
                      {a.detail}
                    </div>
                  )}
                </div>
              ))}
              {alerts.length === 0 && (
                <div style={{ padding:48, textAlign:"center", color:"#636366", fontSize:16 }}>
                  🛡 No threats detected
                </div>
              )}
            </div>
          </div>
        )}

        {/* ════ PACKETS TAB ════════════════════════════════════════════════ */}
        {tab === "packets" && (
          <div style={{ background: "#1c1c1e", borderRadius: 12, overflow: "hidden" }}>
            <div style={{ padding: "16px 20px", borderBottom: "1px solid #2c2c2e" }}>
              <span style={{ fontWeight:600 }}>Live Packet Feed ({fmt(liveStats.total)} total)</span>
            </div>
            <div style={{
              display:"grid",
              gridTemplateColumns:"110px 70px 140px 140px 70px 60px",
              gap:8, padding:"8px 16px",
              background:"#111113",
              color:"#636366", fontSize:11, letterSpacing:1, textTransform:"uppercase"
            }}>
              {["Time","Proto","Src IP","Dst IP","Port","Size"].map(h=><span key={h}>{h}</span>)}
            </div>
            <div style={{ maxHeight: "65vh", overflowY: "auto" }}>
              {packets.map((p,i) => <PacketRow key={p.id ?? i} p={p} />)}
              {packets.length === 0 && (
                <div style={{ padding:48, textAlign:"center", color:"#636366" }}>
                  No packets captured yet
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* ── Footer */}
      <div style={{
        borderTop: "1px solid #1c1c1e", padding: "14px 32px",
        display:"flex", justifyContent:"space-between", alignItems:"center",
        color:"#3a3a3c", fontSize:12
      }}>
        <span>NetWatch IDS — Network Intrusion Detection System</span>
        <span style={{ fontFamily:"'JetBrains Mono',monospace" }}>
          T:{fmt(liveStats.TCP)} U:{fmt(liveStats.UDP)} I:{fmt(liveStats.ICMP)}
        </span>
      </div>
    </div>
  );
}