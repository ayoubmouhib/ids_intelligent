import { Filter, SlidersHorizontal } from "lucide-react";

function Filters({
  decision,
  setDecision,
  timeRange,
  setTimeRange,
  sourceIps = [],
  selectedSourceIp = "",
  setSelectedSourceIp = () => {},
}) {
  return (
    <div className="panel filter-panel" style={{ marginBottom: "1.5rem" }}>
      <div className="filter-header" style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}>
        <SlidersHorizontal size={18} className="text-muted" />
        <h3 style={{ fontSize: "0.95rem", fontWeight: "600", margin: 0 }}>Filter Network Traffic</h3>
      </div>

      <div className="filter-grid" style={{ display: "flex", flexWrap: "wrap", gap: "1rem" }}>
        {/* Decision Filter */}
        <div className="filter-group">
          <label htmlFor="decision-select" style={{ display: "block", fontSize: "0.8rem", color: "#64748b", marginBottom: "0.25rem" }}>
            DECISION
          </label>
          <select
            id="decision-select"
            value={decision}
            onChange={(e) => setDecision(e.target.value)}
            className="filter-select"
          >
            <option value="">All Decisions</option>
            <option value="NORMAL">NORMAL</option>
            <option value="SUSPICIOUS">SUSPICIOUS</option>
            <option value="ATTACK">ATTACK</option>
          </select>
        </div>

        {/* Time Range Filter */}
        <div className="filter-group">
          <label htmlFor="time-range-select" style={{ display: "block", fontSize: "0.8rem", color: "#64748b", marginBottom: "0.25rem" }}>
            TIME RANGE
          </label>
          <select
            id="time-range-select"
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="filter-select"
          >
            <option value="all">All Time</option>
            <option value="1h">Last 1 Hour</option>
            <option value="6h">Last 6 Hours</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
          </select>
        </div>

        {/* Dynamic Source IP Filter */}
        <div className="filter-group">
          <label htmlFor="source-ip-select" style={{ display: "block", fontSize: "0.8rem", color: "#64748b", marginBottom: "0.25rem" }}>
            SOURCE IP
          </label>
          <select
            id="source-ip-select"
            value={selectedSourceIp}
            onChange={(e) => setSelectedSourceIp(e.target.value)}
            className="filter-select"
          >
            <option value="">All Source IPs ({sourceIps.length})</option>
            {sourceIps.map((ip) => (
              <option key={ip} value={ip}>
                {ip}
              </option>
            ))}
          </select>
        </div>
      </div>
    </div>
  );
}

export default Filters;
