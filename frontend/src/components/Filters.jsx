function Filters({
  decision,
  setDecision,
  timeRange,
  setTimeRange,
}) {
  return (
    <div className="filters">
      <div className="filter-group">
        <label>Decision</label>

        <select
          value={decision}
          onChange={(event) =>
            setDecision(event.target.value)
          }
        >
          <option value="">All</option>
          <option value="ATTACK">Attack</option>
          <option value="SUSPICIOUS">
            Suspicious
          </option>
          <option value="NORMAL">Normal</option>
        </select>
      </div>

      <div className="filter-group">
        <label>Time Range</label>

        <select
          value={timeRange}
          onChange={(event) =>
            setTimeRange(event.target.value)
          }
        >
          <option value="all">All time</option>
          <option value="24h">Last 24 hours</option>
          <option value="7d">Last 7 days</option>
          <option value="30d">Last 30 days</option>
        </select>
      </div>

      <div className="filter-disabled">
        Attack Type
        <span>Backend data required</span>
      </div>

      <div className="filter-disabled">
        Source IP
        <span>Backend data required</span>
      </div>
    </div>
  );
}

export default Filters;
