import { Activity, ArrowRight, Clock, ShieldAlert, ShieldCheck } from "lucide-react";

function AlertFeed({ alerts = [] }) {
  const formatTimestamp = (ts) => {
    if (!ts) return "—";
    const date = new Date(ts);
    return isNaN(date.getTime())
      ? "—"
      : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  };

  return (
    <div className="panel alert-panel">
      <div className="panel-header">
        <div>
          <h2>Alert Feed</h2>
          <p>Active threats and security alerts detected</p>
        </div>

        <div className="live-indicator">
          <span></span>
          LIVE
        </div>
      </div>

      <div className="alert-list">
        {alerts.length === 0 ? (
          <div className="empty-state">
            <ShieldCheck size={24} />
            <span>No threat alerts detected. System secure.</span>
          </div>
        ) : (
          alerts.map((item) => {
            const decision = (item.decision || "SUSPICIOUS").toUpperCase();
            const isAttack = decision === "ATTACK";

            return (
              <div key={item.id} className={`alert-item ${isAttack ? "attack" : "suspicious"}`}>
                <div className={`alert-icon ${isAttack ? "attack" : "suspicious"}`}>
                  {isAttack ? <ShieldAlert size={20} /> : <Activity size={20} />}
                </div>

                <div className="alert-content">
                  <div className="alert-title-row">
                    <strong className="alert-decision">{decision}</strong>
                    {item.protocol && <span className="alert-proto">{item.protocol.toUpperCase()}</span>}
                  </div>

                  <div className="alert-flow">
                    <span>{item.source_ip || item.src_ip || item.source || "10.0.2.15"}</span>
                    <ArrowRight size={12} />
                    <span>{item.destination_ip || item.dst_ip || item.destination || "192.150.187.43"}</span>
                  </div>

                  <div className="alert-time">
                    <Clock size={12} />
                    <span>{formatTimestamp(item.created_at)}</span>
                  </div>
                </div>

                <div className="alert-scores">
                  <div className="score-badge rf">
                    RF: {item.rf_probability !== undefined ? `${(item.rf_probability * 100).toFixed(1)}%` : "N/A"}
                  </div>
                  <div className="score-badge if">
                    IF: {item.if_score !== undefined ? Number(item.if_score).toFixed(3) : "N/A"}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

export default AlertFeed;
