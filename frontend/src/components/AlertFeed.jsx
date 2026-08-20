import {
  AlertTriangle,
  Clock,
  ShieldAlert,
} from "lucide-react";

function AlertFeed({ alerts }) {
  return (
    <div className="panel alert-panel">
      <div className="panel-header">
        <div>
          <h2>Alert Feed</h2>
          <p>Recent security events detected by the IDS</p>
        </div>

        <div className="live-indicator">
          <span></span>
          LIVE
        </div>
      </div>

      <div className="alert-list">
        {alerts.length === 0 ? (
          <div className="empty-state">
            No alerts detected.
          </div>
        ) : (
          alerts.map((alert) => {
            const isSuspicious =
              alert.decision === "SUSPICIOUS";

            return (
              <div className="alert-item" key={alert.id}>
                <div
                  className={`alert-icon ${
                    isSuspicious ? "suspicious" : "attack"
                  }`}
                >
                  {isSuspicious ? (
                    <ShieldAlert size={20} />
                  ) : (
                    <AlertTriangle size={20} />
                  )}
                </div>

                <div className="alert-content">
                  <div className="alert-title-row">
                    <strong>{alert.decision}</strong>

                    <span className="alert-id">
                      #{alert.id}
                    </span>
                  </div>

                  <div className="alert-details">
                    RF probability:{" "}
                    {(alert.rf_probability * 100).toFixed(1)}%
                  </div>

                  <div className="alert-time">
                    <Clock size={13} />

                    {new Date(
                      alert.created_at
                    ).toLocaleString()}
                  </div>
                </div>

                <div className="alert-score">
                  IF: {alert.if_score.toFixed(3)}
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
