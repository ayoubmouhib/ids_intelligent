import {
  Activity,
  ArrowDown,
  ArrowUp,
  Clock,
  Globe,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";

function ZeekEvents({ events = [] }) {
  const formatBytes = (bytes) => {
    if (bytes === null || bytes === undefined) {
      return "—";
    }

    if (bytes < 1024) {
      return `${bytes.toFixed(0)} B`;
    }

    if (bytes < 1024 * 1024) {
      return `${(bytes / 1024).toFixed(1)} KB`;
    }

    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const getDecisionClass = (decision) => {
    switch (decision) {
      case "ATTACK":
        return "zeek-decision attack";

      case "SUSPICIOUS":
        return "zeek-decision suspicious";

      case "NORMAL":
      default:
        return "zeek-decision normal";
    }
  };

  const getDecisionIcon = (decision) => {
    switch (decision) {
      case "ATTACK":
        return <ShieldAlert size={18} />;

      case "SUSPICIOUS":
        return <Activity size={18} />;

      case "NORMAL":
      default:
        return <ShieldCheck size={18} />;
    }
  };

  return (
    <div className="panel zeek-events-panel">
      <div className="panel-header">
        <div>
          <h2>Zeek Network Events</h2>
          <p>Live network connections analyzed by the IDS</p>
        </div>

        <div className="live-indicator">
          <span></span>
          LIVE
        </div>
      </div>

      <div className="zeek-event-list">
        {events.length === 0 ? (
          <div className="empty-state">
            No Zeek network events detected.
          </div>
        ) : (
          events.map((event) => (
            <div
              className="zeek-event-item"
              key={event.id}
            >
              <div
                className={getDecisionClass(
                  event.decision
                )}
              >
                {getDecisionIcon(event.decision)}

                <span>
                  {event.decision}
                </span>
              </div>

              <div className="zeek-event-main">

                <div className="zeek-flow">

                  <div className="zeek-endpoint">
                    <strong>
                      {event.source_ip}
                    </strong>

                    <span>
                      :{event.source_port ?? "—"}
                    </span>
                  </div>

                  <div className="zeek-arrow">
                    <ArrowUp size={14} />
                  </div>

                  <div className="zeek-endpoint">
                    <strong>
                      {event.destination_ip}
                    </strong>

                    <span>
                      :{event.destination_port ?? "—"}
                    </span>
                  </div>

                </div>

                <div className="zeek-meta">

                  <span>
                    <Globe size={13} />

                    {event.protocol?.toUpperCase() || "—"}
                  </span>

                  <span>
                    Service:{" "}
                    {event.service || "unknown"}
                  </span>

                  <span>
                    State:{" "}
                    {event.connection_state || "—"}
                  </span>

                  <span>
                    Duration:{" "}
                    {event.duration !== null &&
                    event.duration !== undefined
                      ? `${event.duration.toFixed(2)}s`
                      : "—"}
                  </span>

                </div>

                <div className="zeek-traffic">

                  <span>
                    <ArrowUp size={12} />

                    {formatBytes(
                      event.source_bytes
                    )}
                  </span>

                  <span>
                    <ArrowDown size={12} />

                    {formatBytes(
                      event.destination_bytes
                    )}
                  </span>

                  <span>
                    RF:{" "}
                    {(event.rf_probability * 100).toFixed(1)}
                    %
                  </span>

                  <span>
                    IF:{" "}
                    {event.if_score.toFixed(3)}
                  </span>

                </div>

              </div>

              <div className="zeek-event-time">
                <Clock size={13} />

                {new Date(
                  event.created_at
                ).toLocaleString()}
              </div>

            </div>
          ))
        )}
      </div>
    </div>
  );
}

export default ZeekEvents;
