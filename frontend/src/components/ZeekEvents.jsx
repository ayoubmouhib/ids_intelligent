import {
  Activity,
  ArrowDown,
  ArrowRight,
  ArrowUp,
  Clock,
  Globe,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";

function ZeekEvents({ events = [] }) {
  const formatBytes = (bytes) => {
    if (bytes === null || bytes === undefined || Number.isNaN(Number(bytes))) {
      return "—";
    }

    const value = Number(bytes);

    if (value < 1024) {
      return `${value.toFixed(0)} B`;
    }

    if (value < 1024 * 1024) {
      return `${(value / 1024).toFixed(1)} KB`;
    }

    if (value < 1024 * 1024 * 1024) {
      return `${(value / (1024 * 1024)).toFixed(1)} MB`;
    }

    return `${(value / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  };

  const formatNumber = (value, decimals = 0) => {
    if (
      value === null ||
      value === undefined ||
      Number.isNaN(Number(value))
    ) {
      return "—";
    }

    return Number(value).toFixed(decimals);
  };

  const formatProbability = (value) => {
    if (
      value === null ||
      value === undefined ||
      Number.isNaN(Number(value))
    ) {
      return "—";
    }

    return `${(Number(value) * 100).toFixed(1)}%`;
  };

  const formatTimestamp = (timestamp) => {
    if (!timestamp) {
      return "—";
    }

    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) {
      return "—";
    }

    return date.toLocaleString([], {
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  const getDecisionClass = (decision) => {
    switch (decision?.toUpperCase()) {
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
    switch (decision?.toUpperCase()) {
      case "ATTACK":
        return <ShieldAlert size={16} />;

      case "SUSPICIOUS":
        return <Activity size={16} />;

      case "NORMAL":
      default:
        return <ShieldCheck size={16} />;
    }
  };

  const getDecisionLabel = (decision) => {
    if (!decision) {
      return "UNKNOWN";
    }

    return decision.toUpperCase();
  };

  return (
    <div className="panel zeek-events-panel">
      <div className="panel-header">
        <div>
          <h2>Zeek Network Events</h2>

          <p>
            Network connections analyzed by the IDS
          </p>
        </div>

        <div className="zeek-live-status">
          <span className="zeek-live-dot"></span>
          LIVE MONITORING
        </div>
      </div>

      <div className="zeek-event-summary">
        <span>
          {events.length} event{events.length !== 1 ? "s" : ""}
        </span>

        <span>
          Zeek → RF + IF → Decision
        </span>
      </div>

      <div className="zeek-event-list">
        {events.length === 0 ? (
          <div className="empty-state">
            <ShieldCheck size={24} />
            <span>No Zeek network events detected.</span>
          </div>
        ) : (
          events.map((event) => (
            <article
              className={`zeek-event-item ${(
                event.decision || "NORMAL"
              ).toLowerCase()}`}
              key={event.id}
            >
              <div className="zeek-event-severity">
                <div className={getDecisionClass(event.decision)}>
                  {getDecisionIcon(event.decision)}

                  <span>
                    {getDecisionLabel(event.decision)}
                  </span>
                </div>
              </div>

              <div className="zeek-event-main">

                <div className="zeek-flow">
                  <div className="zeek-endpoint">
                    <span className="zeek-endpoint-label">
                      SOURCE
                    </span>

                    <strong>
                      {event.source_ip || "—"}
                    </strong>

                    <span className="zeek-port">
                      :{event.source_port ?? "—"}
                    </span>
                  </div>

                  <div className="zeek-flow-arrow">
                    <ArrowRight size={18} />
                  </div>

                  <div className="zeek-endpoint">
                    <span className="zeek-endpoint-label">
                      DESTINATION
                    </span>

                    <strong>
                      {event.destination_ip || "—"}
                    </strong>

                    <span className="zeek-port">
                      :{event.destination_port ?? "—"}
                    </span>
                  </div>
                </div>

                <div className="zeek-meta">

                  <span className="zeek-meta-item">
                    <Globe size={13} />
                    <strong>
                      {event.protocol?.toUpperCase() || "UNKNOWN"}
                    </strong>
                  </span>

                  <span className="zeek-meta-item">
                    Service:
                    <strong>
                      {event.service || "unknown"}
                    </strong>
                  </span>

                  <span className="zeek-meta-item">
                    State:
                    <strong>
                      {event.connection_state || "—"}
                    </strong>
                  </span>

                  <span className="zeek-meta-item">
                    <Clock size={13} />
                    Duration:
                    <strong>
                      {event.duration !== null &&
                      event.duration !== undefined
                        ? `${formatNumber(event.duration, 2)}s`
                        : "—"}
                    </strong>
                  </span>

                </div>

                <div className="zeek-details">

                  <div className="zeek-detail-group">
                    <span className="zeek-detail-label">
                      TRAFFIC
                    </span>

                    <div className="zeek-traffic-values">
                      <span className="zeek-traffic-up">
                        <ArrowUp size={12} />

                        {formatBytes(event.source_bytes)}

                        <small>
                          {formatNumber(
                            event.source_packets
                          )} pkts
                        </small>
                      </span>

                      <span className="zeek-traffic-down">
                        <ArrowDown size={12} />

                        {formatBytes(event.destination_bytes)}

                        <small>
                          {formatNumber(
                            event.destination_packets
                          )} pkts
                        </small>
                      </span>
                    </div>
                  </div>

                  <div className="zeek-detail-group">
                    <span className="zeek-detail-label">
                      ML ANALYSIS
                    </span>

                    <div className="zeek-ml-values">
                      <span>
                        RF:
                        <strong>
                          {formatProbability(
                            event.rf_probability
                          )}
                        </strong>
                      </span>

                      <span>
                        IF:
                        <strong>
                          {formatNumber(
                            event.if_score,
                            3
                          )}
                        </strong>
                      </span>
                    </div>
                  </div>

                </div>
              </div>

              <div className="zeek-event-time">
                <Clock size={13} />

                <span>
                  {formatTimestamp(event.created_at)}
                </span>
              </div>
            </article>
          ))
        )}
      </div>
    </div>
  );
}

export default ZeekEvents;