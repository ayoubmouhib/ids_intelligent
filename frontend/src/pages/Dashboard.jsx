import { useEffect, useState } from "react";

import {
  Activity,
  RefreshCw,
  Shield,
} from "lucide-react";

import {
  getAlerts,
  getStatistics,
} from "../services/api";

import StatsCards from "../components/StatsCards";
import AlertFeed from "../components/AlertFeed";
import TrafficChart from "../components/TrafficChart";
import AttackMap from "../components/AttackMap";
import Filters from "../components/Filters";

function Dashboard() {
  const [statistics, setStatistics] = useState({
    total_flows: 0,
    attacks: 0,
    normal: 0,
    suspicious: 0,
    attack_rate: 0,
  });

  const [alerts, setAlerts] = useState([]);

  const [decision, setDecision] = useState("");
  const [timeRange, setTimeRange] = useState("all");

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");


  const getFilteredAlerts = () => {
  if (timeRange === "all") {
    return alerts;
  }

  const now = new Date();

  const ranges = {
    "1h": 60 * 60 * 1000,
    "6h": 6 * 60 * 60 * 1000,
    "24h": 24 * 60 * 60 * 1000,
    "7d": 7 * 24 * 60 * 60 * 1000,
  };

  const range = ranges[timeRange];

  if (!range) {
    return alerts;
  }

  return alerts.filter((alert) => {
    const alertTime = new Date(
      alert.created_at
    ).getTime();

    return now.getTime() - alertTime <= range;
  });
};

  const loadDashboard = async () => {
    try {
      setLoading(true);
      setError("");

      const [statsData, alertsData] =
        await Promise.all([
          getStatistics(),
          getAlerts({
            limit: 50,
            ...(decision
              ? { decision }
              : {}),
          }),
        ]);

      setStatistics(statsData);
      setAlerts(alertsData.alerts || []);
    } catch (err) {
      console.error(err);

      setError(
        "Unable to connect to the IDS API."
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboard();
  }, [decision]);

  useEffect(() => {
    const interval = setInterval(() => {
      loadDashboard();
    }, 10000);

    return () => clearInterval(interval);
  }, [decision]);

  const filteredAlerts = getFilteredAlerts();

  return (
    <div className="dashboard">
      <header className="topbar">
        <div className="brand">
          <div className="brand-icon">
            <Shield size={22} />
          </div>

          <div>
            <h1>IDS Security Center</h1>
            <span>
              Intelligent Intrusion Detection System
            </span>
          </div>
        </div>

        <div className="system-status">
          <span className="status-dot"></span>
          System Online
        </div>
      </header>

      <main className="dashboard-content">

        <div className="dashboard-heading">
          <div>
            <h2>Security Overview</h2>

            <p>
              Real-time network intrusion monitoring
            </p>
          </div>

          <button
            className="refresh-button"
            onClick={loadDashboard}
            disabled={loading}
          >
            <RefreshCw
              size={16}
              className={loading ? "spin" : ""}
            />

            Refresh
          </button>
        </div>

        {error && (
          <div className="error-banner">
            {error}
          </div>
        )}

        <StatsCards
          statistics={statistics}
        />

        <Filters
          decision={decision}
          setDecision={setDecision}
          timeRange={timeRange}
          setTimeRange={setTimeRange}
        />

        <section className="dashboard-grid">

          <TrafficChart
  alerts={filteredAlerts}
/>

          <AttackMap
  alerts={filteredAlerts}
/>

        </section>

        <section className="dashboard-grid bottom">

          <AlertFeed
  alerts={filteredAlerts}
/>

          <div className="panel system-panel">
            <div className="panel-header">
              <div>
                <h2>Detection Engine</h2>
                <p>Current IDS architecture</p>
              </div>

              <Activity size={20} />
            </div>

            <div className="engine-list">

              <div className="engine-item">
                <div>
                  <strong>
                    Random Forest
                  </strong>

                  <span>
                    Supervised classifier
                  </span>
                </div>

                <span className="engine-status">
                  ACTIVE
                </span>
              </div>

              <div className="engine-item">
                <div>
                  <strong>
                    Isolation Forest
                  </strong>

                  <span>
                    Anomaly detector
                  </span>
                </div>

                <span className="engine-status">
                  ACTIVE
                </span>
              </div>

              <div className="engine-item">
                <div>
                  <strong>
                    Hybrid Decision
                  </strong>

                  <span>
                    RF + IF decision policy
                  </span>
                </div>

                <span className="engine-status">
                  ACTIVE
                </span>
              </div>

            </div>
          </div>

        </section>

      </main>
    </div>
  );

  
}

export default Dashboard;