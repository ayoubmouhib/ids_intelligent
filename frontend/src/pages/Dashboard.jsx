import { useEffect, useState } from "react";
import { Activity, RefreshCw, Shield } from "lucide-react";

import {
  getStatistics,
  getStatisticsTimeline,
  getZeekEvents,
} from "../services/api";

import StatsCards from "../components/StatsCards";
import AlertFeed from "../components/AlertFeed";
import TrafficChart from "../components/TrafficChart";
import AttackMap from "../components/AttackMap";
import Filters from "../components/Filters";
import ZeekEvents from "../components/ZeekEvents";

function Dashboard() {
  const [statistics, setStatistics] = useState({
    total_flows: 0,
    attacks: 0,
    normal: 0,
    suspicious: 0,
    attack_rate: 0,
  });

  const [zeekEvents, setZeekEvents] = useState([]);
  const [timelineData, setTimelineData] = useState([]);
  const [availableSourceIps, setAvailableSourceIps] = useState([]);

  const [decision, setDecision] = useState("");
  const [timeRange, setTimeRange] = useState("all");
  const [selectedSourceIp, setSelectedSourceIp] = useState("");

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  

  const loadDashboard = async () => {
  try {
    setLoading(true);
    setError("");

    let start_time = null;
    let end_time = null;

    if (timeRange !== "all") {
      const now = new Date();

      const ranges = {
        "1h": 60 * 60 * 1000,
        "6h": 6 * 60 * 60 * 1000,
        "24h": 24 * 60 * 60 * 1000,
        "7d": 7 * 24 * 60 * 60 * 1000,
      };

      const range = ranges[timeRange];

      if (range) {
        const start = new Date(now.getTime() - range);

        start_time = start.toISOString();
        end_time = now.toISOString();
      }
    }

    
      const timelineHours = {
        all: 24,
        "1h": 1,
        "6h": 6,
        "24h": 24,
        "7d": 168,
      };

  const hours = timelineHours[timeRange] || 24;

  const [zeekData, statisticsData, timelineResponse] =
  await Promise.all([
   
    getZeekEvents({
      limit: 50,
      ...(decision ? { decision } : {}),
      ...(selectedSourceIp
        ? { source_ip: selectedSourceIp }
        : {}),
      ...(start_time ? { start_time } : {}),
      ...(end_time ? { end_time } : {}),
    }),

    getStatistics({
      ...(decision ? { decision } : {}),
      ...(selectedSourceIp
        ? { source_ip: selectedSourceIp }
        : {}),
      ...(start_time ? { start_time } : {}),
      ...(end_time ? { end_time } : {}),
    }),

    getStatisticsTimeline({
      hours,
      bucket_minutes: 60,
      ...(decision ? { decision } : {}),
      ...(selectedSourceIp
        ? { source_ip: selectedSourceIp }
        : {}),
      ...(start_time ? { start_time } : {}),
      ...(end_time ? { end_time } : {}),
    }),
  ]);
   

    
    setStatistics(statisticsData);
    setZeekEvents(zeekData.events || []);
    setTimelineData(timelineResponse || []);
    setAvailableSourceIps((currentIps) => {
        const newIps = (zeekData.events || [])
          .map((event) => event.source_ip)
          .filter(Boolean);

        return [...new Set([...currentIps, ...newIps])];
      });
  } catch (err) {
    console.error(err);
    setError("Unable to connect to the IDS API.");
  } finally {
    setLoading(false);
  }
};

  useEffect(() => {
  loadDashboard();
}, [decision, timeRange, selectedSourceIp]);

  useEffect(() => {
  const interval = setInterval(() => {
    loadDashboard();
  }, 20000);

  return () => clearInterval(interval);
}, [decision, timeRange, selectedSourceIp]);

  const filteredZeekEvents = zeekEvents;

  

  
  

  const suspiciousAndAttacks = filteredZeekEvents.filter(
    (event) =>
      event.decision === "ATTACK" || event.decision === "SUSPICIOUS"
  );

  return (
    <div className="dashboard">
      <header className="topbar">
        <div className="brand">
          <div className="brand-icon">
            <Shield size={22} />
          </div>

          <div>
            <h1>IDS Security Center</h1>
            <span>Intelligent Intrusion Detection System</span>
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
            <p>Real-time network intrusion monitoring</p>
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

        {error && <div className="error-banner">{error}</div>}

        <StatsCards statistics={statistics} />

        <Filters
          decision={decision}
          setDecision={setDecision}
          timeRange={timeRange}
          setTimeRange={setTimeRange}
          sourceIps={availableSourceIps}
          selectedSourceIp={selectedSourceIp}
          setSelectedSourceIp={setSelectedSourceIp}
        />

        <section className="dashboard-grid">
          <TrafficChart timelineData={timelineData} />
          <AttackMap events={filteredZeekEvents} />
        </section>

        <section
          className="zeek-full-width-container"
          style={{
            width: "100%",
            marginBottom: "1.5rem",
          }}
        >
          <ZeekEvents events={filteredZeekEvents} />
        </section>

        <section className="dashboard-grid bottom">
          <AlertFeed
            alerts={
              suspiciousAndAttacks.length > 0
                ? suspiciousAndAttacks
                : []
            }
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
                  <strong>Random Forest</strong>
                  <span>Supervised classifier</span>
                </div>
              </div>

              <div className="engine-item">
                <div>
                  <strong>Isolation Forest</strong>
                  <span>Unsupervised anomaly detector</span>
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}

export default Dashboard;