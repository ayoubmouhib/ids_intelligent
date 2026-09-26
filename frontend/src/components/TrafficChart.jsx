
/*import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
} from "chart.js";

import { Doughnut } from "react-chartjs-2";

ChartJS.register(
  ArcElement,
  Tooltip,
  Legend
);

function TrafficChart({ statistics }) {
  const data = {
    labels: [
      "Attacks",
      "Normal",
      "Suspicious",
    ],

    datasets: [
      {
        data: [
          statistics.attacks,
          statistics.normal,
          statistics.suspicious,
        ],
        borderWidth: 0,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,

    plugins: {
      legend: {
        position: "bottom",
        labels: {
          color: "#a7b0c0",
          padding: 20,
        },
      },
    },

    cutout: "72%",
  };

  return (
    <div className="panel chart-panel">
      <div className="panel-header">
        <div>
          <h2>Traffic Distribution</h2>
          <p>Current network flow classification</p>
        </div>
      </div>

      <div className="chart-container">
        <Doughnut
          data={data}
          options={options}
        />
      </div>
    </div>
  );
}

export default TrafficChart;
*/
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
} from "chart.js";

import { Line } from "react-chartjs-2";

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend
);

function TrafficChart({ alerts = [] }) {
  /*
   * Build a simple timeline from the alerts currently
   * returned by the FastAPI backend.
   *
   * Important:
   * These are IDS detection events, not raw packet volume.
   * Raw network traffic will be added later when Zeek
   * integration is implemented.
   */

  const sortedAlerts = [...alerts]
    .filter((alert) => alert.created_at)
    .sort(
      (a, b) =>
        new Date(a.created_at) -
        new Date(b.created_at)
    );

  const labels = sortedAlerts.map((alert) =>
    new Date(alert.created_at).toLocaleTimeString(
      [],
      {
        hour: "2-digit",
        minute: "2-digit",
      }
    )
  );

  const attacks = sortedAlerts.map((alert) =>
    alert.decision === "ATTACK" ? 1 : 0
  );

  const suspicious = sortedAlerts.map((alert) =>
    alert.decision === "SUSPICIOUS" ? 1 : 0
  );

  const normal = sortedAlerts.map((alert) =>
    alert.decision === "NORMAL" ? 1 : 0
  );

  const data = {
    labels,

    datasets: [
      {
        label: "Attacks",
        data: attacks,
        borderColor: "#ff4d6d",
        backgroundColor: "rgba(255, 77, 109, 0.15)",
        tension: 0.35,
        fill: true,
      },
      {
        label: "Suspicious",
        data: suspicious,
        borderColor: "#f59e0b",
        backgroundColor: "rgba(245, 158, 11, 0.10)",
        tension: 0.35,
        fill: false,
      },
      {
        label: "Normal",
        data: normal,
        borderColor: "#22c55e",
        backgroundColor: "rgba(34, 197, 94, 0.10)",
        tension: 0.35,
        fill: false,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,

    interaction: {
      mode: "index",
      intersect: false,
    },

    plugins: {
      legend: {
        position: "bottom",

        labels: {
          color: "#a7b0c0",
          padding: 20,
        },
      },

      tooltip: {
        backgroundColor: "#0f172a",
        borderColor: "#26334d",
        borderWidth: 1,
        titleColor: "#ffffff",
        bodyColor: "#a7b0c0",
      },
    },

    scales: {
      x: {
        grid: {
          color: "rgba(100, 116, 139, 0.08)",
        },

        ticks: {
          color: "#64748b",
        },
      },

      y: {
        beginAtZero: true,

        ticks: {
          stepSize: 1,
          color: "#64748b",
        },

        grid: {
          color: "rgba(100, 116, 139, 0.08)",
        },
      },
    },
  };

  return (
    <div className="panel chart-panel">
      <div className="panel-header">
        <div>
          <h2>Detection Activity</h2>

          <p>
            IDS security events over time
          </p>
        </div>
      </div>

      <div className="chart-container">
        {sortedAlerts.length === 0 ? (
          <div className="empty-chart">
            No detection events available
          </div>
        ) : (
          <Line
            data={data}
            options={options}
          />
        )}
      </div>
    </div>
  );
}

export default TrafficChart;