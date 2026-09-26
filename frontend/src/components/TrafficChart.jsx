import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
  Filler,
} from "chart.js";
import { Line } from "react-chartjs-2";

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
  Filler
);

function TrafficChart({ timelineData = [] }) {
  const labels = timelineData.map((bucket) => {
    const date = new Date(bucket.time);

    if (Number.isNaN(date.getTime())) {
      return "";
    }

    return date.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    });
  });

  const attacks = timelineData.map(
    (bucket) => bucket.attacks || 0
  );

  const suspicious = timelineData.map(
    (bucket) => bucket.suspicious || 0
  );

  const normal = timelineData.map(
    (bucket) => bucket.normal || 0
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
          padding: 16,
          font: {
            size: 12,
          },
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
          font: {
            size: 11,
          },
        },
      },

      y: {
        beginAtZero: true,
        ticks: {
          precision: 0,
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
          <p>Network security classification trends</p>
        </div>
      </div>

      <div
        className="chart-container"
        style={{
          height: "260px",
          position: "relative",
        }}
      >
        {timelineData.length === 0 ? (
          <div className="empty-state">
            No traffic timeline data available.
          </div>
        ) : (
          <Line data={data} options={options} />
        )}
      </div>
    </div>
  );
}

export default TrafficChart;