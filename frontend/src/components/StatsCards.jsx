import {
  Activity,
  AlertTriangle,
  ShieldCheck,
  Siren,
} from "lucide-react";

function StatsCards({ statistics }) {
  const cards = [
    {
      title: "Total Flows",
      value: statistics.total_flows,
      icon: Activity,
      className: "blue",
    },
    {
      title: "Attacks",
      value: statistics.attacks,
      icon: AlertTriangle,
      className: "red",
    },
    {
      title: "Normal",
      value: statistics.normal,
      icon: ShieldCheck,
      className: "green",
    },
    {
      title: "Suspicious",
      value: statistics.suspicious,
      icon: Siren,
      className: "orange",
    },
  ];

  return (
    <section className="stats-grid">
      {cards.map((card) => {
        const Icon = card.icon;

        return (
          <div className={`stat-card ${card.className}`} key={card.title}>
            <div className="stat-card-top">
              <span>{card.title}</span>

              <div className="stat-icon">
                <Icon size={20} />
              </div>
            </div>

            <div className="stat-value">
              {card.value}
            </div>
          </div>
        );
      })}

      <div className="stat-card purple">
        <div className="stat-card-top">
          <span>Attack Rate</span>

          <div className="stat-icon">
            <AlertTriangle size={20} />
          </div>
        </div>

        <div className="stat-value">
          {Number(statistics.attack_rate).toFixed(1)}%
        </div>
      </div>
    </section>
  );
}

export default StatsCards;
