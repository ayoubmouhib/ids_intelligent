import { useEffect, useRef } from "react";
import * as d3 from "d3";

function AttackMap({ events = [] }) {
  const svgRef = useRef(null);

  useEffect(() => {
    if (!svgRef.current) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const width = 650;
    const height = 280;

    svg
      .attr("viewBox", `0 0 ${width} ${height}`)
      .attr("preserveAspectRatio", "xMidYMid meet");

    // Background panel
    svg
      .append("rect")
      .attr("width", width)
      .attr("height", height)
      .attr("rx", 8)
      .attr("fill", "#090d16");

    if (!events || events.length === 0) {
      svg
        .append("text")
        .attr("x", width / 2)
        .attr("y", height / 2)
        .attr("text-anchor", "middle")
        .attr("fill", "#64748b")
        .attr("font-size", "14px")
        .text("Awaiting network connections for Topology Map...");
      return;
    }

    // Build Node & Link Data from Events
    const nodesMap = new Map();
    const links = [];

    events.slice(0, 20).forEach((evt) => {
      const src = evt.source_ip || "Source";
      const dst = evt.destination_ip || "Target";
      const decision = (evt.decision || "NORMAL").toUpperCase();

      if (!nodesMap.has(src)) {
        nodesMap.set(src, { id: src, type: "source", decision });
      }
      if (!nodesMap.has(dst)) {
        nodesMap.set(dst, { id: dst, type: "target", decision });
      }

      links.push({ source: src, target: dst, decision });
    });

    const nodes = Array.from(nodesMap.values());

    const simulation = d3
      .forceSimulation(nodes)
      .force("link", d3.forceLink(links).id((d) => d.id).distance(90))
      .force("charge", d3.forceManyBody().strength(-120))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .stop();

    for (let i = 0; i < 150; ++i) simulation.tick();

    const colorForDecision = (d) => {
      if (d === "ATTACK") return "#ff4d6d";
      if (d === "SUSPICIOUS") return "#f59e0b";
      return "#22c55e";
    };

    // Draw Links
    const link = svg
      .append("g")
      .selectAll("line")
      .data(links)
      .enter()
      .append("line")
      .attr("stroke", (d) => colorForDecision(d.decision))
      .attr("stroke-opacity", 0.6)
      .attr("stroke-width", (d) => (d.decision === "ATTACK" ? 2.5 : 1.5))
      .attr("x1", (d) => d.source.x)
      .attr("y1", (d) => d.source.y)
      .attr("x2", (d) => d.target.x)
      .attr("y2", (d) => d.target.y);

    // Draw Nodes
    const node = svg
      .append("g")
      .selectAll("circle")
      .data(nodes)
      .enter()
      .append("circle")
      .attr("r", (d) => (d.type === "target" ? 8 : 6))
      .attr("cx", (d) => d.x)
      .attr("cy", (d) => d.y)
      .attr("fill", (d) => colorForDecision(d.decision))
      .attr("stroke", "#0f172a")
      .attr("stroke-width", 2);

    // Labels
    svg
      .append("g")
      .selectAll("text")
      .data(nodes)
      .enter()
      .append("text")
      .attr("x", (d) => d.x + 10)
      .attr("y", (d) => d.y + 4)
      .text((d) => d.id)
      .attr("font-size", "10px")
      .attr("font-family", "monospace")
      .attr("fill", "#a7b0c0");

    // Title Badge
    svg
      .append("text")
      .attr("x", 16)
      .attr("y", 24)
      .attr("fill", "#64748b")
      .attr("font-size", "12px")
      .attr("font-weight", "600")
      .text(`Active Connections Topology (${nodes.length} Nodes)`);
  }, [events]);

  return (
    <div className="panel map-panel">
      <div className="panel-header">
        <div>
          <h2>Network Attack Map</h2>
          <p>Real-time source & destination IP connection topology</p>
        </div>
      </div>

      <div className="map-container" style={{ minHeight: "260px" }}>
        <svg ref={svgRef} style={{ width: "100%", height: "100%" }}></svg>
      </div>
    </div>
  );
}

export default AttackMap;
