import { useEffect, useRef } from "react";
import * as d3 from "d3";

function AttackMap({ alerts }) {
  const svgRef = useRef(null);

  useEffect(() => {
    const svg = d3.select(svgRef.current);

    svg.selectAll("*").remove();

    const width = 700;
    const height = 320;

    svg
      .attr("viewBox", `0 0 ${width} ${height}`)
      .attr("preserveAspectRatio", "xMidYMid meet");

    svg
      .append("rect")
      .attr("width", width)
      .attr("height", height)
      .attr("rx", 12)
      .attr("fill", "#0b1220");

    svg
      .append("text")
      .attr("x", width / 2)
      .attr("y", height / 2 - 15)
      .attr("text-anchor", "middle")
      .attr("fill", "#64748b")
      .attr("font-size", "16px")
      .text("Network Attack Map");

    svg
      .append("text")
      .attr("x", width / 2)
      .attr("y", height / 2 + 15)
      .attr("text-anchor", "middle")
      .attr("fill", "#475569")
      .attr("font-size", "13px")
      .text(
        "Waiting for source IP / geographic traffic data"
      );

    svg
      .append("text")
      .attr("x", 20)
      .attr("y", 30)
      .attr("fill", "#64748b")
      .attr("font-size", "12px")
      .text(`Alerts: ${alerts.length}`);
  }, [alerts]);

  return (
    <div className="panel map-panel">
      <div className="panel-header">
        <div>
          <h2>Attack Map</h2>
          <p>Geographic attack visualization</p>
        </div>
      </div>

      <div className="map-container">
        <svg ref={svgRef}></svg>
      </div>
    </div>
  );
}

export default AttackMap;
