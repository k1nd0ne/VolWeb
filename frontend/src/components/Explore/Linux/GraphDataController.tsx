import { FC, useEffect } from "react";
import Graph from "graphology";
import { useLoadGraph } from "@react-sigma/core";
import { LinuxProcessInfo } from "../../../types";
import ForceSupervisor from "graphology-layout-force/worker";

interface GraphDataControllerProps {
  data: LinuxProcessInfo[];
}

const GraphDataController: FC<GraphDataControllerProps> = ({ data }) => {
  const loadGraph = useLoadGraph();

  useEffect(() => {
    const graph = new Graph();

    // Number of root nodes
    const N = data.length;

    // Add root nodes with positions
    data.forEach((process, i) => {
      const nodeId = process.PID.toString();
      const angle = (i * 2 * Math.PI) / N;
      const x = 100 * Math.cos(angle);
      const y = 100 * Math.sin(angle);

      graph.addNode(nodeId, {
        label: `${process.COMM || "Unknown"} - ${process.PID} (${process.__children.length})`,
        size: 10,
        color:
          process.anomalies && process.anomalies.length > 0
            ? "#ffa726"
            : "#FFFFFF",
        x: x,
        y: y,
      });
    });

    loadGraph(graph);

    const layout = new ForceSupervisor(graph);
    layout.start();
    setTimeout(() => {
      layout.stop();
    }, 1000);

    return () => {
      layout.stop();
    };
  }, [data, loadGraph]);

  return null;
};

export default GraphDataController;
