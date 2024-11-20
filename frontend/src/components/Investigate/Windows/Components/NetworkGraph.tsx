import React, { FC, useEffect, useMemo } from "react";
import { MultiDirectedGraph as MultiGraphConstructor } from "graphology";
import EdgeCurveProgram, {
  DEFAULT_EDGE_CURVATURE,
  indexParallelEdgesIndex,
} from "@sigma/edge-curve";
import { EdgeArrowProgram } from "sigma/rendering";
import { SigmaContainer, useLoadGraph, useSigma } from "@react-sigma/core";
import { useLayoutCircular } from "@react-sigma/layout-circular";
import "@react-sigma/core/lib/react-sigma.min.css";

import { Connection } from "../../../../types";

type NetworkGraphProps = {
  data: Connection[];
};

interface NodeType {
  x: number;
  y: number;
  label: string;
  size: number;
  color: string;
}

interface EdgeType {
  type?: string;
  label?: string;
  size?: number;
  curvature?: number;
  parallelIndex?: number;
  parallelMaxIndex?: number;
}

const NetworkGraphInner: FC<NetworkGraphProps> = ({ data }) => {
  // Hook for the circular layout
  const { assign } = useLayoutCircular();
  // Hook to load the graph
  const loadGraph = useLoadGraph();
  const sigma = useSigma();

  useEffect(() => {
    // Create a new graph instance
    const graph = new MultiGraphConstructor<NodeType, EdgeType>();
    console.log(graph.multi);
    // Keep track of the added nodes to avoid duplicates
    const nodesSet = new Set<string>();

    data.forEach((connection, index) => {
      const localAddr = connection.LocalAddr;
      const foreignAddr = connection.ForeignAddr;

      // Ensure that both localAddr and foreignAddr are non-empty strings
      if (!localAddr || !foreignAddr) {
        return; // Skip this connection if addresses are missing
      }

      // Add the local address node if it hasn't been added yet
      if (!nodesSet.has(localAddr)) {
        graph.addNode(localAddr, {
          label: localAddr,
          size: 10,
          color: "white",
          x: 0,
          y: 0,
        });
        nodesSet.add(localAddr);
      }

      // Add the foreign address node if it hasn't been added yet
      if (!nodesSet.has(foreignAddr)) {
        graph.addNode(foreignAddr, {
          label: foreignAddr,
          size: 10,
          color: "white",
          x: 0,
          y: 0,
        });
        nodesSet.add(foreignAddr);
      }

      // Create the edge connecting localAddr and foreignAddr
      const edgeLabel = `${connection.PID} - ${connection.Owner} : ${connection.LocalPort}:${connection.ForeignPort} - ${connection.State}`;

      graph.addDirectedEdge(localAddr, foreignAddr, {
        label: edgeLabel,
      });
      // Use dedicated helper to identify parallel edges:
      indexParallelEdgesIndex(graph, {
        edgeIndexAttribute: "parallelIndex",
        edgeMaxIndexAttribute: "parallelMaxIndex",
      });
      // Adapt types and curvature of parallel edges for rendering:
      graph.forEachEdge((edge, { parallelIndex, parallelMaxIndex }) => {
        if (typeof parallelIndex === "number") {
          graph.mergeEdgeAttributes(edge, {
            type: "curved",
            curvature:
              DEFAULT_EDGE_CURVATURE +
              (3 * DEFAULT_EDGE_CURVATURE * parallelIndex) /
                (parallelMaxIndex || 1),
          });
        } else {
          graph.setEdgeAttribute(edge, "type", "straight");
        }
      });
    });

    // Load the graph into Sigma
    loadGraph(graph);

    // Apply the circular layout
    assign();
  }, [assign, loadGraph, sigma, data]);

  return null;
};

const NetworkGraph: FC<NetworkGraphProps> = ({ data }) => {
  const settings = useMemo(
    () => ({
      allowInvalidContainer: true,
      renderEdgeLabels: true,
      defaultEdgeType: "straight",

      edgeProgramClasses: {
        straight: EdgeArrowProgram,
        curved: EdgeCurveProgram,
      },
    }),
    [],
  );

  return (
    <SigmaContainer
      style={{ height: "1000px", backgroundColor: "#121212" }}
      graph={MultiGraphConstructor<NodeType, EdgeType>}
      settings={settings}
    >
      <NetworkGraphInner data={data} />
    </SigmaContainer>
  );
};

export default NetworkGraph;
