import React, { useRef, useEffect, useState } from "react";
import Graph from "graphology";
import Sigma from "sigma";
import ProcessDetails from "./ProcessDetails";
import { NodeEventPayload } from "sigma/types/events";
import ForceSupervisor from "graphology-layout-force/worker";
import drawHover from "sigma/rendering/canvas/hover";
import Grid from "@mui/material/Grid2";
import { ProcessInfo } from "../../../types";

interface ProcessGraphProps {
  data: ProcessInfo[];
}

const ProcessGraph: React.FC<ProcessGraphProps> = ({ data }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const sigmaRef = useRef<Sigma | null>(null);
  const [graph, setGraph] = useState<Graph | null>(null);
  const [selectedProcess, setSelectedProcess] = useState<ProcessInfo | null>(
    null,
  );
  const isDraggingRef = useRef<boolean>(false); // Ref to track dragging state
  const draggedNodeRef = useRef<string | null>(null); // Ref to store dragged node

  useEffect(() => {
    if (containerRef.current && !sigmaRef.current) {
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
          label: process.ImageFileName || "Unknown",
          size: 10,
          color: "#FFFFFF",
          x: x,
          y: y,
        });
      });

      // Initialize Sigma with renderer options
      sigmaRef.current = new Sigma(graph, containerRef.current, {
        renderEdgeLabels: true,
        labelSize: 12,
        labelRenderer: drawHover,
        labelRenderedSizeThreshold: 1,
      });
      setGraph(graph);
      const layout = new ForceSupervisor(graph);
      layout.start();
      setTimeout(function () {
        layout.stop();
      }, 1000);
    }
  }, [data]);

  useEffect(() => {
    if (sigmaRef.current && graph) {
      const renderer = sigmaRef.current;
      renderer.on("enterNode", () => {
        document.body.style.cursor = "pointer";
      });

      renderer.on("leaveNode", () => {
        document.body.style.cursor = "default";
      });
      const handleClickNode = (event: NodeEventPayload) => {
        const nodeId = event.node;
        const nodeAttributes = graph.getNodeAttributes(nodeId);

        // Retrieve the process data for this node
        const pid = parseInt(nodeId);
        const process = findProcessByPID(data, pid);
        if (process) {
          setSelectedProcess(process);
        }

        // Check if node has been expanded already
        if (!nodeAttributes.expanded) {
          if (process) {
            expandNode(process, graph);
            graph.setNodeAttribute(nodeId, "expanded", true);
            renderer.refresh();
          }
        }
      };

      const handleMouseDownNode = (event: NodeEventPayload) => {
        isDraggingRef.current = true;
        draggedNodeRef.current = event.node;
        // Optionally highlight the node
        graph.setNodeAttribute(event.node, "highlighted", true);
        const layout = new ForceSupervisor(graph);
        layout.start();
        setTimeout(function () {
          layout.stop();
        }, 1000);
      };

      const handleMouseMove = (event: MouseEvent) => {
        if (isDraggingRef.current && draggedNodeRef.current) {
          const pos = renderer.viewportToGraph({
            x: event.clientX,
            y: event.clientY,
          });
          graph.setNodeAttribute(draggedNodeRef.current, "x", pos.x);
          graph.setNodeAttribute(draggedNodeRef.current, "y", pos.y);
        }
      };

      const handleMouseUp = () => {
        if (isDraggingRef.current) {
          isDraggingRef.current = false;
          if (draggedNodeRef.current) {
            // Remove highlight from the node
            graph.removeNodeAttribute(draggedNodeRef.current, "highlighted");
            draggedNodeRef.current = null;
          }
        }
      };

      renderer.on("clickNode", handleClickNode);
      renderer.on("downNode", handleMouseDownNode);
      renderer.getMouseCaptor().on("mousemove", handleMouseMove);
      renderer.getMouseCaptor().on("mouseup", handleMouseUp);

      // Clean up event listeners on unmount
      return () => {
        renderer.removeListener("clickNode", handleClickNode);
        renderer.removeListener("downNode", handleMouseDownNode);
        renderer.getMouseCaptor().removeListener("mousemove", handleMouseMove);
        renderer.getMouseCaptor().removeListener("mouseup", handleMouseUp);
      };
    }
  }, [graph, data]);

  function findProcessByPID(
    data: ProcessInfo[],
    pid: number,
  ): ProcessInfo | null {
    for (const process of data) {
      if (process.PID === pid) {
        return process;
      } else if (process.__children) {
        const result = findProcessByPID(process.__children, pid);
        if (result) return result;
      }
    }
    return null;
  }

  function expandNode(process: ProcessInfo, graph: Graph) {
    const parentId = process.PID.toString();

    const parentAttributes = graph.getNodeAttributes(parentId);
    const { x: px, y: py } = parentAttributes;

    const children = process.__children || [];
    const N = children.length;

    children.forEach((child, i) => {
      const childId = child.PID.toString();

      const angle = (i * 2 * Math.PI) / N;
      const distance = 50;
      const x = px + distance * Math.cos(angle);
      const y = py + distance * Math.sin(angle);

      if (!graph.hasNode(childId)) {
        graph.addNode(childId, {
          label: child.ImageFileName || "Unknown",
          size: 10,
          color: "#FFFFFF",
          x: x,
          y: y,
        });
      }

      if (!graph.hasEdge(parentId, childId)) {
        graph.addEdge(parentId, childId, {
          label: "",
          size: 1,
          color: "#fff",
          type: "arrow",
        });
      }
    });

    if (sigmaRef.current) {
      sigmaRef.current.refresh();
    }
  }

  return (
    <Grid container>
      <Grid size={12}>
        <div
          ref={containerRef}
          style={{ width: "100%", height: "600px" }}
        ></div>
      </Grid>
      <Grid size={8}>
        {selectedProcess && <ProcessDetails process={selectedProcess} />}
      </Grid>
    </Grid>
  );
};

export default ProcessGraph;
