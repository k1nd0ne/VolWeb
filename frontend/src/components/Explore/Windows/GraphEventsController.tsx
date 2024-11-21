import { FC, useEffect, useState, useRef } from "react";
import { useSigma, useRegisterEvents } from "@react-sigma/core";
import Graph from "graphology";
import { ProcessInfo } from "../../../types";
import ForceSupervisor from "graphology-layout-force/worker";

interface GraphEventsControllerProps {
  data: ProcessInfo[];
  onProcessSelect: (process: ProcessInfo | null) => void;
}

const GraphEventsController: FC<GraphEventsControllerProps> = ({
  data,
  onProcessSelect,
}) => {
  const sigma = useSigma();
  const graph = sigma.getGraph();
  const registerEvents = useRegisterEvents();
  const [selectedProcess, setSelectedProcess] = useState<ProcessInfo | null>(
    null,
  );

  // Refs for drag handling
  const isDragging = useRef<boolean>(false);
  const draggedNode = useRef<string | null>(null);

  useEffect(() => {
    const handleClickNode = ({ node }: { node: string }) => {
      const nodeAttributes = graph.getNodeAttributes(node);

      // Retrieve the process data for this node
      const pid = parseInt(node);
      const process = findProcessByPID(data, pid);
      if (process) {
        setSelectedProcess(process);
        onProcessSelect(process); // Notify parent component
      }

      // Check if node has been expanded already
      if (!nodeAttributes.expanded) {
        if (process) {
          expandNode(process, graph);
          graph.setNodeAttribute(node, "expanded", true);
          sigma.refresh();

          // Run ForceSupervisor layout after expanding node
          const layout = new ForceSupervisor(graph);
          layout.start();
          setTimeout(() => {
            layout.stop();
          }, 1000);
        }
      }
    };

    const handleDownNode = ({ node }: { node: string }) => {
      isDragging.current = true;
      draggedNode.current = node;
      graph.setNodeAttribute(node, "highlighted", true);
    };

    const handleMouseMove = (event: {
      x: number;
      y: number;
      dragging: boolean;
    }) => {
      if (isDragging.current && draggedNode.current) {
        const coords = sigma.viewportToGraph({ x: event.x, y: event.y });
        graph.setNodeAttribute(draggedNode.current, "x", coords.x);
        graph.setNodeAttribute(draggedNode.current, "y", coords.y);
        sigma.refresh();
      }
    };

    const handleMouseUp = () => {
      if (isDragging.current && draggedNode.current) {
        isDragging.current = false;
        graph.removeNodeAttribute(draggedNode.current, "highlighted");
        draggedNode.current = null;
      }
    };

    registerEvents({
      clickNode: handleClickNode,
      downNode: handleDownNode,
      mousemove: handleMouseMove,
      mouseup: handleMouseUp,
    });
  }, [data, graph, sigma, registerEvents, onProcessSelect]);

  // Helper functions
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
          label: `${child.ImageFileName || "Unknown"} - ${child.PID} (${child.__children.length})`,
          size: 5,
          color:
            child.__children.length > 0
              ? "blue"
              : child.anomalies && child.anomalies.length > 0
                ? "orange"
                : "#FFFFFF",
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

    sigma.refresh();
  }

  return null;
};

export default GraphEventsController;
