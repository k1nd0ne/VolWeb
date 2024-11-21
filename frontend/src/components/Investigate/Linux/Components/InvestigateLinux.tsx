import React, { useState, useEffect, useRef } from "react";
import Box from "@mui/material/Box";
import Grid from "@mui/material/Grid2";
import PsTree from "./PsTree";
import ProcessMetadata from "./ProcessMetadata";
import PluginDashboard from "../../PluginDashboard";
import { ProcessInfo, Evidence } from "../../../../types";
import { useParams } from "react-router-dom";
import axiosInstance from "../../../../utils/axiosInstance";
import { downloadFile } from "../../../../utils/downloadFile";

interface InvestigateLinuxProps {
  evidence: Evidence;
}

const InvestigateLinux: React.FC<InvestigateLinuxProps> = ({ evidence }) => {
  const [processMetadata, setProcessMetadata] = useState<ProcessInfo>(
    {} as ProcessInfo,
  );
  const { id } = useParams<{ id: string }>();

  // WebSocket setup
  const ws = useRef<WebSocket | null>(null);

  // Loading states
  const [loadingDump, setLoadingDump] = useState<boolean>(false);
  const [loadingMaps, setLoadingMaps] = useState<boolean>(false);

  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const wsUrl = `${protocol}://${window.location.hostname}:8000/ws/engine/${id}/`;

    ws.current = new WebSocket(wsUrl);

    ws.current.onopen = () => {
      console.log("WebSocket connected");
    };

    ws.current.onmessage = (event) => {
      const data = JSON.parse(event.data);
      console.log("WebSocket message:", data);
      const message = data.message;
      if (message.status === "finished") {
        if (message.pid === processMetadata.PID) {
          if (message.name === "maps") {
            setLoadingMaps(false);
          } else if (message.name === "dump") {
            setLoadingDump(false);
            if (message.result) {
              const results = message.result;
              results.forEach((item: any) => {
                const fileName = item["File output"];
                if (fileName === "Error outputting file") {
                  // TODO use the message handler
                  console.log(
                    `The volatility engine failed to dump ${item.COMM}`,
                  );
                  return;
                }
                const fileUrl = `/media/${id}/${fileName}`;
                // Initiate file download
                downloadFile(fileUrl, fileName);
              });
            }
          }
        }
      }
    };

    ws.current.onclose = () => {
      console.log("WebSocket disconnected");
    };

    ws.current.onerror = (error) => {
      console.log("WebSocket error:", error);
    };

    return () => {
      if (ws.current) {
        ws.current.close();
      }
    };
  }, [id, processMetadata.PID]);

  // Fetch tasks when processMetadata updates
  useEffect(() => {
    if (processMetadata && processMetadata.PID) {
      console.log("Fetching tasks for PID:", processMetadata.PID);
      const fetchTasks = async () => {
        try {
          const response = await axiosInstance.get(
            `/api/evidence/${id}/tasks/`,
          );
          const tasksData: TaskData[] = response.data;

          const pid = processMetadata.PID;

          const getTaskArgsArray = (taskArgsString: string): string[] => {
            try {
              const parsedOnce = JSON.parse(taskArgsString);
              const parsedTwice = JSON.parse(parsedOnce);
              return parsedTwice;
            } catch (error) {
              console.error("Error parsing task_args", error);
              return [];
            }
          };

          const isDumpTaskRunning = tasksData.some((task) => {
            if (
              task.task_name === "volatility_engine.tasks.dump_process" &&
              task.status === "STARTED" &&
              task.task_args
            ) {
              const argsArray = getTaskArgsArray(task.task_args);
              const taskPid = Number(argsArray[1]);
              return taskPid === pid;
            }
            return false;
          });

          const isMapsTaskRunning = tasksData.some((task) => {
            if (
              task.task_name === "volatility_engine.tasks.dump_maps" &&
              task.status === "STARTED" &&
              task.task_args
            ) {
              const argsArray = getTaskArgsArray(task.task_args);
              const taskPid = Number(argsArray[1]);
              return taskPid === pid;
            }
            return false;
          });

          setLoadingDump(isDumpTaskRunning);
          setLoadingMaps(isMapsTaskRunning);
        } catch (error) {
          console.error("Error fetching tasks", error);
        }
      };

      fetchTasks();
    } else {
      console.log("No process selected or PID missing.");
      setLoadingDump(false);
      setLoadingMaps(false);
    }
  }, [processMetadata, id]);

  return (
    <Box sx={{ flexGrow: 1 }}>
      <Grid container spacing={2}>
        <Grid size={3}>
          <PsTree setProcessMetadata={setProcessMetadata} />
        </Grid>
        <Grid size={3}>
          <ProcessMetadata
            processMetadata={processMetadata}
            loadingDumpPslist={loadingDump}
            setLoadingDumpPslist={setLoadingDump}
            loadingDumpMaps={loadingMaps}
            setLoadingDumpMaps={setLoadingMaps}
            id={id}
          />
        </Grid>
        <Grid size={6}>
          <PluginDashboard evidence={evidence} />
        </Grid>
      </Grid>
    </Box>
  );
};

export default InvestigateLinux;