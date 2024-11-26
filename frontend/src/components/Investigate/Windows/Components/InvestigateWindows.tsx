import React, { useState, useEffect, useRef } from "react";
import Box from "@mui/material/Box";
import Grid from "@mui/material/Grid2";
import PsTree from "./PsTree";
import ProcessMetadata from "./ProcessMetadata";
import PluginDashboard from "../../PluginDashboard";
import { ProcessInfo, Evidence, Artefact, TaskData } from "../../../../types";
import { useParams } from "react-router-dom";
import axiosInstance from "../../../../utils/axiosInstance";
import { downloadFile } from "../../../../utils/downloadFile";
import { useSnackbar } from "../../../SnackbarProvider";

interface InvestigateWindowsProps {
  evidence: Evidence;
}

const InvestigateWindows: React.FC<InvestigateWindowsProps> = ({
  evidence,
}) => {
  const [processMetadata, setProcessMetadata] = useState<ProcessInfo>(
    {} as ProcessInfo,
  );
  const { id } = useParams<{ id: string }>();
  const { display_message } = useSnackbar();

  const ws = useRef<WebSocket | null>(null);
  const processMetadataRef = useRef<ProcessInfo>(processMetadata);

  const [loadingDump, setLoadingDump] = useState<boolean>(false);
  const [loadingHandles, setLoadingHandles] = useState<boolean>(false);

  useEffect(() => {
    processMetadataRef.current = processMetadata;
  }, [processMetadata]);

  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const port = window.location.port ? `:${window.location.port}` : "";
    const wsUrl = `${protocol}://${window.location.hostname}${port}/ws/engine/${id}/`;

    ws.current = new WebSocket(wsUrl);

    ws.current.onopen = () => {
      console.log("WebSocket connected");
    };

    ws.current.onmessage = (event) => {
      const data = JSON.parse(event.data);
      console.log("WebSocket message:", data);
      const message = data.message;

      // Use processMetadataRef.current instead of processMetadata
      const currentPID = processMetadataRef.current.PID;

      if (message.status === "finished") {
        if (message.pid === currentPID && message.name === "handles") {
          setLoadingHandles(false);
        }
        if (message.pid === currentPID && message.name === "dump") {
          setLoadingDump(false);
        }

        if (message.name === "handles") {
          display_message("success", `Handles are available for ${currentPID}`);
        } else if (message.name === "dump") {
          if (message.result) {
            const results = message.result;
            results.forEach((item: Artefact) => {
              const fileName = item["File output"] as string;
              if (fileName === "Error outputting file") {
                console.log(
                  `The volatility engine failed to dump ${item.ImageFileName}`,
                );
                display_message(
                  "warning",
                  `The volatility engine failed to dump ${item.ImageFileName}`,
                );

                return;
              }
              const fileUrl = `/media/${id}/${fileName}`;
              // Initiate file download
              downloadFile(fileUrl, fileName);
              display_message(
                "success",
                `${item.ImageFileName} was dumped with success.`,
              );
            });
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
    // Remove processMetadata from dependencies
  }, [id, display_message]); // Only depends on id and display_message

  // Fetch tasks when processMetadata updates
  useEffect(() => {
    if (processMetadata && processMetadata.PID) {
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
              display_message("warning", `Error parsing task_args ${error}`);
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

          const isHandlesTaskRunning = tasksData.some((task) => {
            if (
              task.task_name ===
                "volatility_engine.tasks.dump_windows_handles" &&
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
          setLoadingHandles(isHandlesTaskRunning);
        } catch (error) {
          console.error("Could not fetch tasks", error);
        }
      };

      fetchTasks();
    } else {
      console.log("No process selected or PID missing.");
      setLoadingDump(false);
      setLoadingHandles(false);
    }
  }, [processMetadata, id, display_message]);

  return (
    <Box sx={{ flexGrow: 1 }}>
      <Grid container spacing={2}>
        <Grid size={3}>
          <PsTree setProcessMetadata={setProcessMetadata} />
        </Grid>
        <Grid size={3}>
          <ProcessMetadata
            processMetadata={processMetadata}
            loadingDump={loadingDump}
            setLoadingDump={setLoadingDump}
            loadingHandles={loadingHandles}
            setLoadingHandles={setLoadingHandles}
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

export default InvestigateWindows;
