import React, { useState, useEffect, useRef } from "react";
import { DataGrid, GridColDef, GridToolbar } from "@mui/x-data-grid";
import { Box, Button, CircularProgress } from "@mui/material";
import axiosInstance from "../../../../utils/axiosInstance";
import { useParams } from "react-router-dom";
import { Artefact, TaskData } from "../../../../types";
import { downloadFile } from "../../../../utils/downloadFile";
import { useSnackbar } from "../../../SnackbarProvider";

interface FileScanProps {
  data: Artefact[];
}

interface File {
  id: number;
  Offset: number;
  FileObject: string;
  Result: string;
}

const FileScan: React.FC<FileScanProps> = ({ data }) => {
  const { id: evidenceId } = useParams<{ id: string }>();
  const [loadingRows, setLoadingRows] = useState<{ [key: number]: boolean }>(
    {},
  );
  const ws = useRef<WebSocket | null>(null);
  const { display_message } = useSnackbar();

  useEffect(() => {
    const fetchTasks = async () => {
      try {
        const response = await axiosInstance.get(
          `/api/evidence/${evidenceId}/tasks/`,
        );
        const tasksData: TaskData[] = response.data;

        const getTaskArgsArray = (taskArgsString: string): unknown[] => {
          try {
            const parsedOnce = JSON.parse(taskArgsString);
            const parsedTwice = JSON.parse(parsedOnce);
            return parsedTwice;
          } catch (error) {
            display_message("error", `Error parsing task_args ${error}`);
            console.error("Error parsing task_args", error);
            return [];
          }
        };

        const loadingStates: { [key: number]: boolean } = {};

        tasksData.forEach((task) => {
          if (
            task.task_name === "volatility_engine.tasks.dump_windows_file" &&
            task.status === "STARTED" &&
            task.task_args
          ) {
            const argsArray = getTaskArgsArray(task.task_args);
            const taskOffset = argsArray && argsArray[1];
            if (taskOffset) {
              data.forEach((row) => {
                if (row.Offset === taskOffset) {
                  loadingStates[row.id as unknown as number] = true;
                }
              });
            }
          }
        });
        setLoadingRows(loadingStates);
      } catch (error) {
        console.error("Error fetching tasks", error);
      }
    };

    fetchTasks();
  }, [evidenceId, data, display_message]);

  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const port = window.location.port ? `:${window.location.port}` : "";
    const wsUrl = `${protocol}://${window.location.hostname}${port}/ws/engine/${evidenceId}/`;

    ws.current = new WebSocket(wsUrl);

    ws.current.onopen = () => {
      console.log("WebSocket connected");
    };

    ws.current.onmessage = (event) => {
      const eventData = JSON.parse(event.data);
      console.log("WebSocket message:", eventData);

      // Handle WebSocket notifications
      const message = eventData.message;
      if (message.status === "finished") {
        if (message.name === "file_dump" && message.result) {
          const results = message.result;
          if (results.length > 0) {
            results.forEach((item: File) => {
              const fileName = item.Result;
              const fileUrl = `/media/${evidenceId}/${fileName}`;
              downloadFile(fileUrl, fileName);
              display_message("success", "The file was dumped with success.");
            });
          } else {
            display_message(
              "warning",
              "The volatility3 filescan plugin returned no results",
            );
          }

          const fileObjects = results.map((item: File) => item.Result);
          data.forEach((row) => {
            if (fileObjects.includes(row.Result)) {
              setLoadingRows((prev) => ({
                ...prev,
                [row.id as unknown as number]: false,
              }));
            }
          });
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
  }, [evidenceId, data, display_message]);

  // Define columns for DataGrid, including the "Actions" column
  const columns: GridColDef[] = data[0]
    ? Object.keys(data[0])
        .filter((key) => key !== "__children" && key !== "id")
        .map((key) => ({
          field: key,
          headerName: key,
          flex: 1,
          renderCell: (params) => params.value,
        }))
    : [];

  columns.push({
    field: "actions",
    headerName: "Actions",
    sortable: false,
    renderCell: (params) => {
      const rowId = params.row.id;
      const isLoading = loadingRows[rowId];

      const handleDumpClick = async () => {
        // Set loading state for this row
        setLoadingRows((prev) => ({ ...prev, [rowId]: true }));

        try {
          await axiosInstance.post("/api/evidence/tasks/dump/file/", {
            evidenceId,
            offset: params.row.Offset,
          });
          // The loading state will remain true until we receive a WebSocket message
        } catch (error) {
          console.error("Error during dump", error);
          // Reset loading state on error
          setLoadingRows((prev) => ({ ...prev, [rowId]: false }));
        }
      };

      return (
        <Button
          variant="outlined"
          color="error"
          size="small"
          onClick={handleDumpClick}
          disabled={isLoading}
        >
          {isLoading ? <CircularProgress size={20} /> : "Dump"}
        </Button>
      );
    },
  });

  return (
    <Box>
      <DataGrid
        disableDensitySelector
        slots={{
          toolbar: GridToolbar,
        }}
        slotProps={{
          toolbar: {
            showQuickFilter: true,
          },
        }}
        sx={{ height: "85vh" }}
        rows={data}
        columns={columns}
        getRowId={(row) => row.id}
        pagination
        getRowHeight={() => "auto"}
      />
    </Box>
  );
};

export default FileScan;
