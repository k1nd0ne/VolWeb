import React, {
  useEffect,
  useState,
  useMemo,
  useRef,
  useCallback,
} from "react";
import { useParams } from "react-router-dom";
import Chart from "react-apexcharts";
import { DataGrid, GridColDef, useGridApiRef } from "@mui/x-data-grid";
import axiosInstance from "../../utils/axiosInstance";
import { Button, CircularProgress, Box } from "@mui/material";
import Checkbox from "@mui/material/Checkbox";
import CloseIcon from "@mui/icons-material/Close";
import IconButton from "@mui/material/IconButton";
import { MouseEvent } from "react";
import axios from "axios";
import { useSnackbar } from "../SnackbarProvider";

interface Artefact {
  __children: Artefact[];
  Plugin: string;
  Description: string;
  "Created Date": Date | null;
  "Modified Date": Date | null;
  "Accessed Date": Date | null;
  "Changed Date": Date | null;
}

interface ChartContext {
  w: {
    config: {
      series: {
        data: { x: string; y: number }[];
      }[];
    };
  };
}

interface TaskData {
  task_name: string;
  status: string;
  task_args: string;
}

const Timeliner: React.FC = () => {
  const [graphData, setGraphData] = useState<[string, number][]>([]);
  const [artefactData, setArtefactData] = useState<Artefact[]>([]);
  const { id } = useParams<{ id: string }>();
  const [loading, setLoading] = useState<boolean>(false);
  const [processing, setProcessing] = useState<boolean>(false);
  const [seriesData, setSeriesData] = useState<{ x: string; y: number }[]>([]);
  const apiRef = useGridApiRef();
  const ws = useRef<WebSocket | null>(null);
  const { display_message } = useSnackbar();

  const columns: GridColDef[] = useMemo(() => {
    return artefactData[0]
      ? Object.keys(artefactData[0])
          .filter((key) => key !== "__children" && key !== "id")
          .map((key) => ({
            field: key,
            headerName: key,
            renderCell: (params) =>
              typeof params.value === "boolean" ? (
                params.value ? (
                  <Checkbox checked={true} color="success" />
                ) : (
                  <IconButton color="error">
                    <CloseIcon />
                  </IconButton>
                )
              ) : params.value !== null ? (
                params.value
              ) : (
                ""
              ),
          }))
      : [];
  }, [artefactData]);

  const autosizeOptions = useMemo(
    () => ({
      columns: [...columns].map((col) => col.headerName ?? ""),
      includeOutliers: true,
      includeHeaders: true,
    }),
    [columns],
  );

  // Function to fetch artefacts based on timestamp range
  const fetchArtefacts = useCallback(
    async (range: [string, string]) => {
      try {
        setLoading(true);
        const [start, end] = range;
        const params: { start: string; end: string } = { start, end };
        const response = await axiosInstance.get(
          `/api/evidence/${id}/plugin/volatility3.plugins.timeliner.Timeliner`,
          { params },
        );
        // Assign consistent unique IDs to each row
        const artefactsWithId = response.data.artefacts.map(
          (artefact: Artefact, index: number) => ({
            ...artefact,
            id: index,
          }),
        );
        setArtefactData(artefactsWithId);
      } catch (error) {
        display_message("error", `Error fetching artefacts: ${error}`);
      } finally {
        setLoading(false);
      }
    },
    [id, display_message],
  );

  // Function to check if a timeliner task is running
  const checkIfTimelinerTaskRunning = useCallback(async () => {
    try {
      const response = await axiosInstance.get(`/api/evidence/${id}/tasks/`);
      const tasksData: TaskData[] = response.data;

      const isTimelinerTaskRunning = tasksData.some((task) => {
        return (
          task.task_name === "volatility_engine.tasks.start_timeliner" &&
          task.status === "STARTED"
        );
      });

      setProcessing(isTimelinerTaskRunning);
    } catch (error) {
      //display_message("error", `Error fetching tasks: ${error}`);
      console.error("Error fetching tasks", error);
    }
  }, [id, display_message]);

  // Function to fetch TimelinerGraph data
  const fetchTimelinerGraph = useCallback(async () => {
    try {
      const response = await axiosInstance.get(
        `/api/evidence/${id}/plugin/volatility3.plugins.timeliner.TimelinerGraph`,
      );
      setGraphData(response.data.artefacts);
      setSeriesData(
        response.data.artefacts.map((item: [string, number]) => ({
          x: item[0],
          y: item[1],
        })),
      );

      if (response.data && response.data.artefacts.length > 0) {
        fetchArtefacts([
          response.data.artefacts[0][0],
          response.data.artefacts[0][0],
        ]);
      }
    } catch (error) {
      console.error("Error fetching TimelinerGraph", error);
      if (axios.isAxiosError(error) && error.response?.status === 404) {
        checkIfTimelinerTaskRunning();
      }
    }
  }, [id, fetchArtefacts, checkIfTimelinerTaskRunning]);

  // Fetch TimelinerGraph on component mount
  useEffect(() => {
    fetchTimelinerGraph();
  }, [fetchTimelinerGraph]);

  // WebSocket setup
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

      // Handle WebSocket notifications
      const message = data.message;
      if (message.name === "timeliner") {
        if (message.status === "finished") {
          if (message.result !== "false") {
            setProcessing(false);
            fetchTimelinerGraph();
          } else {
            setProcessing(false);
            display_message(
              "warning",
              "The timeliner plugin did not return any results.",
            );
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
  }, [id, fetchTimelinerGraph]);

  // Autosize columns when artefactData changes
  useEffect(() => {
    if (!loading && artefactData.length > 0) {
      const timeoutId = setTimeout(() => {
        if (apiRef.current && apiRef.current.autosizeColumns) {
          apiRef.current.autosizeColumns(autosizeOptions);
        }
      }, 200);
      return () => clearTimeout(timeoutId);
    }
  }, [loading, artefactData, autosizeOptions, apiRef]);

  // Handle "Build timeline" button click
  const handleRunTask = async () => {
    setProcessing(true);
    try {
      await axiosInstance.post(`/api/evidence/tasks/timeliner/`, { id });
    } catch (error) {
      display_message("error", `Error triggering timeliner task: ${error}`);
      console.error("Error triggering timeliner task", error);
      setProcessing(false); // Stop processing on error
    }
  };

  const state = useMemo(
    () => ({
      series: [{ data: seriesData }],
      options: {
        theme: {
          mode: "dark" as const,
          palette: "palette1",
          monochrome: {
            enabled: true,
            color: "#9a0000",
            shadeTo: "light" as const,
            shadeIntensity: 0.65,
          },
        },
        dataLabels: { enabled: false },
        chart: {
          background: "#121212",
          stacked: false,
          zoom: {
            enabled: true,
            autoScaleYaxis: true,
          },
          events: {
            markerClick: function (
              _event: MouseEvent,
              chartContext: ChartContext,
              {
                seriesIndex,
                dataPointIndex,
              }: { seriesIndex: number; dataPointIndex: number },
            ) {
              const timestamp =
                chartContext.w.config.series[seriesIndex].data[dataPointIndex]
                  .x;
              fetchArtefacts([timestamp, timestamp]);
            },
            zoomed: function (
              chartContext: ChartContext,
              { xaxis }: { xaxis: { min: number; max: number } },
            ) {
              const timestamp_min =
                chartContext.w.config.series[0].data[xaxis.min - 1].x;
              const timestamp_max =
                chartContext.w.config.series[0].data[xaxis.max - 1].x;
              fetchArtefacts([timestamp_min, timestamp_max]);
            },
          },
        },
      },
    }),
    [seriesData, fetchArtefacts],
  );

  if (graphData.length === 0) {
    return (
      <div
        style={{
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          height: "100vh",
        }}
      >
        <Button
          variant="outlined"
          size="large"
          color="error"
          onClick={handleRunTask}
          disabled={processing}
          startIcon={processing && <CircularProgress size={20} />}
        >
          {processing ? "Processing..." : "Build timeline"}
        </Button>
      </div>
    );
  }

  return (
    <Box sx={{ flexGrow: 1 }}>
      <Chart
        options={state.options}
        series={state.series}
        type="area"
        height={300}
      />
      <div style={{ height: 400, width: "100%" }}>
        <DataGrid
          rows={artefactData}
          columns={columns}
          density="compact"
          getRowId={(row) => row.id}
          pagination
          showToolbar={true}
          autosizeOnMount
          loading={loading}
          autosizeOptions={autosizeOptions}
          apiRef={apiRef}
          getRowHeight={() => "auto"}
        />
      </div>
    </Box>
  );
};

export default Timeliner;
