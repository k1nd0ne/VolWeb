import React, { useEffect, useState, useMemo } from "react";
import { useParams } from "react-router-dom";
import Chart from "react-apexcharts";
import { DataGrid, GridColDef, useGridApiRef } from "@mui/x-data-grid";
import axiosInstance from "../../utils/axiosInstance";
import { Button, CircularProgress, Box } from "@mui/material";
import Checkbox from "@mui/material/Checkbox";
import CloseIcon from "@mui/icons-material/Close";
import IconButton from "@mui/material/IconButton";
import { MouseEvent } from "react";

interface Artefact {
  __children: Artefact[];
  Plugin: string;
  Description: string;
  "Created Date": string | null;
  "Modified Date": string | null;
  "Accessed Date": string | null;
  "Changed Date": string | null;
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

const Timeliner: React.FC = () => {
  const [graphData, setGraphData] = useState<[string, number][]>([]);
  const [artefactData, setArtefactData] = useState<Artefact[]>([]);
  const { id } = useParams<{ id: string }>();
  const [loading, setLoading] = useState<boolean>(false);
  const [processing, setProcessing] = useState<boolean>(false);
  const [seriesData, setSeriesData] = useState<{ x: string; y: number }[]>([]);
  const apiRef = useGridApiRef();

  const columns: GridColDef[] = artefactData[0]
    ? Object.keys(artefactData[0])
        .filter((key) => key !== "__children" && key !== "id") // Filter out the "id" column
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
  const autosizeOptions = {
    columns: [...columns].map((col) => col.headerName ?? ""),
    includeOutliers: true,
    includeHeaders: true,
  };
  const fetchArtefacts = async (range: [string, string]) => {
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
      console.error("Error fetching artefacts", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const fetchTimelinerGraph = async () => {
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
      }
    };

    fetchTimelinerGraph();
  }, [id]);

  useEffect(() => {
    if (!loading && artefactData.length > 0) {
      const timeoutId = setTimeout(() => {
        if (apiRef.current) {
          apiRef.current.autosizeColumns(autosizeOptions);
        }
      }, 200); // Delay to ensure DataGrid has rendered
      return () => clearTimeout(timeoutId);
    }
  }, [loading, artefactData]);

  const handleRunTask = async () => {
    setProcessing(true);
    try {
      await axiosInstance.post(`/api/evidence/tasks/timeliner/`, { id });
      // Completion logic goes here
    } catch (error) {
      console.error("Error triggering timeliner task", error);
    } finally {
      setProcessing(false);
    }
  };

  const options = useMemo(
    () => ({
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
      series: [{ data: seriesData }],
      chart: {
        background: "#121212",
        type: "area" as const,
        stacked: false,
        zoom: {
          type: "x" as const,
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
              config,
            }: { seriesIndex: number; dataPointIndex: number; config: any },
          ) {
            const timestamp =
              chartContext.w.config.series[seriesIndex].data[dataPointIndex].x;
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
      dataLabels: { enabled: false },
      markers: { size: 0 },
      title: { text: "Timeline of events", align: "left" as const },
      fill: {
        type: "gradient",
        gradient: {
          shadeIntensity: 1,
          inverseColors: false,
          opacityFrom: 0.5,
          opacityTo: 0,
          stops: [0, 70, 80, 100],
        },
      },
      yaxis: {
        tickAmount: 4,
        labels: { formatter: (val: number) => val.toFixed(0) },
        title: { text: "Event Count" },
      },
      xaxis: {},
      tooltip: {
        shared: false,
        y: { formatter: (val: number) => val.toFixed(0) },
      },
    }),
    [seriesData],
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
          Build timeline
        </Button>
      </div>
    );
  }

  return (
    <Box sx={{ flexGrow: 1 }}>
      <Chart
        options={options}
        series={options.series}
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
