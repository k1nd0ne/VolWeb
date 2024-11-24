import React, { useState, useEffect } from "react";
import axiosInstance from "../utils/axiosInstance";
import ReactApexChart from "react-apexcharts";
import { ApexOptions } from "apexcharts";
import { Box, CircularProgress } from "@mui/material";
import Grid from "@mui/material/Grid2";
import PluginList from "./Lists/PluginList";

interface EvidenceMetadataProps {
  evidenceId?: number;
  theme: "light" | "dark";
}

const EvidenceMetadata: React.FC<EvidenceMetadataProps> = ({
  evidenceId,
  theme,
}) => {
  const [data, setData] = useState<{
    categories: Record<string, number>;
    total_ran: number;
    total_results: number;
  } | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      if (!evidenceId) return;
      try {
        const response = await axiosInstance.get(
          `/api/evidence-statistics/${evidenceId}/`,
        );
        setData(response.data);
      } catch (error) {
        console.error("Error fetching data:", error);
      }
    };

    fetchData();
  }, [evidenceId]);

  if (!data) {
    return <CircularProgress />;
  }

  const categories = Object.keys(data.categories);
  const counts = Object.values(data.categories);

  const colors = ["#790909", "#670979", "#097979", "#097907"];
  const gradientToColors = ["#790909", "#670979", "#097979", "#097907"];

  const radarOptions: ApexOptions = {
    chart: {
      type: "radar",
      background: "transparent",
      foreColor: theme !== "dark" ? "#121212" : "#fff",
    },
    xaxis: {
      categories: categories,
      labels: {
        style: {
          colors: theme !== "dark" ? "#121212" : "#fff",
        },
      },
    },
    yaxis: {
      labels: {
        style: {
          colors: theme !== "dark" ? "#121212" : "#fff",
        },
      },
    },
    title: {
      text: "Results by Category",
      style: {
        color: theme !== "dark" ? "#101418" : "#fff",
      },
    },
    fill: {
      opacity: 0.1,
      colors: colors,
    },
    stroke: {
      colors: colors,
    },
    markers: {
      size: 4,
      colors: colors,
    },
    legend: {
      labels: {
        colors: theme !== "dark" ? "#101418" : "#fff",
      },
      markers: {
        fillColors: colors,
      },
    },
  };

  const radarSeries = [
    {
      name: "Results",
      data: counts,
    },
  ];

  const totalNoResults = data.total_ran - data.total_results;

  const donutOptions: ApexOptions = {
    labels: ["Plugins with Results", "Plugins without Results"],
    chart: {
      type: "donut",
      background: "transparent",
      foreColor: theme !== "dark" ? "#121212" : "#fff",
    },
    plotOptions: {
      pie: {
        startAngle: -90,
        endAngle: 270,
      },
    },
    dataLabels: {
      enabled: true,
    },
    fill: {
      type: "gradient",
      gradient: {
        gradientToColors: gradientToColors.slice(0, 2),
      },
      colors: colors.slice(0, 2),
    },
    legend: {
      formatter: function (
        val: string,
        opts: {
          seriesIndex: number;
          w: {
            globals: {
              series: number[];
            };
          };
        },
      ): string {
        return `${val} - ${opts.w.globals.series[opts.seriesIndex]}`;
      },
      labels: {
        colors: theme !== "dark" ? "#101418" : "#fff",
      },
      markers: {
        fillColors: colors.slice(0, 2),
      },
    },
    title: {
      text: "Plugins Ran vs Results",
      style: {
        color: theme !== "dark" ? "#101418" : "#fff",
      },
    },
    responsive: [
      {
        breakpoint: 480,
        options: {
          chart: {
            width: 100,
          },
          legend: {
            position: "bottom",
          },
        },
      },
    ],
  };

  const donutSeries: number[] = [data.total_results, totalNoResults];

  return (
    <Box sx={{ flexGrow: 1 }}>
      <Grid container spacing={2}>
        <Grid size={4}>
          <Grid container spacing={2}>
            <Grid size={12}>
              <PluginList evidenceId={evidenceId} />
            </Grid>
          </Grid>
        </Grid>
        <Grid size={8}>
          <Grid container spacing={2}>
            <Grid size={7}>
              <ReactApexChart
                options={radarOptions}
                series={radarSeries}
                type="radar"
              />
            </Grid>
            <Grid size={5}>
              <ReactApexChart
                options={donutOptions}
                series={donutSeries}
                type="donut"
              />
            </Grid>
          </Grid>
        </Grid>
      </Grid>
    </Box>
  );
};

export default EvidenceMetadata;
