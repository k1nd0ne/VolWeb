import React from "react";
import ReactApexChart from "react-apexcharts";
import { Card, CardContent } from "@mui/material";

interface LineChartProps {
  dates: string[];
  counts: number[];
  theme: "light" | "dark";
}

const LineChart: React.FC<LineChartProps> = ({ dates, counts, theme }) => {
  const state = {
    series: [
      {
        name: "Analysis Started",
        data: counts,
      },
    ],
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
      labels: dates,

      dataLabels: { enabled: false },
      chart: {
        background: "#121212",
        stacked: false,
        zoom: {
          enabled: true,
          autoScaleYaxis: true,
        },
        stroke: {
          curve: "smooth",
        },
        yaxis: {
          opposite: true,
          labels: {
            style: {
              colors: theme !== "dark" ? "#101418" : "#fff",
            },
          },
        },
      },
    },
  };

  return (
    <Card variant="outlined">
      <CardContent>
        <ReactApexChart
          options={state.options}
          series={state.series}
          type="area"
          height={228}
        />
      </CardContent>
    </Card>
  );
};

export default LineChart;
