import React from "react";
import ReactApexChart from "react-apexcharts";
import { Card, CardContent } from "@mui/material";

interface DonutChartProps {
  totalWindows: number;
  totalLinux: number;
  theme: "light" | "dark";
}

const DonutChart: React.FC<DonutChartProps> = ({
  totalWindows,
  totalLinux,
  theme,
}) => {
  const state = {
    series: [totalWindows, totalLinux],
    options: {
      chart: {
        width: 380,
        background: "transparent",
        foreColor: theme !== "dark" ? "#121212" : "#fff",
      },
      labels: ["Windows", "Linux"],
      dataLabels: {
        enabled: true,
      },
      fill: {
        type: "gradient",
        gradient: {
          gradientToColors: ["#790909", "#670979"],
        },
        colors: ["#790909", "#670979"],
      },
      title: {
        text: "Operating System Repartition",
        style: {
          color: theme !== "dark" ? "#101418" : "#fff",
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
          type="donut"
          width={380}
        />
      </CardContent>
    </Card>
  );
};

export default DonutChart;
