import React from "react";
import ReactApexChart from "react-apexcharts";
import { Card, CardContent } from "@mui/material";

interface LineChartProps {
  dates: string[];
  counts: number[];
  theme: "light" | "dark";
}

const LineChart: React.FC<LineChartProps> = ({ dates, counts, theme }) => {
  const options = {
    theme: {
      mode: theme,
      palette: "palette1",
      monochrome: {
        enabled: true,
        color: "#9a0000",
        shadeTo: "light",
        shadeIntensity: 0.65,
      },
    },
    series: [
      {
        name: "Analysis Started",
        data: counts,
      },
    ],
    chart: {
      type: "area",
      height: 350,
      zoom: {
        enabled: false,
      },
      background: "transparent",
      foreColor: theme !== "dark" ? "#101418" : "#fff",
    },
    dataLabels: {
      enabled: false,
    },
    stroke: {
      curve: "smooth",
    },
    title: {
      text: "Analysis",
      align: "left",
      style: {
        color: theme !== "dark" ? "#101418" : "#fff",
      },
    },
    subtitle: {
      text: "Started analysis in time",
      align: "left",
      style: {
        color: theme !== "dark" ? "#101418" : "#fff",
      },
    },
    labels: dates,
    yaxis: {
      opposite: true,
      labels: {
        style: {
          colors: theme !== "dark" ? "#101418" : "#fff",
        },
      },
    },
    xaxis: {
      labels: {
        style: {
          colors: theme !== "dark" ? "#101418" : "#fff",
        },
      },
    },
    legend: {
      horizontalAlign: "left",
      labels: {
        colors: theme !== "dark" ? "#101418" : "#fff",
      },
    },
  };

  const series = [
    {
      name: "Analysis Started",
      data: counts,
    },
  ];

  return (
    <Card variant="outlined">
      <CardContent>
        <ReactApexChart
          options={options}
          series={series}
          type="area"
          height={228}
        />
      </CardContent>
    </Card>
  );
};

export default LineChart;
