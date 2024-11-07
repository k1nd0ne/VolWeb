import React from "react";
import ReactApexChart from "react-apexcharts";
import { Card, CardContent, Typography } from "@mui/material";

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
  const options = {
    series: [totalWindows, totalLinux],
    labels: ["Windows", "Linux"],
    chart: {
      width: 380,
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
      enabled: false,
    },
    fill: {
      type: "gradient",
      gradient: {
        gradientToColors: ["#790909", "#670979"],
      },
      colors: ["#790909", "#670979"],
    },
    legend: {
      formatter: function (val: string, opts: any) {
        return `${val} - ${opts.w.globals.series[opts.seriesIndex]}`;
      },
      labels: {
        colors: theme !== "dark" ? "#101418" : "#fff",
      },
      markers: {
        fillColors: ["#790909", "#670979"],
      },
    },
    title: {
      text: "Operating System Repartition",
      style: {
        color: theme !== "dark" ? "#101418" : "#fff",
      },
    },
    responsive: [
      {
        breakpoint: 480,
        options: {
          chart: {
            width: 200,
          },
          legend: {
            position: "bottom",
          },
        },
      },
    ],
  };

  const series = [totalWindows, totalLinux];

  return (
    <Card>
      <CardContent>
        <ReactApexChart
          options={options}
          series={series}
          type="donut"
          width={380}
        />
      </CardContent>
    </Card>
  );
};

export default DonutChart;
