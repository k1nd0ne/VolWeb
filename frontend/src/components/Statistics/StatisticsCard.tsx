import React from "react";
import { Card, CardContent, Typography } from "@mui/material";

interface StatisticsCardProps {
  title: string;
  value: number;
}

const StatisticsCard: React.FC<StatisticsCardProps> = ({ title, value }) => {
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6" gutterBottom>
          {title}
        </Typography>
        <Typography variant="h4">{value}</Typography>
      </CardContent>
    </Card>
  );
};

export default StatisticsCard;
