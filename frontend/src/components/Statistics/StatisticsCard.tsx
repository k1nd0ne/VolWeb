import React from "react";
import { Card, CardContent, Typography, Box } from "@mui/material";

interface StatisticsCardProps {
  title: string;
  value: number;
  icon: React.ReactNode; // Accepts a React node for the icon
}

const StatisticsCard: React.FC<StatisticsCardProps> = ({
  title,
  value,
  icon,
}) => {
  return (
    <Card variant="outlined">
      <CardContent>
        <Box display="flex" alignItems="center" marginBottom={1}>
          <Box marginRight={2}>{icon}</Box>
          <Typography variant="h6" gutterBottom>
            {title}
          </Typography>
        </Box>
        <Typography variant="h4">{value}</Typography>
      </CardContent>
    </Card>
  );
};

export default StatisticsCard;
