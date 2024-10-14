import React, { useEffect, useState } from "react";
import Box from "@mui/material/Box";
import Grid from "@mui/material/Grid2";
import { Card, CardContent, Divider, Typography, Button } from "@mui/material";
import HomeRepairServiceIcon from "@mui/icons-material/HomeRepairService";
import { useParams } from "react-router-dom";
import axiosInstance from "../../utils/axiosInstance";

const PluginDashboard: React.FC = () => {
  interface Plugin {
    name: string;
    icon: string;
    description: string;
  }

  const { id } = useParams<{ id: string }>();
  const [plugins, setPlugins] = useState<Plugin[] | null>(null);

  useEffect(() => {
    const fetchCaseDetail = async () => {
      try {
        const response = await axiosInstance.get(
          `/api/evidence/${id}/plugins/`,
        );
        console.log(response.data);
        setPlugins(response.data);
      } catch (error) {
        console.error("Error fetching case details", error);
      }
    };

    fetchCaseDetail();
  }, [id]);

  return (
    <Box sx={{ flexGrow: 1 }}>
      <Card variant="outlined">
        <CardContent>
          <Typography
            gutterBottom
            sx={{
              color: "text.secondary",
              fontSize: 20,
              display: "flex",
              alignItems: "center",
            }}
          >
            <HomeRepairServiceIcon sx={{ marginRight: 1 }} />
            Tools
          </Typography>
          <Divider sx={{ marginBottom: 1 }} />
          <Grid container spacing={2}>
            {plugins &&
              plugins.map((plugin, _index) => (
                <Button
                  color="error"
                  value={plugin["name"]}
                  variant="outlined"
                  size="medium"
                >
                  {plugin["name"].split(".").at(-1)}
                </Button>
              ))}
          </Grid>
        </CardContent>
      </Card>
    </Box>
  );
};

export default PluginDashboard;
