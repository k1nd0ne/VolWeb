import React, { useEffect, useState } from "react";
import Box from "@mui/material/Box";
import Grid from "@mui/material/Grid2";
import {
  Card,
  CardContent,
  Divider,
  Typography,
  Button,
  Dialog,
  DialogTitle,
  IconButton,
  DialogContent,
} from "@mui/material";
import HomeRepairServiceIcon from "@mui/icons-material/HomeRepairService";
import CloseIcon from "@mui/icons-material/Close";
import { useParams } from "react-router-dom";
import axiosInstance from "../../utils/axiosInstance";
import * as Icons from "@mui/icons-material";
import PluginDatatable from "./PluginDatatable";

const PluginDashboard: React.FC = () => {
  interface Plugin {
    name: string;
    icon: string;
    description: string;
  }

  const { id } = useParams<{ id: string }>();
  const [plugins, setPlugins] = useState<Plugin[] | null>(null);
  const [open, setOpen] = useState(false);
  const [currentPlugin, setCurrentPlugin] = useState<Plugin | null>(null);

  const handleClickOpen = (plugin: Plugin) => {
    setCurrentPlugin(plugin);
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
    setCurrentPlugin(null);
  };

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
              plugins.map((plugin) => {
                const iconName = plugin.icon; // e.g., 'Info', 'AccountTree', etc.
                const IconComponent = Icons[iconName];
                return (
                  <Button
                    color="error"
                    key={plugin["name"]}
                    value={plugin["name"]}
                    variant="outlined"
                    size="small"
                    onClick={() => handleClickOpen(plugin)}
                    startIcon={<IconComponent />}
                  >
                    {plugin["name"].split(".").pop()}
                  </Button>
                );
              })}
          </Grid>
        </CardContent>
      </Card>
      <Dialog
        fullScreen
        open={open}
        onClose={handleClose}
        sx={{
          //You can copy the code below in your theme
          "& .MuiPaper-root": {
            background: "#121212",
          },
          "& .MuiBackdrop-root": {
            backgroundColor: "transparent", // Try to remove this to see the result
          },
        }}
      >
        <DialogTitle>
          {currentPlugin ? currentPlugin.name : ""}
          <IconButton
            edge="end"
            color="inherit"
            onClick={handleClose}
            aria-label="close"
            sx={{ position: "absolute", right: 8, top: 8 }}
          >
            <CloseIcon />
          </IconButton>
        </DialogTitle>
        <DialogContent>
          <PluginDatatable
            pluginName={currentPlugin ? currentPlugin.name : ""}
          />
        </DialogContent>
      </Dialog>
    </Box>
  );
};

export default PluginDashboard;
