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
  CircularProgress,
  Tooltip,
} from "@mui/material";
import * as Icons from "@mui/icons-material";
import { HomeRepairService, Close } from "@mui/icons-material";
import { useParams } from "react-router-dom";
import axiosInstance from "../../utils/axiosInstance";
import PluginDataGrid from "./PluginDataGrid";
import { Plugin } from "../../types";
import MalfindButton from "./windows/buttons/MalfindButton";
import FilescanButton from "./windows/buttons/FilescanButton";
import NetGraphButton from "./windows/buttons/NetGraphButton";
const PluginDashboard: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [plugins, setPlugins] = useState<Plugin[] | null>(null);
  const [open, setOpen] = useState(false);
  const [currentPlugin, setCurrentPlugin] = useState<Plugin | null>(null);
  const [loading, setLoading] = useState(true); // State to track loading

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
        setPlugins(response.data);
      } catch (error) {
        console.error("Error fetching case details", error);
      } finally {
        setLoading(false); // Set loading to false after fetch attempt
      }
    };

    fetchCaseDetail();
  }, [id]);

  // Group plugins by category
  const groupedPlugins = plugins
    ? plugins.reduce((groups: { [key: string]: Plugin[] }, plugin) => {
        if (plugin.display === "True") {
          const category = plugin.category || "Uncategorized";
          if (!groups[category]) {
            groups[category] = [];
          }
          groups[category].push(plugin);
        }
        return groups;
      }, {})
    : {};

  // Map each category to a specific color
  const categoryColors: {
    [key: string]:
      | "primary"
      | "secondary"
      | "success"
      | "warning"
      | "error"
      | "info";
  } = {
    Malware: "primary",
    Processes: "secondary",
    Security: "success",
    Kernel: "warning",
    Filesystem: "error",
    Network: "info",
    Registry: "primary",
    Uncategorized: "info",
  };

  return (
    <Box sx={{ flexGrow: 1 }}>
      {loading ? (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 2 }}>
          <CircularProgress />
        </Box>
      ) : (
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
              <HomeRepairService sx={{ marginRight: 1 }} />
              Tools
            </Typography>
            <Divider sx={{ marginBottom: 1 }} />
            <Grid container spacing={1}>
              {Object.keys(groupedPlugins).map((category) => (
                <Grid size={12} key={category}>
                  <Typography
                    variant="subtitle1"
                    color="textSecondary"
                    sx={{ marginBottom: 1 }}
                  >
                    {category}
                  </Typography>
                  <Grid container spacing={1}>
                    {/* Here we insert our custom components */}
                    {category === "Filesystem" && <FilescanButton />}
                    {category === "Malware" && <MalfindButton />}
                    {category === "Network" && <NetGraphButton />}
                    {groupedPlugins[category].map((plugin) => {
                      const iconName = plugin.icon;
                      const IconComponent =
                        Icons[iconName as keyof typeof Icons];
                      const buttonColor = categoryColors[category] || "info"; // Use mapped color or default

                      return (
                        <Tooltip
                          title={plugin.results ? plugin.description : ""}
                          arrow
                          key={plugin.name}
                          placement="top"
                          disableHoverListener={!plugin.results}
                        >
                          <span>
                            <Button
                              color={buttonColor}
                              value={plugin.name}
                              variant="outlined"
                              size="small"
                              onClick={() => handleClickOpen(plugin)}
                              startIcon={
                                IconComponent ? <IconComponent /> : null
                              }
                              sx={{
                                marginRight: 1,
                                marginBottom: 1,
                              }}
                              disabled={!plugin.results}
                            >
                              {plugin.name.split(".").pop()}
                            </Button>
                          </span>
                        </Tooltip>
                      );
                    })}
                  </Grid>
                </Grid>
              ))}
            </Grid>
          </CardContent>
        </Card>
      )}
      <Dialog
        fullWidth
        maxWidth="xl"
        open={open}
        onClose={handleClose}
        sx={{
          "& .MuiPaper-root": {
            background: "#121212",
          },
          "& .MuiBackdrop-root": {
            backgroundColor: "transparent",
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
            <Close />
          </IconButton>
        </DialogTitle>
        <DialogContent>
          <PluginDataGrid
            pluginName={currentPlugin ? currentPlugin.name : ""}
          />
        </DialogContent>
      </Dialog>
    </Box>
  );
};

export default PluginDashboard;
