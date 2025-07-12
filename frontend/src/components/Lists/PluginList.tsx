import React, { useState, useEffect } from "react";
import axiosInstance from "../../utils/axiosInstance";
import {
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Typography,
  Box,
} from "@mui/material";
import * as Icons from "@mui/icons-material";
import { Plugin } from "../../types";
import { useSnackbar } from "../SnackbarProvider";

interface PluginListProps {
  evidenceId?: string;
}

const PluginList: React.FC<PluginListProps> = ({ evidenceId }) => {
  const [plugins, setPlugins] = useState<Plugin[]>([]);
  const { display_message } = useSnackbar();

  useEffect(() => {
    axiosInstance
      .get(`/api/evidence/${evidenceId}/plugins/`)
      .then((response) => {
        setPlugins(response.data);
      })
      .catch((error) => {
        display_message("error", `Error fetching plugins: ${error}`);
        console.error("Error fetching plugins", error);
      });
  }, [evidenceId, display_message]);

  // Function to get the icon component by name
  const getIcon = (iconName: string) => {
    const IconComponent = Icons[iconName as keyof typeof Icons];
    if (IconComponent) {
      return <IconComponent />;
    }
    return <Icons.HelpOutline />;
  };

  return (
    <Box style={{ maxHeight: "85vh", overflowY: "auto", overflowX: "hidden" }}>
      <List>
        {plugins.map((plugin) => (
          <ListItem key={plugin.name}>
            <ListItemIcon>{getIcon(plugin.icon)}</ListItemIcon>
            <ListItemText
              primary={plugin.name}
              secondary={
                <React.Fragment>
                  <Typography
                    component="span"
                    variant="body2"
                    sx={{ color: "text.secondary", display: "block" }}
                  >
                    Category: {plugin.category}
                  </Typography>
                  <Typography
                    component="span"
                    variant="caption"
                    sx={{ color: "text.primary", display: "block" }}
                  >
                    {plugin.description}
                  </Typography>
                  <Typography
                    component="span"
                    variant="body2"
                    sx={{
                      color: plugin.results ? "green" : "red",
                      display: "block",
                    }}
                  >
                    {plugin.results ? "Available" : "Unavailable"}
                  </Typography>
                </React.Fragment>
              }
            />
          </ListItem>
        ))}
      </List>
    </Box>
  );
};

export default PluginList;
