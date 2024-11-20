import React, { useState, useEffect } from "react";
import axiosInstance from "../../utils/axiosInstance";
import {
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Typography,
} from "@mui/material";
import * as Icons from "@mui/icons-material";

// Define the type for a plugin
interface Plugin {
  name: string;
  icon: string;
  category: string;
  description: string;
  results: boolean;
}

// Define the props type for the PluginList component
interface PluginListProps {
  evidenceId: string | number; // Adjust the type based on real usage
}

const PluginList: React.FC<PluginListProps> = ({ evidenceId }) => {
  const [plugins, setPlugins] = useState<Plugin[]>([]);

  useEffect(() => {
    // Fetch the list of plugins for the given evidence ID
    axiosInstance
      .get(`/api/evidence/${evidenceId}/plugins/`)
      .then((response) => {
        console.log(response);
        setPlugins(response.data);
      })
      .catch((error) => {
        console.error("Error fetching plugins:", error);
      });
  }, [evidenceId]);

  // Function to get the icon component by name
  const getIcon = (iconName: string) => {
    const IconComponent = Icons[iconName as keyof typeof Icons];
    if (IconComponent) {
      return <IconComponent />;
    }
    return <Icons.HelpOutline />;
  };

  return (
    <div style={{ maxHeight: "80vh", overflowY: "auto" }}>
      <List>
        {plugins.map((plugin) => (
          <ListItem key={plugin.name}>
            <ListItemIcon>{getIcon(plugin.icon)}</ListItemIcon>
            <ListItemText
              primary={plugin.name}
              secondary={
                <>
                  <Typography variant="body2" color="textSecondary">
                    Category: {plugin.category}
                  </Typography>
                  <Typography variant="body2" color="textPrimary">
                    {plugin.description}
                  </Typography>
                  <Typography
                    variant="body2"
                    style={{ color: plugin.results ? "green" : "red" }}
                  >
                    {plugin.results ? "Available" : "Unavailable"}
                  </Typography>
                </>
              }
            />
          </ListItem>
        ))}
      </List>
    </div>
  );
};

export default PluginList;
