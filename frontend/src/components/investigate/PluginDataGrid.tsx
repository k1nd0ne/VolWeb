import React, { useEffect, useState } from "react";
import { Box, Button } from "@mui/material";
import {
  DataGrid,
  GridColDef,
  GridToolbar,
  useGridApiRef,
} from "@mui/x-data-grid";
import { useParams } from "react-router-dom";
import axiosInstance from "../../utils/axiosInstance";
import Checkbox from "@mui/material/Checkbox";
import CloseIcon from "@mui/icons-material/Close";
import IconButton from "@mui/material/IconButton";
import { Artefact } from "../../types";

interface PluginDataGridProps {
  pluginName: string;
}

const PluginDataGrid: React.FC<PluginDataGridProps> = ({ pluginName }) => {
  const { id } = useParams<{ id: string }>();
  const [data, setData] = useState<Artefact[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const apiRef = useGridApiRef();

  const columns: GridColDef[] = data[0]
    ? Object.keys(data[0])
        .filter((key) => key !== "__children" && key !== "id") // Filter out the "id" and "__children" column
        .map((key) => ({
          field: key,
          headerName: key,
          renderCell: (params) =>
            typeof params.value === "boolean" ? (
              params.value ? (
                <Checkbox checked={true} color="success" />
              ) : (
                <IconButton color="error">
                  <CloseIcon />
                </IconButton>
              )
            ) : params.value !== null ? (
              params.value
            ) : (
              ""
            ),
        }))
    : [];

  const autosizeOptions = {
    columns: [...columns].map((col) => col.headerName ?? ""),
    includeOutliers: true,
    includeHeaders: true,
  };

  useEffect(() => {
    const fetchPlugins = async () => {
      try {
        const response = await axiosInstance.get(
          `/api/evidence/${id}/plugin/${pluginName}`,
        );
        // Assign consistent unique IDs to each row and flatten children
        const artefactsWithId: Artefact[] = [];
        response.data.artefacts.forEach((artefact: Artefact, index: number) => {
          artefactsWithId.push({ ...artefact, id: index });
          if (artefact.__children && artefact.__children.length) {
            artefact.__children.map((child: Artefact, idx: number) => {
              artefactsWithId.push({ ...child, id: `${index}-${idx}` });
            });
          }
        });

        setData(artefactsWithId);
      } catch (error) {
        console.error("Error fetching case details", error);
      } finally {
        setLoading(false);
      }
    };

    fetchPlugins();
  }, [id, pluginName]);

  // Add this useEffect to call autosizeColumns after the data is loaded
  useEffect(() => {
    if (!loading && data.length > 0) {
      const timeoutId = setTimeout(() => {
        if (apiRef.current) {
          apiRef.current.autosizeColumns(autosizeOptions);
        }
      }, 200); // Delay to ensure DataGrid has rendered
      return () => clearTimeout(timeoutId);
    }
  }, [loading, data]);

  return (
    <Box sx={{ flexGrow: 1, p: 1 }}>
      <DataGrid
        disableDensitySelector
        autoPageSize
        slots={{
          toolbar: GridToolbar,
        }}
        slotProps={{
          toolbar: {
            showQuickFilter: true,
          },
        }}
        rows={data}
        density="compact"
        sx={{ height: "90vh" }}
        columns={columns}
        getRowId={(row) => row.id}
        pagination
        loading={loading}
        autosizeOnMount
        autosizeOptions={autosizeOptions}
        apiRef={apiRef}
      />
      <Button
        variant="outlined"
        onClick={() => apiRef.current.autosizeColumns(autosizeOptions)}
      >
        Autosize columns
      </Button>
    </Box>
  );
};

export default PluginDataGrid;
