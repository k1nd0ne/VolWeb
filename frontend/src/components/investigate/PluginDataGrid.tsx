import React, { useEffect, useState } from "react";
import Box from "@mui/material/Box";
import { DataGrid, GridColDef, GridToolbar } from "@mui/x-data-grid";
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

    useEffect(() => {
        const fetchPlugins = async () => {
            try {
                const response = await axiosInstance.get(
                    `/api/evidence/${id}/plugin/${pluginName}`,
                );
                // Assign consistent unique IDs to each row
                const artefactsWithId = response.data.artefacts.map(
                    (artefact: Artefact, index: number) => ({
                        ...artefact,
                        id: index,
                    }),
                );
                setData(artefactsWithId);
            } catch (error) {
                console.error("Error fetching case details", error);
            } finally {
                setLoading(false);
            }
        };

        fetchPlugins();
    }, [id, pluginName]);

    const columns: GridColDef[] = data[0]
        ? Object.keys(data[0])
              .filter((key) => key !== "__children" && key !== "id") // Filter out the "id" column
              .map((key) => ({
                  field: key,
                  headerName: key,
                  display: "flex",
                  flex: 1,
                  sortable: true,
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

    return (
        <Box sx={{ flexGrow: 1, p: 1 }}>
            <DataGrid
                disableDensitySelector
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
            />
        </Box>
    );
};

export default PluginDataGrid;
