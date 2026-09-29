import React, { useCallback, useEffect, useState } from "react";
import {
  Box,
  Button,
  CircularProgress,
  IconButton,
  Tooltip,
  Typography,
} from "@mui/material";
import { DataGrid, GridColDef, GridToolbar } from "@mui/x-data-grid";
import { Download, Delete } from "@mui/icons-material";
import { useParams } from "react-router-dom";
import axiosInstance from "../../utils/axiosInstance";
import { downloadFile } from "../../utils/downloadFile";
import { useSnackbar } from "../SnackbarProvider";

interface LootArtefact {
  name: string;
  size: number;
  modified: string;
  url: string;
}

const formatBytes = (bytes: number): string => {
  if (!bytes) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1,
  );
  return `${(bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
};

const Loot: React.FC = () => {
  const { id: evidenceId } = useParams<{ id: string }>();
  const { display_message } = useSnackbar();

  const [artefacts, setArtefacts] = useState<LootArtefact[]>([]);
  const [totalSize, setTotalSize] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [busy, setBusy] = useState<{ [name: string]: boolean }>({});

  const fetchLoot = useCallback(async () => {
    try {
      const response = await axiosInstance.get(
        `/api/evidence/${evidenceId}/loot/`,
      );
      setArtefacts(response.data.artefacts || []);
      setTotalSize(response.data.total_size || 0);
    } catch (error) {
      console.error("Error fetching loot", error);
      display_message("error", `Error fetching loot: ${error}`);
    } finally {
      setLoading(false);
    }
  }, [evidenceId, display_message]);

  useEffect(() => {
    fetchLoot();
  }, [fetchLoot]);

  const handleDelete = async (name: string) => {
    setBusy((prev) => ({ ...prev, [name]: true }));
    try {
      await axiosInstance.delete(`/api/evidence/${evidenceId}/loot/`, {
        data: { name },
      });
      display_message("success", `${name} deleted.`);
      await fetchLoot();
    } catch (error) {
      console.error("Error deleting artefact", error);
      display_message("error", `Error deleting ${name}: ${error}`);
    } finally {
      setBusy((prev) => ({ ...prev, [name]: false }));
    }
  };

  const columns: GridColDef[] = [
    { field: "name", headerName: "Name", flex: 2 },
    {
      field: "size",
      headerName: "Size",
      flex: 1,
      renderCell: (params) => formatBytes(params.value as number),
    },
    {
      field: "modified",
      headerName: "Extracted",
      flex: 1,
      renderCell: (params) =>
        params.value ? new Date(params.value as string).toLocaleString() : "",
    },
    {
      field: "actions",
      headerName: "Actions",
      sortable: false,
      filterable: false,
      flex: 1,
      renderCell: (params) => {
        const row = params.row as LootArtefact;
        const isBusy = busy[row.name];
        return (
          <Box>
            <Tooltip title="Download" arrow>
              <span>
                <IconButton
                  color="primary"
                  size="small"
                  disabled={isBusy}
                  onClick={() => downloadFile(row.url, row.name)}
                >
                  <Download fontSize="small" />
                </IconButton>
              </span>
            </Tooltip>
            <Tooltip title="Delete from disk" arrow>
              <span>
                <IconButton
                  color="error"
                  size="small"
                  disabled={isBusy}
                  onClick={() => handleDelete(row.name)}
                >
                  {isBusy ? (
                    <CircularProgress size={18} />
                  ) : (
                    <Delete fontSize="small" />
                  )}
                </IconButton>
              </span>
            </Tooltip>
          </Box>
        );
      },
    },
  ];

  if (loading) {
    return (
      <Box sx={{ display: "flex", justifyContent: "center", mt: 4 }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Box
        sx={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          mb: 1,
        }}
      >
        <Typography variant="body2" color="text.secondary">
          {artefacts.length} artefact{artefacts.length === 1 ? "" : "s"} on disk
          {" · "}
          {formatBytes(totalSize)}
        </Typography>
        <Button size="small" onClick={fetchLoot}>
          Refresh
        </Button>
      </Box>
      {artefacts.length === 0 ? (
        <Typography
          variant="body2"
          color="text.secondary"
          sx={{ mt: 4, textAlign: "center" }}
        >
          No artefacts have been dumped for this evidence yet.
        </Typography>
      ) : (
        <DataGrid
          disableDensitySelector
          slots={{ toolbar: GridToolbar }}
          slotProps={{ toolbar: { showQuickFilter: true } }}
          sx={{ height: "70vh" }}
          rows={artefacts}
          columns={columns}
          getRowId={(row) => row.name}
          pagination
          showToolbar
          getRowHeight={() => "auto"}
        />
      )}
    </Box>
  );
};

export default Loot;
