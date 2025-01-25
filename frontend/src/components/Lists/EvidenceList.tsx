import { useEffect, useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { DataGrid, GridColDef, GridRenderCellParams } from "@mui/x-data-grid";
import axiosInstance from "../../utils/axiosInstance";
import { AxiosError } from "axios";
import EvidenceCreationDialog from "../Dialogs/EvidenceCreationDialog";
import LinearProgressWithLabel from "../LinearProgressBar";
import {
  Chip,
  IconButton,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  Button,
  Fab,
} from "@mui/material";
import {
  Add as AddIcon,
  Memory,
  DeviceHub,
  Biotech,
  DeleteSweep,
  Link,
  Delete as DeleteIcon,
  RestartAlt,
  Fingerprint,
} from "@mui/icons-material";
import BindEvidenceDialog from "../Dialogs/BindEvidenceDialog";
import { Evidence } from "../../types";
interface EvidenceListProps {
  caseId?: number;
}
import { useSnackbar } from "../SnackbarProvider";

function EvidenceList({ caseId }: EvidenceListProps) {
  const navigate = useNavigate();
  const [evidenceData, setEvidenceData] = useState<Evidence[]>([]);
  const [openDeleteDialog, setOpenDeleteDialog] = useState<boolean>(false);
  const [openRestartDialog, setOpenRestartDialog] = useState<boolean>(false);

  const [openCreationDialog, setOpenCreationDialog] = useState<boolean>(false);
  const [openBindingDialog, setOpenBindingDialog] = useState<boolean>(false);
  const [selectedEvidence, setSelectedEvidence] = useState<Evidence | null>(
    null,
  );
  const [checked, setChecked] = useState<number[]>([]);
  const [deleteMultiple, setDeleteMultiple] = useState(false);

  const { display_message } = useSnackbar();

  const [isConnected, setIsConnected] = useState(false);
  const ws = useRef<WebSocket | null>(null);
  const retryInterval = useRef<number | null>(null);

  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const port = window.location.port ? `:${window.location.port}` : "";
    const wsUrl = `${protocol}://${window.location.hostname}${port}/ws/evidences/${caseId ? `${caseId}/` : ""}`;

    const connectWebSocket = () => {
      ws.current = new WebSocket(wsUrl);

      ws.current.onopen = () => {
        console.log("WebSocket connected");
        setIsConnected(true);
        if (retryInterval.current) {
          clearInterval(retryInterval.current);
          retryInterval.current = null;
        }
      };

      ws.current.onclose = () => {
        console.log("WebSocket disconnected");
        setIsConnected(false);
        if (!retryInterval.current) {
          retryInterval.current = window.setTimeout(connectWebSocket, 5000);
          console.log("Attempting to reconnect to WebSocket...");
        }
      };

      ws.current.onmessage = (event) => {
        const data = JSON.parse(event.data);
        const status = data.status;
        const message = data.message;

        if (status === "created") {
          setEvidenceData((prevData) => {
            const exists = prevData.some(
              (evidence) => evidence.id === message.id,
            );
            if (exists) {
              return prevData.map((evidence) =>
                evidence.id === message.id ? message : evidence,
              );
            } else {
              return [...prevData, message];
            }
          });
        } else {
          setEvidenceData((prevData) =>
            prevData.filter((evidence) => evidence.id !== message.id),
          );
          setChecked((prevChecked) =>
            prevChecked.filter((id) => id !== message.id),
          );
        }
      };

      ws.current.onerror = (error) => {
        console.log("WebSocket error:", error);
      };
    };

    connectWebSocket();

    axiosInstance
      .get("/api/evidences/", { params: caseId ? { linked_case: caseId } : {} })
      .then((response) => {
        setEvidenceData(response.data);
      })
      .catch((error) => {
        display_message("error", `Error fetching evidence data: ${error}`);
        console.error("Error fetching evidence data:", error);
      });

    return () => {
      if (ws.current) {
        ws.current.close();
      }
      if (retryInterval.current) {
        clearInterval(retryInterval.current);
      }
    };
  }, [caseId, display_message]);

  const handleCreateSuccess = () => {
    display_message("success", "Evidence created.");
  };

  const handleCreateFailed = (error: unknown) => {
    console.log(error);
    display_message("success", "Evidence created.");

    display_message(
      "error",
      `Evidence could not be created: ${
        error instanceof AxiosError && error.response
          ? Object.entries(error.response.data)
              .map(([key, value]) => `${key}: ${value}`)
              .join(", ")
          : "Unknown error"
      }`,
    );
  };

  const handleBindSuccess = () => {
    display_message("success", "Evidence binded.");
  };

  const handleToggle = (id: number) => {
    navigate(`/evidences/${id}`);
  };

  const handleDeleteClick = (row: Evidence) => {
    setSelectedEvidence(row);
    setOpenDeleteDialog(true);
    setDeleteMultiple(false);
  };

  const handleRestartClick = (row: Evidence) => {
    setSelectedEvidence(row);
    setOpenRestartDialog(true);
  };

  const handleOpenDeleteMultipleDialog = () => {
    setDeleteMultiple(true);
    setOpenDeleteDialog(true);
  };

  const handleConfirmDelete = async () => {
    if (selectedEvidence && !deleteMultiple) {
      try {
        await axiosInstance.delete(`/api/evidences/${selectedEvidence.id}/`);
        display_message("success", "Evidence deleted.");
      } catch (error) {
        display_message("error", `Error deleting the evidence: ${error}`);
      } finally {
        setOpenDeleteDialog(false);
        setSelectedEvidence(null);
      }
    } else if (deleteMultiple) {
      handleDeleteSelected();
    }
  };

  const handleConfirmRestart = async () => {
    if (selectedEvidence) {
      const id: number = selectedEvidence.id;
      try {
        await axiosInstance.post(`/api/evidence/tasks/restart/`, { id });
        display_message("success", "Analysis restarted");
      } catch (error) {
        display_message("error", `Error restarting the analysis: ${error}`);
      } finally {
        setOpenRestartDialog(false);
      }
    }
  };

  const handleDeleteSelected = async () => {
    try {
      await Promise.all(
        checked.map((id) => axiosInstance.delete(`/api/evidences/${id}/`)),
      );
      display_message("success", "Selected evidences deleted.");
      setChecked([]);
    } catch (error) {
      display_message(
        "error",
        `Error deleting the selected evidence: ${error}`,
      );
    } finally {
      setOpenDeleteDialog(false);
    }
  };

  const columns: GridColDef[] = [
    {
      field: "name",
      headerName: "Evidence Name",
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
          <Memory style={{ marginRight: 8 }} color="info" />
          {params.value}
        </div>
      ),
      flex: 1,
    },
    {
      field: "os",
      headerName: "Operating System",
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
          <DeviceHub style={{ marginRight: 8 }} />
          {params.value}
        </div>
      ),
      flex: 1,
    },
    {
      field: "etag",
      headerName: "Identifier",
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
          <Fingerprint style={{ marginRight: 8 }} color="secondary" />
          {params.value}
        </div>
      ),
      flex: 1,
    },
    {
      field: "status",
      headerName: "Status",
      renderCell: (params: GridRenderCellParams) =>
        params.value === 100 ? (
          <div
            style={{ display: "flex", alignItems: "center", height: "100%" }}
          >
            <Chip
              label="success"
              size="small"
              color="success"
              variant="outlined"
            />
          </div>
        ) : params.value === -1 ? (
          <div
            style={{ display: "flex", alignItems: "center", height: "100%" }}
          >
            <Chip
              label="Unsatisfied requirements"
              size="small"
              color="error"
              variant="outlined"
            />
          </div>
        ) : (
          <div
            style={{ display: "flex", alignItems: "center", height: "100%" }}
          >
            <LinearProgressWithLabel value={Number(params.value)} />
          </div>
        ),
      flex: 1,
    },
    {
      field: "actions",
      headerName: "Actions",
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
          <Tooltip title="Investigate" placement="left">
            {params.row.status !== 100 ? (
              <IconButton edge="end" disabled={params.row.status !== 100}>
                <Biotech />
              </IconButton>
            ) : (
              <IconButton
                edge="end"
                aria-label="open"
                onClick={() => handleToggle(params.row.id)}
              >
                <Biotech />
              </IconButton>
            )}
          </Tooltip>
          <Tooltip title="Restart analysis" placement="right">
            <IconButton
              edge="end"
              aria-label="restart"
              onClick={() => handleRestartClick(params.row)}
            >
              <RestartAlt />
            </IconButton>
          </Tooltip>
          <Tooltip title="Delete" placement="right">
            {params.row.status !== 100 ? (
              <IconButton edge="end" disabled={params.row.status !== 100}>
                <DeleteSweep />
              </IconButton>
            ) : (
              <IconButton
                edge="end"
                aria-label="delete"
                onClick={() => handleDeleteClick(params.row)}
              >
                <DeleteSweep />
              </IconButton>
            )}
          </Tooltip>
        </div>
      ),
      flex: 1,
    },
  ];

  return (
    <>
      <Fab
        color="primary"
        aria-label="add"
        onClick={() => {
          setOpenCreationDialog(true);
        }}
        style={{ position: "fixed", bottom: "16px", right: "16px" }}
      >
        <AddIcon />
      </Fab>
      <EvidenceCreationDialog
        open={openCreationDialog}
        onClose={() => {
          setOpenCreationDialog(false);
        }}
        onCreateSuccess={handleCreateSuccess}
        onCreateFailed={handleCreateFailed}
        caseId={caseId}
      />
      <Fab
        color="secondary"
        aria-label="bind"
        onClick={() => {
          setOpenBindingDialog(true);
        }}
        style={{ position: "fixed", bottom: "16px", right: "80px" }}
      >
        <Link />
      </Fab>
      <BindEvidenceDialog
        open={openBindingDialog}
        onClose={() => {
          setOpenBindingDialog(false);
        }}
        onBindSuccess={handleBindSuccess}
        caseId={caseId}
      />
      <DataGrid
        rowHeight={40}
        disableRowSelectionOnClick
        rows={evidenceData}
        columns={columns}
        loading={!isConnected}
        checkboxSelection
        onRowSelectionModelChange={(newSelection) => {
          setChecked(newSelection as number[]);
        }}
      />
      {checked.length > 0 && (
        <Fab
          color="secondary"
          aria-label="delete"
          style={{ position: "fixed", bottom: 80, right: 16 }}
          onClick={handleOpenDeleteMultipleDialog}
        >
          <DeleteIcon />
        </Fab>
      )}
      <Dialog
        open={openDeleteDialog}
        onClose={() => setOpenDeleteDialog(false)}
        aria-labelledby="alert-dialog-title"
        aria-describedby="alert-dialog-description"
      >
        <DialogTitle id="alert-dialog-title">{`Delete ${
          deleteMultiple ? "Selected Evidences" : "Evidence"
        }`}</DialogTitle>
        <DialogContent>
          <DialogContentText id="alert-dialog-description">
            {`Are you sure you want to delete ${
              deleteMultiple ? "these evidences" : "this evidence"
            }?`}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenDeleteDialog(false)} color="primary">
            Cancel
          </Button>
          <Button onClick={handleConfirmDelete} color="primary" autoFocus>
            Yes
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog
        open={openRestartDialog}
        onClose={() => setOpenRestartDialog(false)}
        aria-labelledby="alert-dialog-title"
        aria-describedby="alert-dialog-description"
      >
        <DialogTitle id="alert-dialog-title">Restart the analysis</DialogTitle>
        <DialogContent>
          <DialogContentText id="alert-dialog-description">
            You are about to restart the analysis, confirm ?
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenRestartDialog(false)} color="primary">
            Cancel
          </Button>
          <Button onClick={handleConfirmRestart} color="primary" autoFocus>
            Restart
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}

export default EvidenceList;
