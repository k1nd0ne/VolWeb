import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { DataGrid, GridColDef, GridRenderCellParams } from "@mui/x-data-grid";
import axiosInstance from "../../utils/axiosInstance";
import EvidenceCreationDialog from "../Dialogs/EvidenceCreationDialog";
import MessageHandler from "../MessageHandler";
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
  Delete as DeleteIcon,
} from "@mui/icons-material";

interface Evidence {
  id: number;
  name: string;
  os: string;
  status: number;
}

interface EvidenceListProps {
  evidences: Evidence[];
}

function EvidenceList({ evidences }: EvidenceListProps) {
  const navigate = useNavigate();
  const [evidenceData, setEvidenceData] = useState<Evidence[]>(evidences);
  const [openDeleteDialog, setOpenDeleteDialog] = useState<boolean>(false);
  const [openCreationDialog, setOpenCreationDialog] = useState<boolean>(false);
  const [selectedEvidence, setSelectedEvidence] = useState<Evidence | null>(
    null,
  );
  const [checked, setChecked] = useState<number[]>([]);
  const [deleteMultiple, setDeleteMultiple] = useState(false);
  const [messageHandlerOpen, setMessageHandlerOpen] = useState<boolean>(false);
  const [messageHandlerMessage, setMessageHandlerMessage] =
    useState<string>("");
  const [messageHandlerSeverity, setMessageHandlerSeverity] = useState<
    "success" | "error"
  >("success");

  useEffect(() => {
    setEvidenceData(evidences);
  }, [evidences]);

  const handleCreateSuccess = (newEvidence: Evidence) => {
    setMessageHandlerMessage("Evidence created successfully");
    setMessageHandlerSeverity("success");
    setEvidenceData([...evidenceData, newEvidence]);
  };

  const handleToggle = (id: number) => {
    navigate(`/evidences/${id}`);
  };

  const handleDeleteClick = (row: Evidence) => {
    setSelectedEvidence(row);
    setOpenDeleteDialog(true);
    setDeleteMultiple(false);
  };

  const handleOpenDeleteMultipleDialog = () => {
    setDeleteMultiple(true);
    setOpenDeleteDialog(true);
  };

  const handleConfirmDelete = async () => {
    if (selectedEvidence && !deleteMultiple) {
      try {
        await axiosInstance.delete(`/api/evidences/${selectedEvidence.id}/`);
        setMessageHandlerMessage("Evidence deleted successfully");
        setMessageHandlerSeverity("success");
        setEvidenceData((prevData) =>
          prevData.filter((evidence) => evidence.id !== selectedEvidence.id),
        );
      } catch {
        setMessageHandlerMessage("Error deleting evidence");
        setMessageHandlerSeverity("error");
      } finally {
        setMessageHandlerOpen(true);
        setOpenDeleteDialog(false);
        setSelectedEvidence(null);
      }
    } else if (deleteMultiple) {
      handleDeleteSelected();
    }
  };

  const handleDeleteSelected = async () => {
    try {
      await Promise.all(
        checked.map((id) => axiosInstance.delete(`/api/evidences/${id}/`)),
      );
      setMessageHandlerMessage("Selected evidences deleted successfully");
      setMessageHandlerSeverity("success");
      setEvidenceData((prevData) =>
        prevData.filter((evidence) => !checked.includes(evidence.id)),
      );
      setChecked([]);
    } catch {
      setMessageHandlerMessage("Error deleting selected evidences");
      setMessageHandlerSeverity("error");
    } finally {
      setMessageHandlerOpen(true);
      setOpenDeleteDialog(false);
    }
  };

  const columns: GridColDef[] = [
    {
      field: "name",
      headerName: "Evidence Name",
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
          <Memory style={{ marginRight: 8 }} />
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
      field: "status",
      headerName: "Status",
      renderCell: (params: GridRenderCellParams) =>
        params.value !== 100 ? (
          <div
            style={{ display: "flex", alignItems: "center", height: "100%" }}
          >
            <LinearProgressWithLabel value={Number(params.value)} />
          </div>
        ) : (
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
        ),
      flex: 1,
    },
    {
      field: "actions",
      headerName: "Actions",
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
          <Tooltip title="Investigate">
            <IconButton
              edge="end"
              aria-label="open"
              onClick={() => handleToggle(params.row.id)}
            >
              <Biotech />
            </IconButton>
          </Tooltip>
          <Tooltip title="Delete">
            <IconButton
              edge="end"
              aria-label="delete"
              onClick={() => handleDeleteClick(params.row)}
            >
              <DeleteSweep />
            </IconButton>
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
      />
      <DataGrid
        rowHeight={40}
        disableRowSelectionOnClick
        rows={evidenceData}
        columns={columns}
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
      <MessageHandler
        open={messageHandlerOpen}
        message={messageHandlerMessage}
        severity={messageHandlerSeverity}
        onClose={() => setMessageHandlerOpen(false)}
      />
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
    </>
  );
}

export default EvidenceList;
