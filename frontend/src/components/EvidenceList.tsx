import { useEffect, useState } from "react";
import DataTable, { createTheme } from "react-data-table-component";
import { useNavigate } from "react-router-dom";
import axiosInstance from "../utils/axiosInstance";
import EvidenceCreationDialog from "./EvidenceCreationDialog";
import AddIcon from "@mui/icons-material/Add";
import Memory from "@mui/icons-material/Memory";
import DeviceHub from "@mui/icons-material/DeviceHub";
import MessageHandler from "./MessageHandler";
import LinearProgressWithLabel from "./LinearProgressBar";
import Chip from "@mui/material/Chip";
import {
  IconButton,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  Button,
} from "@mui/material";
import { Biotech } from "@mui/icons-material";
import DeleteSweep from "@mui/icons-material/DeleteSweep";
import Fab from "@mui/material/Fab";
import DeleteIcon from "@mui/icons-material/Delete";

createTheme(
  "mui",
  {
    text: {
      primary: "#fff",
      secondary: "rgba(255, 255, 255, 0.7)",
    },
    background: {
      default: "#121212",
    },
    context: {
      background: "#121212",
      text: "#FFFFFF",
    },
    divider: {
      default: "rgba(255, 255, 255, 0.12)",
    },
    button: {
      default: "#fff",
      hover: "rgba(255, 255, 255, 0.08)",
      focus: "rgba(255, 255, 255, 0.16)",
      disabled: "rgba(255, 255, 255, 0.12)",
    },
  },
  "dark",
);

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
    // eslint-disable-next-line react-hooks/exhaustive-deps
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

  const columns = [
    {
      name: "Evidence Name",
      selector: (row: Evidence) => (
        <div style={{ display: "flex", alignItems: "center" }}>
          <Memory style={{ marginRight: 8 }} />
          {row.name}
        </div>
      ),
      sortable: true,
    },
    {
      name: "Operating System",
      selector: (row: Evidence) => (
        <div style={{ display: "flex", alignItems: "center" }}>
          <DeviceHub style={{ marginRight: 8 }} />
          {row.os}
        </div>
      ),
      sortable: true,
    },
    {
      name: "Status",
      selector: (row: Evidence) =>
        row.status !== 100 ? (
          <LinearProgressWithLabel value={row.status} />
        ) : (
          <Chip
            label="success"
            size="small"
            color="success"
            variant="outlined"
          />
        ),
      ignoreRowClick: true,
      allowoverflow: true,
    },
    {
      name: "Actions",
      cell: (row: Evidence) => (
        <>
          <Tooltip title="Review Investigation">
            <IconButton
              edge="end"
              aria-label="open"
              onClick={() => handleToggle(row.id)}
            >
              <Biotech />
            </IconButton>
          </Tooltip>
          <Tooltip title="Delete Evidence">
            <IconButton
              edge="end"
              aria-label="delete"
              onClick={() => handleDeleteClick(row)}
            >
              <DeleteSweep />
            </IconButton>
          </Tooltip>
        </>
      ),
      ignoreRowClick: true,
      allowoverflow: true,
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
      <DataTable
        title="Evidences"
        theme="mui"
        columns={columns}
        data={evidenceData}
        pagination
        selectableRows
        onSelectedRowsChange={({ selectedRows }) => {
          const selectedIds = selectedRows.map((row: Evidence) => row.id);
          setChecked(selectedIds);
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
