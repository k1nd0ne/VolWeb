import React, { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { DataGrid, GridColDef, GridRenderCellParams } from "@mui/x-data-grid";
import {
  IconButton,
  Chip,
  Snackbar,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  Button,
  Alert,
  Tooltip,
  Fab,
} from "@mui/material";
import {
  Biotech,
  DeleteSweep,
  Work,
  Info,
  CalendarToday,
  Add as AddIcon,
  Delete as DeleteIcon,
} from "@mui/icons-material";
import axiosInstance from "../../utils/axiosInstance";
import AddCaseDialog from "../Dialogs/CaseCreationDialog";
import { Case } from "../../types";

function CaseList() {
  const navigate = useNavigate();
  const [checked, setChecked] = useState<number[]>([]);
  const [openDialog, setOpenDialog] = useState(false);
  const [selectedCase, setSelectedCase] = useState<Case | null>(null);
  const [openSnackbar, setOpenSnackbar] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState("");
  const [snackbarSeverity, setSnackbarSeverity] = useState<"success" | "error">(
    "success",
  );
  const [caseDialogOpen, setCaseDialogOpen] = useState(false);
  const [caseData, setCaseData] = useState<Case[]>([]);
  const [deleteMultiple, setDeleteMultiple] = useState(false);

  // WebSocket related state
  const [isConnected, setIsConnected] = useState(false);
  const ws = useRef<WebSocket | null>(null);

  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const wsUrl = `${protocol}://localhost:8000/ws/cases/`;
    ws.current = new WebSocket(wsUrl);

    ws.current.onopen = () => {
      console.log("WebSocket connected");
      setIsConnected(true);
    };

    ws.current.onclose = () => {
      console.log("WebSocket disconnected");
      setIsConnected(false);
    };

    ws.current.onmessage = (event) => {
      const data = JSON.parse(event.data);
      const status = data.status;
      const message = data.message;

      if (status === "created") {
        setCaseData((prevData) => [...prevData, message]);
      } else if (status === "updated") {
        setCaseData((prevData) =>
          prevData.map((caseItem) =>
            caseItem.id === message.id ? message : caseItem,
          ),
        );
      } else if (status === "deleted") {
        setCaseData((prevData) =>
          prevData.filter((caseItem) => caseItem.id !== message.id),
        );
      }
    };

    ws.current.onerror = (error) => {
      console.log("WebSocket error:", error);
    };

    // Fetch initial case data
    axiosInstance
      .get("/api/cases/")
      .then((response) => {
        setCaseData(response.data);
      })
      .catch((error) => {
        console.error("Error fetching case data:", error);
      });

    return () => {
      if (ws.current) {
        ws.current.close();
      }
    };
  }, []);

  const handleCreateSuccess = () => {
    setSnackbarMessage("Case created successfully");
    setSnackbarSeverity("success");
    setOpenSnackbar(true);
  };

  const handleDeleteClick = (row: Case) => {
    setSelectedCase(row);
    setOpenDialog(true);
    setDeleteMultiple(false);
  };

  const handleConfirmDelete = async () => {
    if (selectedCase && !deleteMultiple) {
      try {
        await axiosInstance.delete(`/api/cases/${selectedCase.id}/`);
        setSnackbarMessage("Case deleted successfully");
        setSnackbarSeverity("success");
      } catch {
        setSnackbarMessage("Error deleting case");
        setSnackbarSeverity("error");
      } finally {
        setOpenSnackbar(true);
        setOpenDialog(false);
        setSelectedCase(null);
      }
    } else if (deleteMultiple) {
      handleDeleteSelected();
    }
  };

  const handleDeleteSelected = async () => {
    try {
      await Promise.all(
        checked.map((id) => axiosInstance.delete(`/api/cases/${id}/`)),
      );
      setSnackbarMessage("Selected cases deleted successfully");
      setSnackbarSeverity("success");
      setChecked([]);
    } catch {
      setSnackbarMessage("Error deleting selected cases");
      setSnackbarSeverity("error");
    } finally {
      setOpenSnackbar(true);
      setOpenDialog(false);
    }
  };

  const handleOpenDeleteMultipleDialog = () => {
    setDeleteMultiple(true);
    setOpenDialog(true);
  };

  const handleToggle = (id: number) => {
    navigate(`/cases/${id}`);
  };

  const columns: GridColDef[] = [
    {
      field: "name",
      headerName: "Case Name",
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center" }}>
          <Work style={{ marginRight: 8 }} />
          {params.value}
        </div>
      ),
      flex: 1,
    },
    {
      field: "description",
      headerName: "Description",
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center" }}>
          <Info style={{ marginRight: 8 }} />
          {params.value}
        </div>
      ),
      flex: 2,
    },
    {
      field: "bucket_id",
      headerName: "Bucket",
      renderCell: (params: GridRenderCellParams) => (
        <Chip label={params.value} color="error" variant="outlined" />
      ),
      flex: 1,
    },
    {
      field: "last_update",
      headerName: "Last Update",
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center" }}>
          <CalendarToday style={{ marginRight: 8 }} />
          {params.value}
        </div>
      ),
      flex: 1,
    },
    {
      field: "actions",
      headerName: "Actions",
      renderCell: (params: GridRenderCellParams) => (
        <>
          <Tooltip title="Review case">
            <IconButton
              edge="end"
              aria-label="open"
              onClick={() => handleToggle(params.row.id)}
            >
              <Biotech />
            </IconButton>
          </Tooltip>
          <Tooltip title="Delete Case">
            <IconButton
              edge="end"
              aria-label="delete"
              onClick={() => handleDeleteClick(params.row)}
            >
              <DeleteSweep />
            </IconButton>
          </Tooltip>
        </>
      ),
      sortable: false,
      flex: 1,
    },
  ];

  return (
    <>
      <DataGrid
        rowHeight={40}
        disableRowSelectionOnClick
        columns={columns}
        rows={caseData}
        loading={!isConnected}
        checkboxSelection
        onRowSelectionModelChange={(selection) => {
          setChecked(selection as number[]);
        }}
      />
      <Fab
        color="primary"
        aria-label="add"
        style={{ position: "fixed", bottom: 16, right: 16 }}
        onClick={() => setCaseDialogOpen(true)}
      >
        <AddIcon />
      </Fab>
      {checked.length > 0 && (
        <Fab
          color="secondary"
          aria-label="delete"
          style={{ position: "fixed", bottom: 90, right: 16 }}
          onClick={handleOpenDeleteMultipleDialog}
        >
          <DeleteIcon />
        </Fab>
      )}
      <AddCaseDialog
        open={caseDialogOpen}
        onClose={() => setCaseDialogOpen(false)}
        onCreateSuccess={handleCreateSuccess}
      />
      <Snackbar
        open={openSnackbar}
        autoHideDuration={6000}
        onClose={() => setOpenSnackbar(false)}
      >
        <Alert
          onClose={() => setOpenSnackbar(false)}
          severity={snackbarSeverity}
        >
          {snackbarMessage}
        </Alert>
      </Snackbar>
      <Dialog
        open={openDialog}
        onClose={() => setOpenDialog(false)}
        aria-labelledby="alert-dialog-title"
        aria-describedby="alert-dialog-description"
      >
        <DialogTitle id="alert-dialog-title">{`Delete ${
          deleteMultiple ? "Selected Cases" : "Case"
        }`}</DialogTitle>
        <DialogContent>
          <DialogContentText id="alert-dialog-description">
            {`Are you sure you want to delete ${
              deleteMultiple ? "these cases" : "this case"
            }?`}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenDialog(false)} color="primary">
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

export default CaseList;
