import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import {
  DataGrid,
  GridColDef,
  GridRenderCellParams,
  GridRowSelectionModel,
} from "@mui/x-data-grid";
import {
  IconButton,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  Button,
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
import { useSnackbar } from "../SnackbarProvider";

function CaseList() {
  const navigate = useNavigate();
  const { display_message } = useSnackbar();

  const [selectionModel, setSelectionModel] = useState<GridRowSelectionModel>({
    type: "include",
    ids: new Set(),
  });
  const [openDialog, setOpenDialog] = useState(false);
  const [selectedCase, setSelectedCase] = useState<Case | null>(null);
  const [caseDialogOpen, setCaseDialogOpen] = useState(false);
  const [caseData, setCaseData] = useState<Case[]>([]);
  const [deleteMultiple, setDeleteMultiple] = useState(false);

  const [isConnected, setIsConnected] = useState(false);
  const ws = useRef<WebSocket | null>(null);
  const retryInterval = useRef<number | null>(null);

  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const port = window.location.port ? `:${window.location.port}` : "";
    const wsUrl = `${protocol}://${window.location.hostname}${port}/ws/cases/`;

    const connectWebSocket = () => {
      ws.current = new WebSocket(wsUrl);

      ws.current.onopen = () => {
        console.log("WebSocket connected");
        setIsConnected(true);
        if (retryInterval.current) {
          clearTimeout(retryInterval.current);
          retryInterval.current = null;
        }
      };

      ws.current.onclose = () => {
        console.log("WebSocket disconnected");
        setIsConnected(false);
        if (!retryInterval.current) {
          retryInterval.current = window.setTimeout(connectWebSocket, 2000);
          console.log("Attempting to reconnect to WebSocket...");
        }
      };

      ws.current.onmessage = (event) => {
        const data = JSON.parse(event.data);
        const status = data.status;
        const message = data.message;

        if (status === "created") {
          setCaseData((prevData) => {
            const exists = prevData.some(
              (caseItem) => caseItem.id === message.id,
            );
            if (exists) {
              return prevData.map((caseItem) =>
                caseItem.id === message.id ? message : caseItem,
              );
            } else {
              return [...prevData, message];
            }
          });
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
          setSelectionModel({
            type: "include",
            ids: new Set(),
          });
        }
      };

      ws.current.onerror = (error) => {
        console.log("WebSocket error:", error);
      };
    };

    connectWebSocket();

    axiosInstance
      .get("/api/cases/")
      .then((response) => {
        setCaseData(response.data);
      })
      .catch((error) => {
        display_message("error", "Error fetching the case data.");
        console.error("Error fetching case data:", error);
      });

    return () => {
      if (ws.current) {
        ws.current.close();
      }
      if (retryInterval.current) {
        clearTimeout(retryInterval.current);
      }
    };
  }, [display_message]);

  const handleCreateSuccess = () => {
    display_message("success", "Case created.");
  };

  const selectedIds = [...selectionModel.ids] as number[];

  const handleDeleteClick = (row: Case) => {
    setSelectedCase(row);
    setDeleteMultiple(false);
    setOpenDialog(true);
  };

  const handleConfirmDelete = async () => {
    if (deleteMultiple) {
      try {
        await Promise.all(
          selectedIds.map((id) => axiosInstance.delete(`/api/cases/${id}/`)),
        );
        display_message("success", "Selected cases deleted.");
        setSelectionModel({
          type: "include",
          ids: new Set(),
        });
      } catch {
        display_message("error", "Error deleting selected cases");
      } finally {
        setOpenDialog(false);
      }
    } else if (selectedCase) {
      try {
        await axiosInstance.delete(`/api/cases/${selectedCase.id}/`);
        display_message("success", "Case deleted.");
      } catch {
        display_message("error", "Error deleting case");
      } finally {
        setOpenDialog(false);
        setSelectedCase(null);
      }
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
      flex: 1,
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center" }}>
          <Work style={{ marginRight: 8 }} />
          {params.value}
        </div>
      ),
    },
    {
      field: "description",
      headerName: "Description",
      flex: 2,
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center" }}>
          <Info style={{ marginRight: 8 }} />
          {params.value}
        </div>
      ),
    },
    {
      field: "last_update",
      headerName: "Last Update",
      flex: 1,
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center" }}>
          <CalendarToday style={{ marginRight: 8 }} />
          {params.value}
        </div>
      ),
    },
    {
      field: "actions",
      headerName: "Actions",
      flex: 1,
      sortable: false,
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
        rowSelectionModel={selectionModel}
        onRowSelectionModelChange={(newSelection) =>
          setSelectionModel(newSelection as GridRowSelectionModel)
        }
      />
      <Fab
        color="primary"
        aria-label="add"
        style={{ position: "fixed", bottom: 16, right: 16 }}
        onClick={() => setCaseDialogOpen(true)}
      >
        <AddIcon />
      </Fab>
      {selectedIds.length > 0 && (
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
