import { useEffect, useState, useRef } from "react";
import { DataGrid, GridColDef, GridRenderCellParams } from "@mui/x-data-grid";
import axiosInstance from "../../utils/axiosInstance";
import SymbolCreationDialog from "../Dialogs/SymbolCreationDialog";
import {
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
  DeleteSweep,
  Delete as DeleteIcon,
} from "@mui/icons-material";
import { Symbol } from "../../types";
import { useSnackbar } from "../SnackbarProvider";

function SymbolsList() {
  const { display_message } = useSnackbar();
  const [symbolData, setSymbolData] = useState<Symbol[]>([]);
  const [openDeleteDialog, setOpenDeleteDialog] = useState<boolean>(false);
  const [openCreationDialog, setOpenCreationDialog] = useState<boolean>(false);
  const [selectedSymbol, setSelectedSymbol] = useState<Symbol | null>(null);
  const [checked, setChecked] = useState<number[]>([]);
  const [deleteMultiple, setDeleteMultiple] = useState(false);

  // WebSocket related state
  const [isConnected, setIsConnected] = useState(false);
  const ws = useRef<WebSocket | null>(null);
  const retryInterval = useRef<number | null>(null);

  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const wsUrl = `${protocol}://localhost:8000/ws/symbols/`;

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
          retryInterval.current = window.setTimeout(connectWebSocket, 5000);
          console.log("Attempting to reconnect to WebSocket...");
        }
      };

      ws.current.onmessage = (event) => {
        const data = JSON.parse(event.data);
        const status = data.status;
        const message = data.message;

        if (status === "created") {
          setSymbolData((prevData) => {
            const exists = prevData.some((symbol) => symbol.id === message.id);
            if (exists) {
              return prevData.map((symbol) =>
                symbol.id === message.id ? message : symbol,
              );
            } else {
              return [...prevData, message];
            }
          });
        } else if (status === "updated") {
          setSymbolData((prevData) =>
            prevData.map((symbol) =>
              symbol.id === message.id ? message : symbol,
            ),
          );
        } else if (status === "deleted") {
          setSymbolData((prevData) =>
            prevData.filter((symbol) => symbol.id !== message.id),
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

    // Fetch initial symbol data
    axiosInstance
      .get("/api/symbols/")
      .then((response) => {
        setSymbolData(response.data);
      })
      .catch((error) => {
        display_message("error", `Error fetching symbol data: ${error}`);
        console.error("Error fetching symbol data:", error);
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
    display_message("success", "Symbol created.");
  };

  const handleDeleteClick = (row: Symbol) => {
    setSelectedSymbol(row);
    setOpenDeleteDialog(true);
    setDeleteMultiple(false);
  };

  const handleOpenDeleteMultipleDialog = () => {
    setDeleteMultiple(true);
    setOpenDeleteDialog(true);
  };

  const handleConfirmDelete = async () => {
    if (selectedSymbol && !deleteMultiple) {
      try {
        await axiosInstance.delete(`/api/symbols/${selectedSymbol.id}/`);
        display_message("success", "Symbols deleted.");
      } catch (error) {
        display_message("error", `Error deleting symbols: ${error}`);
      } finally {
        setOpenDeleteDialog(false);
        setSelectedSymbol(null);
      }
    } else if (deleteMultiple) {
      handleDeleteSelected();
    }
  };

  const handleDeleteSelected = async () => {
    try {
      await Promise.all(
        checked.map((id) => axiosInstance.delete(`/api/symbols/${id}/`)),
      );
      display_message("success", `Selected symbols deleted.`);
      setChecked([]);
    } catch (error) {
      display_message("error", `Error deleting the symbols: ${error}`);
    } finally {
      setOpenDeleteDialog(false);
    }
  };

  const columns: GridColDef[] = [
    {
      field: "name",
      headerName: "Symbol Name",
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
      field: "description",
      headerName: "Description",
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
          <Memory style={{ marginRight: 8 }} />
          {params.value}
        </div>
      ),
      flex: 1,
    },
    {
      field: "actions",
      headerName: "Actions",
      renderCell: (params: GridRenderCellParams) => (
        <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
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
      <SymbolCreationDialog
        open={openCreationDialog}
        onClose={() => {
          setOpenCreationDialog(false);
        }}
        onCreateSuccess={handleCreateSuccess}
      />
      <DataGrid
        rowHeight={40}
        disableRowSelectionOnClick
        rows={symbolData}
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
          deleteMultiple ? "Selected Symbols" : "Symbol"
        }`}</DialogTitle>
        <DialogContent>
          <DialogContentText id="alert-dialog-description">
            {`Are you sure you want to delete ${
              deleteMultiple ? "these symbols" : "this symbol"
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

export default SymbolsList;
