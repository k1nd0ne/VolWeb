import { useEffect, useState } from "react";
import { DataGrid, GridColDef, GridRenderCellParams } from "@mui/x-data-grid";
import { useNavigate } from "react-router-dom";
import axiosInstance from "../../utils/axiosInstance";
import SymbolCreationDialog from "../Dialogs/SymbolCreationDialog";
import MessageHandler from "../MessageHandler";
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

interface SymbolsListProps {
  symbols: Symbol[];
}

function SymbolsList({ symbols }: SymbolsListProps) {
  const navigate = useNavigate();
  const [symbolData, setSymbolData] = useState<Symbol[]>(symbols);
  const [openDeleteDialog, setOpenDeleteDialog] = useState<boolean>(false);
  const [openCreationDialog, setOpenCreationDialog] = useState<boolean>(false);
  const [selectedSymbol, setSelectedSymbol] = useState<Symbol | null>(null);
  const [checked, setChecked] = useState<number[]>([]);
  const [deleteMultiple, setDeleteMultiple] = useState(false);
  const [messageHandlerOpen, setMessageHandlerOpen] = useState<boolean>(false);
  const [messageHandlerMessage, setMessageHandlerMessage] =
    useState<string>("");
  const [messageHandlerSeverity, setMessageHandlerSeverity] = useState<
    "success" | "error"
  >("success");

  useEffect(() => {
    setSymbolData(symbols);
  }, [symbols]);

  const handleCreateSuccess = (newSymbol: Symbol) => {
    setMessageHandlerMessage("Symbol created successfully");
    setMessageHandlerSeverity("success");
    setSymbolData([...symbolData, newSymbol]); // Corrected from `newESymbol` to `newSymbol`
    setMessageHandlerOpen(true);
  };

  const handleToggle = (id: number) => {
    navigate(`/symbols/${id}`);
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
        setMessageHandlerMessage("Symbol deleted successfully");
        setMessageHandlerSeverity("success");
        setSymbolData((prevData) =>
          prevData.filter((symbol) => symbol.id !== selectedSymbol.id),
        );
      } catch {
        setMessageHandlerMessage("Error deleting symbol");
        setMessageHandlerSeverity("error");
      } finally {
        setMessageHandlerOpen(true);
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
      setMessageHandlerMessage("Selected symbols deleted successfully");
      setMessageHandlerSeverity("success");
      setSymbolData((prevData) =>
        prevData.filter((symbol) => !checked.includes(symbol.id)),
      );
      setChecked([]);
    } catch {
      setMessageHandlerMessage("Error deleting selected symbols");
      setMessageHandlerSeverity("error");
    } finally {
      setMessageHandlerOpen(true);
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
