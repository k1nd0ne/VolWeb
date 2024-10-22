import { useState, useEffect } from "react";
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
} from "@mui/material";
import Biotech from "@mui/icons-material/Biotech";
import DeleteSweep from "@mui/icons-material/DeleteSweep";
import Work from "@mui/icons-material/Work";
import Info from "@mui/icons-material/Info";
import CalendarToday from "@mui/icons-material/CalendarToday";
import axiosInstance from "../utils/axiosInstance";
import AddCaseDialog from "./CaseCreationDialog";
import { Case } from "../types";
import Fab from "@mui/material/Fab";
import AddIcon from "@mui/icons-material/Add";
import DeleteIcon from "@mui/icons-material/Delete";

interface CaseListProps {
  cases: Case[];
}

function CaseList({ cases }: CaseListProps) {
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
  const [caseData, setCaseData] = useState<Case[]>(cases);
  const [deleteMultiple, setDeleteMultiple] = useState(false);

  useEffect(() => {
    setCaseData(cases);
  }, [cases]);

  const handleCreateSuccess = (newCase: Case) => {
    setCaseData([...caseData, newCase]);
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
        setCaseData(
          caseData.filter((caseItem) => caseItem.id !== selectedCase.id),
        );
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
      setCaseData(
        caseData.filter((caseItem) => !checked.includes(caseItem.id)),
      );
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
