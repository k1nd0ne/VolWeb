import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import DataTable, { createTheme } from "react-data-table-component";
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

  const columns = [
    {
      name: "Case Name",
      selector: (row: Case) => (
        <div style={{ display: "flex", alignItems: "center" }}>
          <Work style={{ marginRight: 8 }} />
          {row.name}
        </div>
      ),
      sortable: true,
    },
    {
      name: "Description",
      selector: (row: Case) => (
        <div style={{ display: "flex", alignItems: "center" }}>
          <Info style={{ marginRight: 8 }} />
          {row.description}
        </div>
      ),
      sortable: true,
    },
    {
      name: "Bucket",
      cell: (row: Case) => (
        <Chip label={row.bucket_id} color="error" variant="outlined" />
      ),
      sortable: true,
    },
    {
      name: "Last Update",
      selector: (row: Case) => (
        <div style={{ display: "flex", alignItems: "center" }}>
          <CalendarToday style={{ marginRight: 8 }} />
          {row.last_update}
        </div>
      ),
      sortable: true,
    },
    {
      name: "Actions",
      cell: (row: Case) => (
        <>
          <Tooltip title="Review case">
            <IconButton
              edge="end"
              aria-label="open"
              onClick={() => handleToggle(row.id)}
            >
              <Biotech />
            </IconButton>
          </Tooltip>
          <Tooltip title="Delete Case">
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
      <DataTable
        columns={columns}
        title="Cases"
        data={caseData}
        theme="mui"
        selectableRows
        onSelectedRowsChange={({ selectedRows }) => {
          const selectedIds = selectedRows.map((row: Case) => row.id);
          setChecked(selectedIds);
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
