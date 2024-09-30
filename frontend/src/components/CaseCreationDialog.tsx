import React, { useState } from "react";
import axiosInstance from "../utils/axiosInstance";
import Button from "@mui/material/Button";
import { styled } from "@mui/material/styles";
import Dialog from "@mui/material/Dialog";
import DialogTitle from "@mui/material/DialogTitle";
import DialogContent from "@mui/material/DialogContent";
import DialogActions from "@mui/material/DialogActions";
import CloseIcon from "@mui/icons-material/Close";
import Typography from "@mui/material/Typography";
import IconButton from "@mui/material/IconButton";
import FormControl from "@mui/material/FormControl";
import Divider from "@mui/material/Divider";
import TextField from "@mui/material/TextField";
import InvestigatorSelect from "./InvestigatorSelect";
import Snackbar from "@mui/material/Snackbar";
import Alert from "@mui/material/Alert";

const BootstrapDialog = styled(Dialog)(({ theme }) => ({
  "& .MuiDialogContent-root": {
    padding: theme.spacing(2),
  },
  "& .MuiDialogActions-root": {
    padding: theme.spacing(1),
  },
}));

const AddCaseDialog: React.FC<AddCaseDialogProps> = ({
  open,
  onClose,
  onCreateSuccess,
}) => {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [openSnackbar, setOpenSnackbar] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState("");
  const [snackbarSeverity, setSnackbarSeverity] = useState<"success" | "error">(
    "success",
  );

  const handleCreate = async () => {
    try {
      const response = await axiosInstance.post("/api/cases/", {
        name,
        description,
        bucket_id: "123e4567-e89b-12d3-a456-426614174000", // Replace with actual bucket_id
      });
      onCreateSuccess(response.data);
      setSnackbarMessage("Case created successfully");
      setSnackbarSeverity("success");
      onClose();
    } catch {
      setSnackbarMessage("Error creating case");
      setSnackbarSeverity("error");
    } finally {
      setOpenSnackbar(true);
    }
  };

  return (
    <BootstrapDialog
      onClose={onClose}
      aria-labelledby="customized-dialog-title"
      open={open}
      fullWidth={true}
      maxWidth={"sm"}
    >
      <DialogTitle sx={{ m: 0, pl: 2 }} id="customized-dialog-title">
        Create a case
        <Typography sx={{ m: 0, pl: 2 }}>
          <i>
            The case will contain all of the information about your
            investigation.
          </i>
        </Typography>
      </DialogTitle>

      <Divider />
      <IconButton
        aria-label="close"
        onClick={onClose}
        sx={{
          position: "absolute",
          right: 8,
          top: 8,
          color: (theme) => theme.palette.grey[500],
        }}
      >
        <CloseIcon />
      </IconButton>
      <DialogContent dividers>
        <FormControl sx={{ width: 1, mb: 1 }}>
          <TextField
            autoFocus
            required
            margin="dense"
            id="name"
            name="name"
            label="Name"
            type="text"
            fullWidth
            variant="outlined"
            size="small"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </FormControl>
        <FormControl sx={{ width: 1, mb: 2 }}>
          <TextField
            id="description"
            name="description"
            required
            label="Description"
            multiline
            fullWidth
            rows={4}
            size="small"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </FormControl>
        <InvestigatorSelect />
      </DialogContent>
      <DialogActions>
        <Button autoFocus onClick={handleCreate}>
          Create
        </Button>
      </DialogActions>
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
    </BootstrapDialog>
  );
};

interface AddCaseDialogProps {
  open: boolean;
  onClose: () => void;
  onCreateSuccess: (newCase: Case) => void;
}

export default AddCaseDialog;
