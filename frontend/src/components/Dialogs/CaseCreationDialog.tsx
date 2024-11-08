import React, { useState } from "react";
import axiosInstance from "../../utils/axiosInstance";
import {
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Typography,
  IconButton,
  FormControl,
  Divider,
  TextField,
  Snackbar,
  Alert,
} from "@mui/material";
import { styled } from "@mui/material/styles";
import CloseIcon from "@mui/icons-material/Close";
import { Case, User } from "../../types";
import InvestigatorSelect from "../InvestigatorSelect";

const BootstrapDialog = styled(Dialog)(({ theme }) => ({
  "& .MuiDialogContent-root": {
    padding: theme.spacing(2),
  },
  "& .MuiDialogActions-root": {
    padding: theme.spacing(1),
  },
}));

interface AddCaseDialogProps {
  open: boolean;
  onClose: () => void;
  onCreateSuccess: (newCase: Case) => void;
}

const AddCaseDialog: React.FC<AddCaseDialogProps> = ({
  open,
  onClose,
  onCreateSuccess,
}) => {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [selectedUsers, setSelectedUsers] = useState<User[]>([]);
  const [openSnackbar, setOpenSnackbar] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState("");
  const [snackbarSeverity, setSnackbarSeverity] = useState<"success" | "error">(
    "success",
  );

  const handleCreate = async () => {
    const requestData = {
      name,
      description,
      bucket_id: "123e4567-e89b-12d3-a456-426614174000", // Replace with actual bucket_id
      linked_users: selectedUsers.map((user) => user.id),
    };
    try {
      const response = await axiosInstance.post("/api/cases/", requestData);
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
        <InvestigatorSelect
          selectedUsers={selectedUsers}
          setSelectedUsers={setSelectedUsers}
        />
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
