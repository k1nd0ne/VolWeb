import React, { useState, useEffect } from "react";
import {
  Box,
  Fab,
  Tooltip,
  Drawer,
  Typography,
  TextField,
  Button,
  IconButton,
  Select,
  MenuItem,
  InputLabel,
  FormControl,
  Snackbar,
  Alert,
  CircularProgress,
} from "@mui/material";
import {
  Add as AddIcon,
  Visibility as VisibilityIcon,
  Close as CloseIcon,
} from "@mui/icons-material";
import axiosInstance from "../utils/axiosInstance";
import IndicatorsList from "./IndicatorsList"; // Import the new component

const StixModule = ({ evidenceId }) => {
  const [isFormDrawerOpen, setFormDrawerOpen] = useState(false);
  const [isIndicatorsDrawerOpen, setIndicatorsDrawerOpen] = useState(false);

  const [types, setTypes] = useState([]);
  const [isLoadingTypes, setIsLoadingTypes] = useState(false);
  const [typesError, setTypesError] = useState("");

  // State for Form
  const [formData, setFormData] = useState({
    type: "",
    name: "",
    description: "",
    value: "",
    evidence: evidenceId || "",
  });

  // State for Notifications
  const [snackbar, setSnackbar] = useState({
    open: false,
    message: "",
    severity: "success", // 'success' | 'error' | 'warning' | 'info'
  });

  // Handlers for Drawers
  const toggleFormDrawer = (open) => () => {
    setFormDrawerOpen(open);
    if (open && types.length === 0) {
      fetchTypes();
    }
  };

  const toggleIndicatorsDrawer = (open) => () => {
    setIndicatorsDrawerOpen(open);
    // IndicatorsList handles its own fetching when open
  };

  // Handlers for Snackbar
  const handleCloseSnackbar = (event, reason) => {
    if (reason === "clickaway") return;
    setSnackbar({ ...snackbar, open: false });
  };

  // Fetch Types
  const fetchTypes = async () => {
    setIsLoadingTypes(true);
    setTypesError("");
    try {
      const response = await axiosInstance.get("/core/stix/indicator-types/");
      setTypes(response.data);
    } catch (error) {
      setTypesError("Failed to fetch indicator types.");
      setSnackbar({
        open: true,
        message: "Failed to fetch indicator types.",
        severity: "error",
      });
    } finally {
      setIsLoadingTypes(false);
    }
  };

  // Handle Form Input Change
  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  // Handle Form Submission
  const handleFormSubmit = async (e) => {
    e.preventDefault();
    try {
      // Preparing the data for submission
      const payload = {
        type: formData.type,
        name: formData.name,
        description: formData.description,
        value: formData.value,
        evidence: formData.evidence,
      };

      await axiosInstance.post("/core/stix/indicators/", payload);

      // Reset the form
      setFormData({
        type: "",
        name: "",
        description: "",
        value: "",
        evidence: evidenceId || "",
      });

      setFormDrawerOpen(false);
      setSnackbar({
        open: true,
        message: "Indicator created successfully!",
        severity: "success",
      });
      // If you keep indicators as state in StixModule, you would refresh them here
      // Otherwise, IndicatorsList will handle its own refresh
    } catch (error) {
      const message =
        error.response?.data?.message ||
        "An error occurred while creating the indicator.";
      setSnackbar({
        open: true,
        message,
        severity: "error",
      });
      setFormDrawerOpen(false);
    }
  };

  return (
    <Box>
      <Tooltip title="New Indicator" placement="left">
        <Fab
          color="error"
          aria-label="add"
          onClick={toggleFormDrawer(true)}
          style={{ position: "fixed", bottom: 80, right: 16 }}
        >
          <AddIcon />
        </Fab>
      </Tooltip>

      <Tooltip title="View Indicators" placement="left">
        <Fab
          color="primary"
          aria-label="view"
          onClick={toggleIndicatorsDrawer(true)}
          style={{ position: "fixed", bottom: 16, right: 16 }}
        >
          <VisibilityIcon />
        </Fab>
      </Tooltip>

      <Drawer
        anchor="right"
        open={isFormDrawerOpen}
        onClose={toggleFormDrawer(false)}
      >
        <Box
          sx={{ width: 350, padding: 2 }}
          role="presentation"
          component="form"
          onSubmit={handleFormSubmit}
        >
          <Box
            display="flex"
            justifyContent="space-between"
            alignItems="center"
          >
            <Typography variant="h6">Create a New Indicator</Typography>
            <IconButton onClick={toggleFormDrawer(false)}>
              <CloseIcon />
            </IconButton>
          </Box>
          <Box mt={2}>
            <FormControl fullWidth required margin="normal">
              <InputLabel id="type-label">Indicator Type</InputLabel>
              {isLoadingTypes ? (
                <Box
                  display="flex"
                  justifyContent="center"
                  alignItems="center"
                  padding={2}
                >
                  <CircularProgress size={24} />
                </Box>
              ) : typesError ? (
                <Typography color="error">{typesError}</Typography>
              ) : (
                <Select
                  labelId="type-label"
                  id="type"
                  name="type"
                  value={formData.type}
                  label="Indicator Type"
                  onChange={handleInputChange}
                  required
                >
                  {types.map((type) => (
                    <MenuItem key={type.value} value={type.value}>
                      {type.display}
                    </MenuItem>
                  ))}
                </Select>
              )}
            </FormControl>
            <TextField
              label="Name"
              name="name"
              value={formData.name}
              onChange={handleInputChange}
              fullWidth
              required
              margin="normal"
            />
            <TextField
              label="Description"
              name="description"
              value={formData.description}
              onChange={handleInputChange}
              fullWidth
              required
              multiline
              rows={4}
              margin="normal"
            />
            <TextField
              label="Value"
              name="value"
              value={formData.value}
              onChange={handleInputChange}
              fullWidth
              required
              margin="normal"
            />
            <input type="hidden" name="evidence" value={formData.evidence} />
            <Button
              type="submit"
              variant="contained"
              color="error"
              fullWidth
              sx={{ mt: 2 }}
              disabled={isLoadingTypes || typesError !== ""}
            >
              Create
            </Button>
          </Box>
        </Box>
      </Drawer>

      <Drawer
        anchor="right"
        open={isIndicatorsDrawerOpen}
        onClose={toggleIndicatorsDrawer(false)}
        PaperProps={{ sx: { width: "60%" } }}
      >
        <IndicatorsList
          open={isIndicatorsDrawerOpen}
          onClose={toggleIndicatorsDrawer(false)}
          evidenceId={evidenceId}
          // Optionally, handle indicator deletion callbacks here
          // onIndicatorDeleted={(deletedId) => { /* Your logic */ }}
        />
      </Drawer>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
      >
        <Alert
          onClose={handleCloseSnackbar}
          severity={snackbar.severity}
          sx={{ width: "100%" }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default StixModule;
