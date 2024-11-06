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
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
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
const StixModule = ({ evidenceId }) => {
  // State for Drawers
  const [isFormDrawerOpen, setFormDrawerOpen] = useState(false);
  const [isIndicatorsDrawerOpen, setIndicatorsDrawerOpen] = useState(false);

  // State for Indicators
  const [indicators, setIndicators] = useState([]);

  // State for Types
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
    if (open) {
      fetchIndicators();
    }
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

  // Fetch Indicators
  const fetchIndicators = async () => {
    try {
      const url = `/core/stix/indicators/evidence/${evidenceId}/`;
      const response = await axiosInstance.get(url);
      setIndicators(response.data);
    } catch (error) {
      setSnackbar({
        open: true,
        message: "Failed to fetch indicators.",
        severity: "error",
      });
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
      fetchIndicators(); // Refresh indicators list
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

  // Handle Delete Indicator
  const handleDelete = async (indicatorId) => {
    try {
      await axiosInstance.delete(`/core/stix/indicators/${indicatorId}/`);
      setSnackbar({
        open: true,
        message: "Indicator deleted successfully.",
        severity: "success",
      });
      fetchIndicators(); // Refresh indicators list
    } catch (error) {
      setSnackbar({
        open: true,
        message: "Failed to delete the indicator.",
        severity: "error",
      });
    }
  };

  return (
    <Box>
      {/* Add New Indicator FAB */}
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

      {/* View Indicators FAB */}
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

      {/* Form Drawer */}
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
            {/* Hidden Evidence Field */}
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

      {/* Indicators Drawer */}
      <Drawer
        anchor="right"
        open={isIndicatorsDrawerOpen}
        onClose={toggleIndicatorsDrawer(false)}
        PaperProps={{ sx: { width: "60%" } }}
      >
        <Box
          sx={{
            padding: 2,
            height: "100%",
            display: "flex",
            flexDirection: "column",
          }}
        >
          <Box
            display="flex"
            justifyContent="space-between"
            alignItems="center"
          >
            <Typography variant="h6" color="warning">
              Indicators
            </Typography>
            <IconButton onClick={toggleIndicatorsDrawer(false)}>
              <CloseIcon />
            </IconButton>
          </Box>
          <Box mt={2} flexGrow={1} overflow="auto">
            <TableContainer component={Paper}>
              <Table size="small" aria-label="indicators table">
                <TableHead>
                  <TableRow>
                    <TableCell>Type</TableCell>
                    <TableCell>Name</TableCell>
                    <TableCell>Description</TableCell>
                    <TableCell>Value</TableCell>
                    <TableCell>Source</TableCell>
                    <TableCell>Action</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {indicators.map((indicator) => (
                    <TableRow key={indicator.id}>
                      <TableCell>
                        <Box
                          sx={{
                            p: 1,
                            textTransform: "uppercase",
                            fontWeight: "600",
                            color: "warning.main",
                            border: "1px solid",
                            borderColor: "warning.light",
                            textAlign: "center",
                          }}
                        >
                          {indicator.type}
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" color="text.secondary">
                          {indicator.name}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" color="text.secondary">
                          {indicator.description}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" color="error">
                          {indicator.value}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" color="text.secondary">
                          {indicator.dump_linked_dump_name}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="outlined"
                          color="error"
                          size="small"
                          onClick={() => handleDelete(indicator.id)}
                        >
                          Remove
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                  {indicators.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={6} align="center">
                        No indicators found.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        </Box>
      </Drawer>

      {/* Snackbar for Notifications */}
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
