import React, { useEffect, useState } from "react";
import {
  Box,
  Typography,
  IconButton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Button,
  CircularProgress,
  Snackbar,
  Alert,
} from "@mui/material";
import { Close as CloseIcon } from "@mui/icons-material";
import axiosInstance from "../../utils/axiosInstance";
import PropTypes from "prop-types";

const IndicatorsList = ({ open, onClose, evidenceId, onIndicatorDeleted }) => {
  const [indicators, setIndicators] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");

  const [snackbar, setSnackbar] = useState({
    open: false,
    message: "",
    severity: "success",
  });

  useEffect(() => {
    if (open) {
      fetchIndicators();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  // Fetch Indicators
  const fetchIndicators = async () => {
    setIsLoading(true);
    setError("");
    try {
      const url = `/core/stix/indicators/evidence/${evidenceId}/`;
      const response = await axiosInstance.get(url);
      setIndicators(response.data);
    } catch (err) {
      setError("Failed to fetch indicators.");
      setSnackbar({
        open: true,
        message: "Failed to fetch indicators.",
        severity: "error",
      });
    } finally {
      setIsLoading(false);
    }
  };

  // Handle Delete Indicator
  const handleDelete = async (indicatorId) => {
    if (!window.confirm("Are you sure you want to delete this indicator?")) {
      return;
    }

    try {
      await axiosInstance.delete(`/core/stix/indicators/${indicatorId}/`);
      setSnackbar({
        open: true,
        message: "Indicator deleted successfully.",
        severity: "success",
      });
      // Refresh indicators list
      fetchIndicators();
      // Notify parent component if needed
      if (onIndicatorDeleted) {
        onIndicatorDeleted(indicatorId);
      }
    } catch (err) {
      setSnackbar({
        open: true,
        message: "Failed to delete the indicator.",
        severity: "error",
      });
    }
  };

  // Handle Snackbar Close
  const handleCloseSnackbar = (event, reason) => {
    if (reason === "clickaway") return;
    setSnackbar({ ...snackbar, open: false });
  };

  return (
    <Box
      sx={{
        padding: 2,
        height: "100%",
        display: "flex",
        flexDirection: "column",
      }}
    >
      {/* Header */}
      <Box display="flex" justifyContent="space-between" alignItems="center">
        <Typography variant="h6" color="warning">
          Indicators
        </Typography>
        <IconButton onClick={onClose}>
          <CloseIcon />
        </IconButton>
      </Box>

      {/* Content */}
      <Box mt={2} flexGrow={1} overflow="auto">
        {isLoading ? (
          <Box
            display="flex"
            justifyContent="center"
            alignItems="center"
            height="100%"
          >
            <CircularProgress />
          </Box>
        ) : error ? (
          <Typography color="error">{error}</Typography>
        ) : (
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
                {indicators.length > 0 ? (
                  indicators.map((indicator) => (
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
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={6} align="center">
                      No indicators found.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Box>

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

IndicatorsList.propTypes = {
  open: PropTypes.bool.isRequired,
  onClose: PropTypes.func.isRequired,
  evidenceId: PropTypes.string.isRequired,
  onIndicatorDeleted: PropTypes.func, // Optional callback
};

export default IndicatorsList;
