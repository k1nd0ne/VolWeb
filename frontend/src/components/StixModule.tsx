import React, { useState } from "react";
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
  CircularProgress,
  SelectChangeEvent,
} from "@mui/material";
import {
  Add as AddIcon,
  Visibility as VisibilityIcon,
  Close as CloseIcon,
} from "@mui/icons-material";
import axiosInstance from "../utils/axiosInstance";
import IndicatorsList from "./Lists/IndicatorsList";
import { useSnackbar } from "./SnackbarProvider";

interface StixModuleProps {
  evidenceId?: string;
}

const StixModule: React.FC<StixModuleProps> = ({ evidenceId }) => {
  const [isFormDrawerOpen, setFormDrawerOpen] = useState(false);
  const [isIndicatorsDrawerOpen, setIndicatorsDrawerOpen] = useState(false);
  const { display_message } = useSnackbar();

  const [types, setTypes] = useState<{ value: string; display: string }[]>([]);
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

  // Handlers for Drawers
  const toggleFormDrawer = (open: boolean) => () => {
    setFormDrawerOpen(open);
    if (open && types.length === 0) {
      fetchTypes();
    }
  };

  const toggleIndicatorsDrawer = (open: boolean) => () => {
    setIndicatorsDrawerOpen(open);
    // IndicatorsList handles its own fetching when open
  };

  // Fetch Types
  const fetchTypes = async () => {
    setIsLoadingTypes(true);
    setTypesError("");
    try {
      const response = await axiosInstance.get("/core/stix/indicator-types/");
      setTypes(response.data);
    } catch (error) {
      display_message("error", `Failed to fetch indicator types: ${error}`);
    } finally {
      setIsLoadingTypes(false);
    }
  };

  // Handle Form Input Change
  const handleInputChange = (
    e: React.ChangeEvent<HTMLInputElement | { name?: string; value: unknown }>,
  ) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name as string]: value as string });
  };

  // Handle Select Input Change
  const handleSelectChange = (event: SelectChangeEvent<string>) => {
    const { name, value } = event.target;
    setFormData({ ...formData, [name as string]: value });
  };

  // Handle Form Submission
  const handleFormSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
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
      display_message("success", "Indicator created successfully.");
    } catch (error) {
      display_message("error", `Failed to fetch indicators: ${error}`);
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
                  onChange={handleSelectChange}
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
        />
      </Drawer>
    </Box>
  );
};

export default StixModule;
