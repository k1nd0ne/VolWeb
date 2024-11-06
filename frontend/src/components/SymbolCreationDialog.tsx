import React, { useState } from "react";
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  TextField,
} from "@mui/material";
import axiosInstance from "../utils/axiosInstance";
import { Symbol } from "../types";

interface SymbolCreationDialogProps {
  open: boolean;
  onClose: () => void;
  onCreateSuccess: (newSymbol: Symbol) => void;
}

const SymbolCreationDialog: React.FC<SymbolCreationDialogProps> = ({
  open,
  onClose,
  onCreateSuccess,
}) => {
  const OS_OPTIONS = [
    { value: "Windows", label: "Windows" },
    { value: "Linux", label: "Linux" },
  ];

  const [os, setOs] = useState<string>("");
  const [file, setFile] = useState<File | null>(null);
  const [description, setDescription] = useState<string>(""); // Add description state
  const [uploading, setUploading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const handleUpload = async () => {
    if (!os || !file || !description) {
      setError("Please fill in all fields.");
      return;
    }

    setUploading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append("os", os);
      formData.append("description", description);
      formData.append("symbols_file", file); // Use 'symbols_file' to match serializer
      if (file) {
        formData.append("name", file.name); // Add name as the name of the uploaded file
      }

      const response = await axiosInstance.post(
        "api/upload_symbols/",
        formData,
        {
          headers: {
            "Content-Type": "multipart/form-data",
          },
        },
      );
      onCreateSuccess(response.data.symbol);
      setUploading(false);
      onClose();
      // Reset form fields after successful upload
      setOs("");
      setDescription("");
      setFile(null);
    } catch (error) {
      console.error("Upload error:", error); // Log the error
      setError("Failed to upload the file. Please try again.");
      setUploading(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth>
      <DialogTitle>Upload New Symbol</DialogTitle>
      <DialogContent>
        <FormControl fullWidth margin="dense">
          <InputLabel id="os-select-label">Operating System</InputLabel>
          <Select
            labelId="os-select-label"
            label="Operating System"
            value={os}
            onChange={(e) => setOs(e.target.value as string)}
          >
            {OS_OPTIONS.map((option) => (
              <MenuItem key={option.value} value={option.value}>
                {option.label}
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        {/* Add Description Field */}
        <TextField
          label="Description"
          fullWidth
          multiline
          rows={4}
          margin="dense"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />

        <Button variant="contained" component="label" style={{ marginTop: 16 }}>
          Select File
          <input
            type="file"
            hidden
            onChange={(e) => setFile(e.target.files ? e.target.files[0] : null)}
          />
        </Button>
        {file && <div style={{ marginTop: 8 }}>Selected File: {file.name}</div>}
        {error && <div style={{ color: "red", marginTop: 16 }}>{error}</div>}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={uploading}>
          Cancel
        </Button>
        <Button onClick={handleUpload} variant="contained" disabled={uploading}>
          Upload
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default SymbolCreationDialog;
