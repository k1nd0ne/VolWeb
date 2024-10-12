import React, { useState, useEffect } from "react";
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Select,
  MenuItem,
  LinearProgress,
  FormControl,
  InputLabel,
  Autocomplete,
  CircularProgress,
} from "@mui/material";
import axiosInstance from "../utils/axiosInstance";
import axios from "axios";
import { Evidence, Case } from "../types";

interface EvidenceCreationDialogProps {
  open: boolean;
  onClose: () => void;
  onCreateSuccess: (newEvidence: Evidence) => void;
}

const EvidenceCreationDialog: React.FC<EvidenceCreationDialogProps> = ({
  open,
  onClose,
  onCreateSuccess,
}) => {
  const OS_OPTIONS = [
    { value: "windows", label: "Windows" },
    { value: "linux", label: "Linux" },
  ];

  const [os, setOs] = useState<string>("");
  const [file, setFile] = useState<File | null>(null);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [uploading, setUploading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const [cases, setCases] = useState<Case[]>([]);
  const [selectedCase, setSelectedCase] = useState<Case | null>(null);
  const [casesLoading, setCasesLoading] = useState<boolean>(false);

  useEffect(() => {
    if (open) {
      fetchCases();
    }
  }, [open]);

  const fetchCases = async () => {
    setCasesLoading(true);
    try {
      const response = await axiosInstance.get<Case[]>("/api/cases/");
      setCases(response.data);
    } catch (err) {
      console.error("Error fetching cases:", err);
      setError("Failed to load cases.");
    } finally {
      setCasesLoading(false);
    }
  };

  const handleUpload = async () => {
    if (!os || !file || !selectedCase) {
      setError("Please fill in all fields.");
      return;
    }

    setUploading(true);
    setError(null);

    try {
      const response = await axiosInstance.get<{ url: string }>(
        `/api/cases/${selectedCase.id}/generate-presigned-url/`,
        {
          params: {
            filename: file.name,
          },
        },
      );
      const { url } = response.data;

      const uploadResponse = await axios.put(url, file, {
        headers: {
          "Content-Type": file.type,
        },
        onUploadProgress: (progressEvent) => {
          if (progressEvent.total) {
            const percentage = Math.round(
              (progressEvent.loaded / progressEvent.total) * 100,
            );
            setUploadProgress(percentage);
          }
        },
      });

      const etag = uploadResponse.headers["etag"];

      try {
        const newEvidenceResp = await axiosInstance.post<Evidence>(
          "/api/evidences/",
          {
            name: file.name,
            os,
            linked_case: selectedCase.id,
            etag,
          },
        );
        onCreateSuccess(newEvidenceResp.data);
        onClose();
      } catch (error) {
        console.log("ERROR creating evidence:", error);
      } finally {
        console.log("Finally");
      }

      setUploading(false);
      onClose();

      // Notify the parent component about the new evidence

      // Reset form
      setOs("");
      setFile(null);
      setUploadProgress(null);
    } catch (err) {
      console.error("Upload error:", err);
      setError("Upload failed.");
      setUploading(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth>
      <DialogTitle>Upload New Evidence</DialogTitle>
      <DialogContent>
        {casesLoading ? (
          <div style={{ textAlign: "center", marginTop: "20px" }}>
            <CircularProgress />
          </div>
        ) : (
          <>
            <Autocomplete
              options={cases}
              getOptionLabel={(option) => option.name}
              value={selectedCase}
              onChange={(event, newValue) => {
                setSelectedCase(newValue);
              }}
              renderInput={(params) => (
                <TextField
                  {...params}
                  label="Select Case"
                  margin="dense"
                  fullWidth
                  required
                />
              )}
            />
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
            <Button
              variant="contained"
              component="label"
              style={{ marginTop: 16 }}
            >
              Select File
              <input
                type="file"
                hidden
                onChange={(e) =>
                  setFile(e.target.files ? e.target.files[0] : null)
                }
              />
            </Button>
            {file && (
              <div style={{ marginTop: 8 }}>Selected File: {file.name}</div>
            )}

            {uploading && (
              <div style={{ marginTop: 16 }}>
                <LinearProgress
                  variant="determinate"
                  value={uploadProgress || 0}
                />
                <div>{uploadProgress}%</div>
              </div>
            )}
            {error && (
              <div style={{ color: "red", marginTop: 16 }}>{error}</div>
            )}
          </>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={uploading || casesLoading}>
          Cancel
        </Button>
        <Button
          onClick={handleUpload}
          variant="contained"
          disabled={uploading || !selectedCase || casesLoading}
        >
          Upload
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default EvidenceCreationDialog;
