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
import axiosInstance from "../../utils/axiosInstance";
import { Evidence, Case } from "../../types";
interface EvidenceCreationDialogProps {
  open: boolean;
  onClose: () => void;
  onCreateSuccess: (newEvidence: Evidence) => void;
  onCreateFailed: (error: unknown) => void;
  caseId?: number;
}

const EvidenceCreationDialog: React.FC<EvidenceCreationDialogProps> = ({
  open,
  onClose,
  onCreateSuccess,
  onCreateFailed,
  caseId,
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
  const [selectedEvidence, setSelectedEvidence] = useState<Case | null>(null);
  const [evidenceLoading, setEvidencesLoading] = useState<boolean>(false);

  const CHUNK_SIZE = 5 * 1024 * 1024; // 5MB

  const createFileChunks = (file: File) => {
    const chunks = [];
    let currentPointer = 0;

    while (currentPointer < file.size) {
      const chunk = file.slice(currentPointer, currentPointer + CHUNK_SIZE);
      chunks.push(chunk);
      currentPointer += CHUNK_SIZE;
    }

    return chunks;
  };

  useEffect(() => {
    if (open) {
      if (caseId) {
        // If caseId is provided, set the selectedEvidence directly
        setSelectedEvidence({ id: caseId } as Case);
        setEvidencesLoading(false);
      } else {
        fetchCases();
      }
    }
  }, [open, caseId]);

  const fetchCases = async () => {
    setEvidencesLoading(true);
    try {
      const response = await axiosInstance.get<Case[]>("/api/cases/");
      setCases(response.data);
    } catch (err) {
      console.error("Error fetching cases:", err);
      setError("Failed to load cases.");
    } finally {
      setEvidencesLoading(false);
    }
  };

  const handleUpload = async () => {
    if (!os || !file || (!selectedEvidence && !caseId)) {
      setError("Please fill in all fields.");
      return;
    }

    setUploading(true);
    setError(null);

    const uploadCaseId = caseId || selectedEvidence?.id;

    try {
      const initiateResponse = await axiosInstance.post(
        `/api/cases/upload/initiate/`,
        {
          filename: file.name,
          case_id: uploadCaseId,
          os: os,
        },
      );
      const uploadId = initiateResponse.data.upload_id;

      const chunks = createFileChunks(file);

      let uploadedSize = 0;

      for (let index = 0; index < chunks.length; index++) {
        const chunk = chunks[index];
        const partNumber = index + 1;

        const formData = new FormData();
        formData.append("chunk", chunk, file.name + ".part" + partNumber);
        formData.append("upload_id", uploadId);
        formData.append("part_number", partNumber.toString());
        formData.append("filename", file.name);

        await axiosInstance.post(`/api/cases/upload/chunk/`, formData);

        uploadedSize += chunk.size;
        const percentage = Math.round((uploadedSize / file.size) * 100);
        setUploadProgress(percentage);
      }

      try {
        const completeUploadResponse = await axiosInstance.post(
          `/api/cases/upload/complete/`,
          {
            upload_id: uploadId,
          },
        );
        onCreateSuccess(completeUploadResponse.data);
      } catch (error) {
        console.error("Complete upload failed:", error);
        onCreateFailed(error);
      }
      onClose();
      setUploading(false);
      setOs("");
      setFile(null);
      setUploadProgress(null);
    } catch (err) {
      console.error("Upload error:", err);
      setError(`Upload failed: ${err}`);
      setUploading(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth>
      <DialogTitle>Upload a new evidence</DialogTitle>
      <DialogContent>
        {evidenceLoading ? (
          <div style={{ textAlign: "center", marginTop: "20px" }}>
            <CircularProgress />
          </div>
        ) : (
          <>
            {!caseId && (
              <Autocomplete
                options={cases}
                getOptionLabel={(option) => option.name}
                value={selectedEvidence}
                onChange={(_event, newValue) => {
                  setSelectedEvidence(newValue);
                }}
                renderInput={(params) => (
                  <TextField
                    {...params}
                    label="Linked Case"
                    margin="dense"
                    fullWidth
                    required
                  />
                )}
              />
            )}
            <FormControl fullWidth margin="dense">
              <InputLabel id="os-select-label">Source OS</InputLabel>
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
              variant="outlined"
              component="label"
              style={{ marginTop: 16 }}
              color="secondary"
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
        <Button onClick={onClose} disabled={uploading || evidenceLoading}>
          Cancel
        </Button>
        <Button
          onClick={handleUpload}
          variant="outlined"
          color="error"
          disabled={
            uploading || (!selectedEvidence && !caseId) || evidenceLoading
          }
        >
          Upload
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default EvidenceCreationDialog;
