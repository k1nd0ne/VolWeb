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
import axios from "axios";
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
      // Step 1: Initiate Multipart Upload
      const initiateResponse = await axiosInstance.post(
        `/api/cases/${uploadCaseId}/initiate-multipart-upload/`,
        {
          filename: file.name,
        },
      );
      const uploadId = initiateResponse.data.upload_id;

      // Step 2: Split File into Chunks
      const chunks = createFileChunks(file);
      //const totalChunks = chunks.length;

      // Store ETags of uploaded parts
      const parts: { ETag: string; PartNumber: number }[] = [];

      let uploadedSize = 0;

      for (let index = 0; index < chunks.length; index++) {
        const chunk = chunks[index];
        const partNumber = index + 1;

        // Step 3: Get Presigned URL for Each Part
        const presignedUrlResponse = await axiosInstance.get(
          `/api/cases/${uploadCaseId}/generate-presigned-url-for-part/`,
          {
            params: {
              filename: file.name,
              upload_id: uploadId,
              part_number: partNumber,
            },
          },
        );
        const originalUrl = new URL(presignedUrlResponse.data.url);
        const presignedUrl = `/minio${originalUrl.pathname}${originalUrl.search}`;
        console.log(`${presignedUrl}`);

        // Step 4: Upload Each Chunk
        const uploadResponse = await axios.put(presignedUrl, chunk, {
          headers: {
            "Content-Type": "application/octet-stream",
          },
          onUploadProgress: (progressEvent) => {
            if (progressEvent.total) {
              uploadedSize += progressEvent.loaded;
              const percentage = Math.round((uploadedSize / file.size) * 100);
              setUploadProgress(percentage);
            }
          },
        });

        // Extract ETag from headers
        let etag = uploadResponse.headers.etag;
        if (!etag) {
          // Try to get ETag from the response data (if any)
          console.error("ETag not found in response headers.");
          setError("ETag not found in response headers.");
          setUploading(false);
          return;
        }

        // Remove quotes from ETag if present
        etag = etag.replace(/"/g, "");

        // Store the ETag and PartNumber
        parts.push({ ETag: etag, PartNumber: partNumber });
      }

      // Step 5: Comple Multipart Upload
      const completeResponse = await axiosInstance.post(
        `/api/cases/${uploadCaseId}/complete-multipart-upload/`,
        {
          filename: file.name,
          upload_id: uploadId,
          parts: parts,
        },
      );

      // For example, log the response status
      console.log("Upload completed:", completeResponse.status);

      // Step 6: Create Evidence Record
      try {
        const newEvidenceResp = await axiosInstance.post<Evidence>(
          "/api/evidences/",
          {
            name: file.name,
            os,
            linked_case: uploadCaseId,
            etag: parts[parts.length - 1].ETag,
          },
        );
        onCreateSuccess(newEvidenceResp.data);
        onClose();
      } catch (error) {
        onCreateFailed(error);
        console.log(error);
      }

      setUploading(false);
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
                    label="Select Case"
                    margin="dense"
                    fullWidth
                    required
                  />
                )}
              />
            )}
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
        <Button onClick={onClose} disabled={uploading || evidenceLoading}>
          Cancel
        </Button>
        <Button
          onClick={handleUpload}
          variant="contained"
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
