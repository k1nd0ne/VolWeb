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
  FormControl,
  InputLabel,
  Autocomplete,
  CircularProgress,
} from "@mui/material";
import axiosInstance from "../../utils/axiosInstance";
import { Evidence, Case } from "../../types";

interface BindEvidenceDialogProps {
  open: boolean;
  onClose: () => void;
  onBindSuccess: (newEvidence: Evidence) => void;
  caseId?: number;
}

const BindEvidenceDialog: React.FC<BindEvidenceDialogProps> = ({
  open,
  onClose,
  onBindSuccess,
  caseId,
}) => {
  const OS_OPTIONS = [
    { value: "windows", label: "Windows" },
    { value: "linux", label: "Linux" },
  ];

  const SOURCES = [
    { value: "AWS", label: "AWS" },
    { value: "MINIO", label: "MinIO" },
  ];

  const [os, setOs] = useState<string>("");
  const [source, setSource] = useState<string>("");
  const [accessKeyId, setAccessKeyId] = useState<string>("");
  const [accessKey, setAccessKey] = useState<string>("");
  const [url, setUrl] = useState<string>("");
  const [region, setRegion] = useState<string>("");
  const [endpoint, setEndpoint] = useState<string>("");

  const [error, setError] = useState<string | null>(null);

  const [cases, setCases] = useState<Case[]>([]);
  const [selectedCase, setSelectedCase] = useState<Case | null>(null);
  const [casesLoading, setCasesLoading] = useState<boolean>(false);

  useEffect(() => {
    if (open) {
      if (caseId) {
        setSelectedCase({ id: caseId } as Case);
        setCasesLoading(false);
      } else {
        fetchCases();
      }
      // Reset form fields
      setOs("");
      setSource("");
      setAccessKeyId("");
      setAccessKey("");
      setUrl("");
      setRegion("");
      setEndpoint("");
      setError(null);
    }
  }, [open, caseId]);

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

  const handleBind = async () => {
    // Validation logic
    const missingFields = [];

    if (!os) missingFields.push("Operating System");
    if (!selectedCase && !caseId) missingFields.push("Linked Case");
    if (!source) missingFields.push("Source");
    if (!accessKeyId) missingFields.push("Access Key ID");
    if (!accessKey) missingFields.push("Access Key");
    if (!url) missingFields.push("URL");
    if (source === "AWS" && !region) missingFields.push("Region");
    if (source === "MINIO" && !endpoint) missingFields.push("Endpoint");

    if (missingFields.length > 0) {
      setError(`Please fill in all fields: ${missingFields.join(", ")}.`);
      return;
    }

    // Prepare data
    const data: any = {
      os,
      linked_case: caseId || selectedCase!.id,
      source,
      access_key_id: accessKeyId,
      access_key: accessKey,
      url,
    };

    if (source === "AWS") {
      data.region = region;
    } else if (source === "MINIO") {
      data.endpoint = endpoint;
    }

    try {
      const response = await axiosInstance.post<Evidence>(
        "/api/evidences/bind/",
        data,
      );
      onBindSuccess(response.data);
      onClose();
      // Reset form fields
      setOs("");
      setSource("");
      setAccessKeyId("");
      setAccessKey("");
      setUrl("");
      setRegion("");
      setEndpoint("");
      setError(null);
    } catch (error: any) {
      setError(
        `Failed to bind evidence: ${
          error.response && error.response.data
            ? error.response.data.detail
            : error.message
        }`,
      );
    }
  };

  const handleSourceChange = (
    event: React.ChangeEvent<{ name?: string; value: unknown }>,
  ) => {
    const newSource = event.target.value as string;
    setSource(newSource);
    setError(null);

    // Reset fields not needed for the selected source
    if (newSource === "AWS") {
      setEndpoint("");
    } else if (newSource === "MINIO") {
      setRegion("");
    }
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth>
      <DialogTitle>Bind Existing Evidence</DialogTitle>
      <DialogContent>
        {casesLoading ? (
          <div style={{ textAlign: "center", marginTop: "20px" }}>
            <CircularProgress />
          </div>
        ) : (
          <>
            {!caseId && (
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
            <FormControl fullWidth margin="dense">
              <InputLabel id="source-select-label">Source</InputLabel>
              <Select
                labelId="source-select-label"
                label="Source"
                value={source}
                onChange={handleSourceChange}
              >
                {SOURCES.map((option) => (
                  <MenuItem key={option.value} value={option.value}>
                    {option.label}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            <TextField
              label="Access Key ID"
              margin="dense"
              fullWidth
              required
              value={accessKeyId}
              onChange={(e) => setAccessKeyId(e.target.value)}
            />
            <TextField
              label="Access Key"
              margin="dense"
              fullWidth
              required
              type="password"
              value={accessKey}
              onChange={(e) => setAccessKey(e.target.value)}
            />
            <TextField
              label="URL"
              margin="dense"
              fullWidth
              required
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
            {/* Conditionally render Region or Endpoint based on Source */}
            {source === "AWS" && (
              <TextField
                label="Region"
                margin="dense"
                fullWidth
                required
                value={region}
                onChange={(e) => setRegion(e.target.value)}
              />
            )}
            {source === "MINIO" && (
              <TextField
                label="Endpoint"
                margin="dense"
                fullWidth
                required
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
              />
            )}
            {error && (
              <div style={{ color: "red", marginTop: 16 }}>{error}</div>
            )}
          </>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={casesLoading}>
          Cancel
        </Button>
        <Button
          onClick={handleBind}
          variant="contained"
          disabled={casesLoading || (!selectedCase && !caseId)}
        >
          Bind
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default BindEvidenceDialog;
