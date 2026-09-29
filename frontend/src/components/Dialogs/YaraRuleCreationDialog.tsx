import React, { useState, useEffect } from "react";
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  FormControl,
  Autocomplete,
  LinearProgress,
  CircularProgress,
  Box,
  Typography,
  Link,
  Alert,
  InputLabel,
  Select,
  MenuItem,
  Tabs,
  Tab,
} from "@mui/material";
import {
  CloudUpload as CloudUploadIcon,
  CloudDownload as CloudDownloadIcon,
} from "@mui/icons-material";
import axiosInstance from "../../utils/axiosInstance";
import { YaraRuleSet } from "../../types";

export interface ImportSummary {
  created: number;
  skipped: number;
}

interface YaraRuleCreationDialogProps {
  open: boolean;
  onClose: () => void;
  onCreateSuccess: (summary: ImportSummary) => void;
  onImportSuccess: (summary: ImportSummary) => void;
  onCreateFailed?: (error: unknown) => void;
  onImportFailed?: (error: string) => void;
  yara_ruleset?: YaraRuleSet;
}

const YaraRuleCreationDialog: React.FC<YaraRuleCreationDialogProps> = ({
  open,
  onClose,
  onCreateSuccess,
  onImportSuccess,
  onCreateFailed,
  onImportFailed,
  yara_ruleset,
}) => {
  const [tabIndex, setTabIndex] = useState(0);

  const [yaraRuleSets, setYaraRuleSets] = useState<YaraRuleSet[]>([]);
  const [loadingSets, setLoadingSets] = useState(false);

  const [uploadDescription, setUploadDescription] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploadRuleset, setUploadRuleset] = useState<YaraRuleSet | null>(null);
  const [uploadMode, setUploadMode] = useState<"standalone" | "existing" | "new">("standalone");
  const [newRulesetName, setNewRulesetName] = useState("");

  const [githubUrl, setGithubUrl] = useState("");
  const [githubDescription, setGithubDescription] = useState("");
  const [githubMode, setGithubMode] = useState<"standalone" | "existing" | "new">("standalone");
  const [githubRuleset, setGithubRuleset] = useState<YaraRuleSet | null>(null);
  const [importing, setImporting] = useState(false);
  const [githubError, setGithubError] = useState<string | null>(null);
  const [githubValidationError, setGithubValidationError] = useState<string | null>(null);

  const CHUNK_SIZE = 5 * 1024 * 1024;

  useEffect(() => {
    if (open) {
      setTabIndex(0);
      resetForm();
      fetchSets();
    }
  }, [open]);

  const resetForm = () => {
    setUploadDescription("");
    setFile(null);
    setUploadProgress(null);
    setUploadError(null);
    setUploadRuleset(null);
    setUploadMode("standalone");
    setNewRulesetName("");

    setGithubUrl("");
    setGithubDescription("");
    setGithubError(null);
    setGithubValidationError(null);
    setGithubRuleset(null);
    setGithubMode("standalone");
  };

  const fetchSets = async () => {
    setLoadingSets(true);
    try {
      const res = await axiosInstance.get<YaraRuleSet[]>("/api/yararulesets/");
      setYaraRuleSets(res.data);
    } catch (err) {
      console.error("Error fetching rulesets", err);
    } finally {
      setLoadingSets(false);
    }
  };

  const handleUpload = async () => {
    if (!file) {
      setUploadError("Please select a file.");
      return;
    }

    let rulesetId: number | null = null;

    try {
      if (uploadMode === "existing") {
        const rs = yara_ruleset || uploadRuleset;
        if (!rs) {
          setUploadError("Select a target ruleset.");
          return;
        }
        rulesetId = rs.id;
      } else if (uploadMode === "new") {
        if (!newRulesetName.trim()) {
          setUploadError("Please enter a name for the new ruleset.");
          return;
        }
        const createRes = await axiosInstance.post("/api/yararulesets/", {
          name: newRulesetName.trim(),
          description: `Created via upload dialog.`,
        });
        rulesetId = createRes.data.id;
      }

      setUploading(true);
      setUploadError(null);

      const initRes = await axiosInstance.post("/api/yararulesets/upload/initiate/", {
        filename: file.name,
        yara_ruleset_id: rulesetId,
        source: "custom",
        description: uploadDescription,
      });

      const uploadId = initRes.data.upload_id;
      const chunks = [];
      let currentPointer = 0;

      while (currentPointer < file.size) {
        const chunk = file.slice(currentPointer, currentPointer + CHUNK_SIZE);
        chunks.push(chunk);
        currentPointer += CHUNK_SIZE;
      }

      let uploadedSize = 0;
      for (let i = 0; i < chunks.length; i++) {
        const formData = new FormData();
        formData.append("chunk", chunks[i], `${file.name}.part${i + 1}`);
        formData.append("upload_id", uploadId);
        formData.append("part_number", `${i + 1}`);
        formData.append("filename", file.name);

        await axiosInstance.post("/api/yararulesets/upload/chunk/", formData);
        uploadedSize += chunks[i].size;
        setUploadProgress(Math.round((uploadedSize / file.size) * 100));
      }

      const completeRes = await axiosInstance.post("/api/yararulesets/upload/complete/", {
        upload_id: uploadId,
      });

      onCreateSuccess({
        created: completeRes.data?.rules_created ?? 0,
        skipped: completeRes.data?.skipped_duplicates ?? 0,
      });
      handleClose();
    } catch (err) {
      console.error("Upload failed", err);
      setUploadError("Upload failed.");
      if (onCreateFailed) onCreateFailed(err);
    } finally {
      setUploading(false);
    }
  };

  const handleGithubImport = async () => {
    if (!githubUrl) {
      setGithubError("Please enter a GitHub URL.");
      return;
    }

    if (!validateGithubUrl(githubUrl)) {
      setGithubError("Invalid GitHub URL.");
      return;
    }

    setImporting(true);
    setGithubError(null);

    try {
      let rulesetId = null;

      if (githubMode === "existing") {
        const rs = yara_ruleset || githubRuleset;
        if (!rs) {
          setGithubError("Select a target ruleset.");
          return;
        }
        rulesetId = rs.id;
      } else if (githubMode === "new") {
        const path = githubUrl.replace(/\/$/, "").split("/").slice(-2).join("/");
        const rulesetName = `GitHub - ${path}`;
        const res = await axiosInstance.post("/api/yararulesets/", {
          name: rulesetName,
          description: `Automatically created from ${githubUrl}`,
        });
        rulesetId = res.data.id;
      }

      const response = await axiosInstance.post("/api/yararulesets/import/github/", {
        github_url: githubUrl,
        yara_ruleset_id: rulesetId,
        description: githubDescription || `Imported from ${githubUrl}`,
      });

      if (response.data.success) {
        onImportSuccess({
          created: response.data?.imported_count ?? 0,
          skipped: response.data?.skipped_duplicates ?? 0,
        });
        handleClose();
      } else {
        setGithubError(response.data.error || "Import failed.");
        if (onImportFailed) onImportFailed(response.data.error || "Import failed.");
      }
    } catch (err: any) {
      console.error("GitHub import failed", err);
      setGithubError(err.message || "Import failed.");
    } finally {
      setImporting(false);
    }
  };

  const validateGithubUrl = (url: string) =>
    /^https?:\/\/(www\.)?github\.com\/[\w-]+\/[\w.-]+/.test(url);

  const handleClose = () => {
    if (!uploading && !importing) {
      resetForm();
      onClose();
    }
  };

  return (
    <Dialog open={open} onClose={handleClose} fullWidth maxWidth="sm">
      <DialogTitle>
        <Tabs value={tabIndex} onChange={(_, val) => { if (!uploading && !importing) setTabIndex(val); }}>
          <Tab label="Upload from File" disabled={uploading || importing} />
          <Tab label="Import from GitHub" disabled={uploading || importing} />
        </Tabs>
      </DialogTitle>
      <DialogContent dividers>
        {uploading ? (
          <Box sx={{ textAlign: "center", py: 4 }}>
            <Typography variant="body1" gutterBottom>
              Uploading file...
            </Typography>
            <LinearProgress variant="determinate" value={uploadProgress || 0} sx={{ my: 2 }} />
            <Typography variant="body2" color="text.secondary">
              {uploadProgress}%
            </Typography>
            {uploadError && <Alert severity="error" sx={{ mt: 2 }}>{uploadError}</Alert>}
          </Box>
        ) : importing ? (
          <Box sx={{ textAlign: "center", py: 4 }}>
            <CircularProgress sx={{ mb: 2 }} />
            <Typography variant="body1">
              Importing from GitHub...
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              This may take a while depending on the repository size.
            </Typography>
            {githubError && <Alert severity="error" sx={{ mt: 2 }}>{githubError}</Alert>}
          </Box>
        ) : tabIndex === 0 ? (
          <>
            <FormControl fullWidth margin="normal">
              <InputLabel id="upload-mode-label">Upload Mode</InputLabel>
              <Select
                labelId="upload-mode-label"
                id="upload-mode"
                value={uploadMode}
                label="Upload Mode"
                onChange={(e) => setUploadMode(e.target.value as any)}
              >
                <MenuItem value="standalone">Standalone</MenuItem>
                <MenuItem value="existing">Assign to existing ruleset</MenuItem>
                <MenuItem value="new">Create new ruleset</MenuItem>
              </Select>
            </FormControl>

            {uploadMode === "existing" && !yara_ruleset && (
              <FormControl fullWidth margin="normal">
                <Autocomplete
                  options={yaraRuleSets}
                  getOptionLabel={(opt) => opt.name}
                  onChange={(_, val) => setUploadRuleset(val)}
                  renderInput={(params) => (
                    <TextField {...params} label="Select Existing Ruleset" />
                  )}
                />
              </FormControl>
            )}

            {uploadMode === "new" && (
              <TextField
                label="New Ruleset Name"
                id="new-ruleset-name"
                fullWidth
                margin="normal"
                value={newRulesetName}
                onChange={(e) => setNewRulesetName(e.target.value)}
              />
            )}

            <TextField
              label="Description (Optional)"
              fullWidth
              multiline
              rows={3}
              value={uploadDescription}
              onChange={(e) => setUploadDescription(e.target.value)}
              margin="normal"
            />
            <Button variant="outlined" component="label" color="secondary" sx={{ mt: 2 }}>
              Select File *
              <input type="file" hidden onChange={(e) => setFile(e.target.files?.[0] || null)} />
            </Button>
            {file && <div style={{ marginTop: 8 }}>Selected: {file.name}</div>}
            {uploadError && <Alert severity="error">{uploadError}</Alert>}
          </>
        ) : (
          <>
            <TextField
              fullWidth
              label="GitHub Repository URL"
              value={githubUrl}
              onChange={(e) => {
                const val = e.target.value;
                setGithubUrl(val);
                setGithubValidationError(
                  val && !validateGithubUrl(val) ? "Invalid GitHub URL" : null
                );
              }}
              error={!!githubValidationError}
              helperText={githubValidationError}
              margin="normal"
            />

            <Box sx={{ mt: 1, mb: 2 }}>
              <Typography variant="caption" color="text.secondary">
                Example repositories:
              </Typography>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5, mt: 0.5 }}>
                {[
                  "https://github.com/Yara-Rules/rules",
                  "https://github.com/Neo23x0/signature-base",
                  "https://github.com/bartblaze/Yara-rules",
                ].map((url, index) => (
                  <Link
                    key={index}
                    component="button"
                    variant="caption"
                    onClick={() => setGithubUrl(url)}
                    sx={{ textAlign: 'left' }}
                  >
                    {url}
                  </Link>
                ))}
              </Box>
            </Box>

            <FormControl fullWidth margin="normal">
              <InputLabel id="github-mode-label">Import Mode</InputLabel>
              <Select
                labelId="github-mode-label"
                id="github-mode"
                value={githubMode}
                label="Import Mode"
                onChange={(e) => setGithubMode(e.target.value as any)}
              >
                <MenuItem value="standalone">Standalone</MenuItem>
                <MenuItem value="existing">Assign to existing ruleset</MenuItem>
                <MenuItem value="new">
                  Create new ruleset (name will be based on repo path)
                </MenuItem>
              </Select>
            </FormControl>

            {githubMode === "existing" && !yara_ruleset && (
              <Autocomplete
                options={yaraRuleSets}
                getOptionLabel={(o) => o.name}
                onChange={(_, val) => setGithubRuleset(val)}
                renderInput={(params) => <TextField {...params} label="Target Ruleset" />}
              />
            )}
            <TextField
              fullWidth
              label="Description (Optional)"
              multiline
              rows={3}
              value={githubDescription}
              onChange={(e) => setGithubDescription(e.target.value)}
              margin="normal"
            />
            {githubError && <Alert severity="error">{githubError}</Alert>}
          </>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={handleClose} disabled={uploading || importing}>
          Cancel
        </Button>
        {tabIndex === 0 ? (
          <Button
            variant="contained"
            color="error"
            onClick={handleUpload}
            disabled={uploading || !file}
            startIcon={<CloudUploadIcon />}
          >
            {uploading ? "Uploading..." : "Upload"}
          </Button>
        ) : (
          <Button
            variant="contained"
            color="primary"
            onClick={handleGithubImport}
            disabled={importing || !!githubValidationError || !githubUrl}
            startIcon={<CloudDownloadIcon />}
          >
            {importing ? "Importing..." : "Import"}
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
};

export default YaraRuleCreationDialog;
