import React, { useState, useEffect } from "react";
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Box,
  Typography,
  IconButton,
  Alert,
  CircularProgress,
  useTheme,
  Paper,
  Tooltip,
} from "@mui/material";
import {
  Close as CloseIcon,
  Save as SaveIcon,
  FileCopy as FileCopyIcon,
  Edit as EditIcon,
  Visibility as VisibilityIcon,
} from "@mui/icons-material";
import { Editor } from "@monaco-editor/react";
import axiosInstance from "../../utils/axiosInstance";
import { YaraRule, YaraRuleSet } from "../../types";
import { useSnackbar } from "../../components/SnackbarProvider";

interface YaraRuleEditDialogProps {
  open: boolean;
  onClose: () => void;
  yaraRule: YaraRule | null;
  onUpdateSuccess?: (updatedRule: YaraRule) => void;
  yaraRuleSets?: YaraRuleSet[];
}

const YaraRuleEditDialog: React.FC<YaraRuleEditDialogProps> = ({
  open,
  onClose,
  yaraRule,
  onUpdateSuccess,
  yaraRuleSets = [],
}) => {
  const theme = useTheme();
  const { display_message } = useSnackbar();
  const [editMode, setEditMode] = useState(false);
  const [saving, setSaving] = useState(false);
  const [validating, setValidating] = useState(false);
  
  // Form fields
  const [ruleName, setRuleName] = useState("");
  const [ruleContent, setRuleContent] = useState("");
  const [description, setDescription] = useState("");
  const [selectedRulesetId, setSelectedRulesetId] = useState<number | null>(null);
  const [saveMode, setSaveMode] = useState<"overwrite" | "copy">("overwrite");
  const [newRuleName, setNewRuleName] = useState("");
  
  // Validation state
  const [validationError, setValidationError] = useState<string | null>(null);

  useEffect(() => {
    if (yaraRule) {
      setRuleName(yaraRule.name || "");
      setRuleContent(yaraRule.rule_content || "");
      setDescription(yaraRule.description || "");
      setSelectedRulesetId(yaraRule.linked_yararuleset?.id || null);
      setNewRuleName(yaraRule.name ? `${yaraRule.name}_copy` : "");
      // Set edit mode to true if creating a new rule (id === 0)
      setEditMode(yaraRule.id === 0);
      setValidationError(null);
    }
  }, [yaraRule]);

  const handleClose = () => {
    if (!saving) {
      setEditMode(false);
      setSaveMode("overwrite");
      setValidationError(null);
      onClose();
    }
  };

  const validateRuleContent = async (content: string): Promise<boolean> => {
    try {
      setValidating(true);
      setValidationError(null);
      
      // Send to backend for validation
      const response = await axiosInstance.post("/api/yararules/validate/", {
        rule_content: content,
      });
      
      if (response.data.valid) {
        return true;
      } else {
        setValidationError(response.data.error || "Invalid YARA rule syntax");
        return false;
      }
    } catch (error: any) {
      setValidationError(error.response?.data?.error || "Failed to validate rule");
      return false;
    } finally {
      setValidating(false);
    }
  };

  const handleSave = async () => {
    if (!yaraRule) return;

    // Validate before saving
    const isValid = await validateRuleContent(ruleContent);
    if (!isValid) {
      display_message("error", "Please fix the validation errors before saving");
      return;
    }

    try {
      setSaving(true);

      if (yaraRule.id === 0) {
        // Creating a brand new rule
        const response = await axiosInstance.post("/api/yararules/", {
          name: ruleName,
          rule_content: ruleContent,
          description: description,
          linked_yararuleset: selectedRulesetId,
          source: "custom",
          etag: `${ruleName}_${Date.now()}`,
          is_active: true,
        });
        
        display_message("success", "YARA rule created successfully");
        if (onUpdateSuccess) {
          onUpdateSuccess(response.data);
        }
      } else if (saveMode === "overwrite") {
        // Update existing rule
        const response = await axiosInstance.patch(`/api/yararules/${yaraRule.id}/`, {
          name: ruleName,
          rule_content: ruleContent,
          description: description,
          linked_yararuleset: selectedRulesetId,
        });
        
        display_message("success", "YARA rule updated successfully");
        if (onUpdateSuccess) {
          onUpdateSuccess(response.data);
        }
      } else {
        // Create new rule as a copy
        const response = await axiosInstance.post("/api/yararules/", {
          name: newRuleName,
          rule_content: ruleContent,
          description: description,
          linked_yararuleset: selectedRulesetId,
          source: "copy",
          etag: `${newRuleName}_${Date.now()}`,
          is_active: true,
        });
        
        display_message("success", "YARA rule copied successfully");
        if (onUpdateSuccess) {
          onUpdateSuccess(response.data);
        }
      }
      
      handleClose();
    } catch (error: any) {
      const data = error.response?.data;
      let detail: string = error.message;
      if (typeof data === "string") {
        detail = data;
      } else if (data?.error) {
        detail = data.error;
      } else if (data && typeof data === "object") {
        // Surface DRF field errors (e.g. duplicate content on rule_content)
        const first = data.rule_content ?? Object.values(data)[0];
        detail = Array.isArray(first) ? first[0] : String(first);
      }
      display_message("error", `Failed to save YARA rule: ${detail}`);
    } finally {
      setSaving(false);
    }
  };

  const handleEditorChange = (value: string | undefined) => {
    setRuleContent(value || "");
    setValidationError(null); // Clear error when user types
  };

  if (!yaraRule) return null;

  return (
    <Dialog
      open={open}
      onClose={handleClose}
      maxWidth="lg"
      fullWidth
      PaperProps={{
        sx: {
          backgroundColor: theme.palette.mode === 'dark' ? '#1e1e1e' : '#f5f5f5',
        }
      }}
    >
      <DialogTitle sx={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center',
        backgroundColor: theme.palette.mode === 'dark' ? '#2d2d2d' : '#e0e0e0',
      }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography variant="h6">
            {yaraRule.id === 0 ? "Create New YARA Rule" : editMode ? "Edit YARA Rule" : "View YARA Rule"}
          </Typography>
          {yaraRule.name && yaraRule.id !== 0 && (
            <Typography variant="subtitle2" color="text.secondary">
              ({yaraRule.name})
            </Typography>
          )}
        </Box>
        <Box>
          {!editMode && (
            <Tooltip title="Edit Rule">
              <IconButton onClick={() => setEditMode(true)} color="primary">
                <EditIcon />
              </IconButton>
            </Tooltip>
          )}
          <IconButton onClick={handleClose} disabled={saving}>
            <CloseIcon />
          </IconButton>
        </Box>
      </DialogTitle>
      
      <DialogContent sx={{ p: 0 }}>
        <Box sx={{ p: 2 }}>
          {editMode && yaraRule.id !== 0 && (
            <>
              <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
                <FormControl sx={{ minWidth: 200 }}>
                  <InputLabel>Save Mode</InputLabel>
                  <Select
                    value={saveMode}
                    onChange={(e) => setSaveMode(e.target.value as any)}
                    label="Save Mode"
                    size="small"
                  >
                    <MenuItem value="overwrite">
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <SaveIcon fontSize="small" />
                        Overwrite Existing
                      </Box>
                    </MenuItem>
                    <MenuItem value="copy">
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <FileCopyIcon fontSize="small" />
                        Save as Copy
                      </Box>
                    </MenuItem>
                  </Select>
                </FormControl>

                {saveMode === "copy" && (
                  <TextField
                    label="New Rule Name"
                    value={newRuleName}
                    onChange={(e) => setNewRuleName(e.target.value)}
                    size="small"
                    required
                    sx={{ flex: 1 }}
                  />
                )}
              </Box>

              <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
                <TextField
                  label="Rule Name"
                  value={ruleName}
                  onChange={(e) => setRuleName(e.target.value)}
                  size="small"
                  disabled={saveMode === "copy"}
                  sx={{ flex: 1 }}
                />
                
                <FormControl sx={{ minWidth: 200 }}>
                  <InputLabel>Ruleset</InputLabel>
                  <Select
                    value={selectedRulesetId || ""}
                    onChange={(e) => setSelectedRulesetId(e.target.value as number)}
                    label="Ruleset"
                    size="small"
                  >
                    <MenuItem value="">
                      <em>None</em>
                    </MenuItem>
                    {yaraRuleSets.map((ruleset) => (
                      <MenuItem key={ruleset.id} value={ruleset.id}>
                        {ruleset.name}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Box>

              <TextField
                label="Description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                multiline
                rows={2}
                fullWidth
                size="small"
                sx={{ mb: 2 }}
              />
            </>
          )}

          {editMode && yaraRule.id === 0 && (
            <>
              <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
                <TextField
                  label="Rule Name"
                  value={ruleName}
                  onChange={(e) => setRuleName(e.target.value)}
                  size="small"
                  required
                  sx={{ flex: 1 }}
                />
                
                <FormControl sx={{ minWidth: 200 }}>
                  <InputLabel>Ruleset</InputLabel>
                  <Select
                    value={selectedRulesetId || ""}
                    onChange={(e) => setSelectedRulesetId(e.target.value as number)}
                    label="Ruleset"
                    size="small"
                  >
                    <MenuItem value="">
                      <em>None</em>
                    </MenuItem>
                    {yaraRuleSets.map((ruleset) => (
                      <MenuItem key={ruleset.id} value={ruleset.id}>
                        {ruleset.name}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Box>

              <TextField
                label="Description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                multiline
                rows={2}
                fullWidth
                size="small"
                sx={{ mb: 2 }}
              />
            </>
          )}

          {validationError && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {validationError}
            </Alert>
          )}

          <Paper 
            variant="outlined" 
            sx={{ 
              height: editMode ? '400px' : '500px',
              backgroundColor: theme.palette.mode === 'dark' ? '#1e1e1e' : '#ffffff',
            }}
          >
            <Editor
              height="100%"
              defaultLanguage="yara"
              language="yara"
              value={ruleContent}
              onChange={handleEditorChange}
              theme={theme.palette.mode === 'dark' ? "vs-dark" : "light"}
              options={{
                readOnly: !editMode,
                minimap: { enabled: false },
                fontSize: 14,
                wordWrap: 'on',
                lineNumbers: 'on',
                scrollBeyondLastLine: false,
                automaticLayout: true,
                tabSize: 2,
              }}
            />
          </Paper>
        </Box>
      </DialogContent>
      
      <DialogActions sx={{
        backgroundColor: theme.palette.mode === 'dark' ? '#2d2d2d' : '#e0e0e0',
      }}>
        {editMode ? (
          <>
            <Button 
              onClick={() => setEditMode(false)} 
              disabled={saving || validating}
            >
              Cancel
            </Button>
            <Button
              onClick={handleSave}
              variant="contained"
              color="primary"
              disabled={saving || validating || !ruleContent.trim() || (saveMode === "copy" && !newRuleName.trim()) || (yaraRule.id === 0 && !ruleName.trim())}
              startIcon={saving ? <CircularProgress size={16} /> : <SaveIcon />}
            >
              {saving ? "Saving..." : yaraRule.id === 0 ? "Create Rule" : saveMode === "overwrite" ? "Save Changes" : "Save as Copy"}
            </Button>
          </>
        ) : (
          <>
            <Button onClick={() => setEditMode(true)} startIcon={<EditIcon />}>
              Edit Rule
            </Button>
            <Button onClick={handleClose} color="primary">
              Close
            </Button>
          </>
        )}
      </DialogActions>
    </Dialog>
  );
};

export default YaraRuleEditDialog;