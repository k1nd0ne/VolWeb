import React, { useState, useCallback, useEffect, useRef } from "react";
import {
  Box,
  Button,
  IconButton,
  Paper,
  Typography,
  List,
  ListItem,
  ListItemText,
  Checkbox,
  FormControlLabel,
  Divider,
  Alert,
  Chip,
  CircularProgress,
  TextField,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Tooltip,
  InputAdornment,
} from "@mui/material";
import {
  ArrowBack,
  Extension,
  PlayArrow,
  ExpandMore,
  Lock,
  Timeline,
  CheckCircle,
  ErrorOutline,
  RemoveCircleOutline,
  Timer,
  TimerOff,
  Search,
} from "@mui/icons-material";
import axiosInstance from "../../utils/axiosInstance";
import { AvailablePlugin, AvailablePluginsResponse } from "../../types";
import { useSnackbar } from "../SnackbarProvider";

interface PluginSelectorProps {
  evidenceId: string;
  evidenceOs: string;
  onExtractionStarted?: () => void;
  onBack?: () => void;
}

// Required plugins that cannot be deselected
const REQUIRED_PLUGINS: { [os: string]: string[] } = {
  windows: [
    "volatility3.plugins.windows.pslist.PsList",
    "volatility3.plugins.windows.pstree.PsTree",
  ],
  linux: [
    "volatility3.plugins.linux.pslist.PsList",
    "volatility3.plugins.linux.pstree.PsTree",
  ],
};

const categoryColors: { [key: string]: "primary" | "secondary" | "success" | "warning" | "error" | "info" } = {
  Malware: "primary",
  Processes: "secondary",
  Security: "success",
  Kernel: "warning",
  Filesystem: "error",
  Network: "info",
  Registry: "primary",
  GUI: "info",
  Services: "secondary",
  "Code Injection": "error",
  Memory: "warning",
  Other: "info",
};

const PluginSelector: React.FC<PluginSelectorProps> = ({
  evidenceId,
  evidenceOs,
  onExtractionStarted,
  onBack,
}) => {
  const { display_message } = useSnackbar();
  const ws = useRef<WebSocket | null>(null);

  const [categories, setCategories] = useState<{ [key: string]: AvailablePlugin[] }>({});
  const [totalPlugins, setTotalPlugins] = useState(0);
  const [selectedPlugins, setSelectedPlugins] = useState<string[]>([]);
  const [runTimeliner, setRunTimeliner] = useState(false);
  const [pidFilter, setPidFilter] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [processing, setProcessing] = useState(false);
  const [skipCompleted, setSkipCompleted] = useState(true);
  const [hasExecutedPlugins, setHasExecutedPlugins] = useState(false);
  const [enableTimeout, setEnableTimeout] = useState(false);
  const [pluginTimeout, setPluginTimeout] = useState<string>("600");
  const [searchQuery, setSearchQuery] = useState("");

  // Linux kernel-symbol (ISF) resolution state — gates extraction.
  const isLinux = evidenceOs === "linux";
  const [isfStatus, setIsfStatus] = useState<string>(isLinux ? "pending" : "ready");
  const [isfBanner, setIsfBanner] = useState<string | null>(null);
  const [isfMessage, setIsfMessage] = useState<string | null>(null);
  const [isfGuidance, setIsfGuidance] = useState<any | null>(null);
  const [isfRetrying, setIsfRetrying] = useState(false);
  const isfReady = !isLinux || isfStatus === "ready";

  const requiredPlugins = REQUIRED_PLUGINS[evidenceOs] || [];

  const fetchAvailablePlugins = useCallback(async () => {
    try {
      setLoading(true);
      const response = await axiosInstance.get<AvailablePluginsResponse>(
        `/api/evidence/${evidenceId}/available-plugins/`
      );
      setCategories(response.data.categories);
      setTotalPlugins(response.data.total_plugins);

      // Check if any plugins have been executed before
      const allPlugins = Object.values(response.data.categories).flat();
      const anyExecuted = allPlugins.some((p) => p.execution_status !== null && p.execution_status !== undefined);
      setHasExecutedPlugins(anyExecuted);

      if (anyExecuted) {
        // Pre-select failed and no_output plugins (+ required), deselect successful ones
        const toSelect = allPlugins
          .filter((p) =>
            requiredPlugins.includes(p.name) ||
            p.execution_status === "failed" ||
            p.execution_status === "timed_out" ||
            p.execution_status === "no_output" ||
            p.execution_status === null ||
            p.execution_status === undefined
          )
          .map((p) => p.name);
        setSelectedPlugins([...new Set([...requiredPlugins, ...toSelect])]);
      } else {
        // First run: pre-select only required plugins
        setSelectedPlugins([...requiredPlugins]);
      }
    } catch (error) {
      display_message("error", `Failed to fetch available plugins: ${error}`);
    } finally {
      setLoading(false);
    }
  }, [evidenceId, display_message, requiredPlugins]);

  useEffect(() => {
    fetchAvailablePlugins();
  }, [fetchAvailablePlugins]);

  const fetchIsfStatus = useCallback(async () => {
    if (!isLinux) return;
    try {
      const res = await axiosInstance.get(`/api/evidence/${evidenceId}/isf/`);
      setIsfStatus(res.data.status);
      setIsfBanner(res.data.banner ?? null);
      setIsfMessage(res.data.message ?? null);
      setIsfGuidance(res.data.guidance ?? null);
    } catch {
      /* keep pending; WS will update */
    }
  }, [evidenceId, isLinux]);

  useEffect(() => {
    fetchIsfStatus();
  }, [fetchIsfStatus]);

  const handleRetryIsf = async () => {
    try {
      setIsfRetrying(true);
      await axiosInstance.post(`/api/evidence/${evidenceId}/isf/`);
      setIsfStatus("detecting");
      setIsfGuidance(null);
      display_message("info", "Kernel symbol resolution restarted");
    } catch (error) {
      setIsfRetrying(false);
      display_message("error", `Failed to restart ISF resolution: ${error}`);
    }
  };

  // WebSocket for extraction progress
  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const port = window.location.port ? `:${window.location.port}` : "";
    const wsUrl = `${protocol}://${window.location.hostname}${port}/ws/engine/${evidenceId}/`;

    ws.current = new WebSocket(wsUrl);

    ws.current.onmessage = (event) => {
      const data = JSON.parse(event.data);
      const message = data.message;
      if (message.name === "selective_extraction") {
        if (message.status === "finished") {
          setProcessing(false);
          if (message.result !== "false") {
            display_message("success", "Analysis completed successfully");
          } else {
            display_message("error", "Analysis failed");
          }
        }
      }
      if (message.name === "isf") {
        setIsfStatus(message.status);
        if (message.banner !== undefined) setIsfBanner(message.banner);
        if (message.message !== undefined) setIsfMessage(message.message);
        if (message.guidance !== undefined) setIsfGuidance(message.guidance);
        if (message.status === "ready") {
          setIsfRetrying(false);
          display_message(
            "success",
            "Kernel symbols (ISF) retrieved successfully and added to your Symbols database."
          );
        } else if (message.status.startsWith("failed")) {
          setIsfRetrying(false);
        }
      }
    };

    return () => {
      if (ws.current) {
        ws.current.close();
      }
    };
  }, [evidenceId, display_message, onExtractionStarted]);

  const isRequired = (pluginName: string) => requiredPlugins.includes(pluginName);

  const handlePluginToggle = (pluginName: string) => {
    if (isRequired(pluginName)) return;
    setSelectedPlugins((prev) =>
      prev.includes(pluginName)
        ? prev.filter((p) => p !== pluginName)
        : [...prev, pluginName]
    );
  };

  const getCategoryPlugins = (category: string) => categories[category] || [];

  const getSelectedCountForCategory = (category: string) => {
    const plugins = getCategoryPlugins(category);
    return plugins.filter((p) => selectedPlugins.includes(p.name)).length;
  };

  const handleCategoryToggle = (category: string, checked: boolean) => {
    const plugins = getCategoryPlugins(category);
    if (checked) {
      const newSelected = new Set(selectedPlugins);
      plugins.forEach((p) => newSelected.add(p.name));
      setSelectedPlugins(Array.from(newSelected));
    } else {
      const categoryNames = plugins.filter((p) => !isRequired(p.name)).map((p) => p.name);
      setSelectedPlugins((prev) => prev.filter((p) => !categoryNames.includes(p)));
    }
  };

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      const allNames = Object.values(categories).flat().map((p) => p.name);
      setSelectedPlugins(allNames);
    } else {
      setSelectedPlugins([...requiredPlugins]);
    }
  };

  const allSelected =
    totalPlugins > 0 && selectedPlugins.length === totalPlugins;
  const someSelected =
    selectedPlugins.length > requiredPlugins.length && !allSelected;

  const getStatusChip = (status: AvailablePlugin["execution_status"]) => {
    switch (status) {
      case "success":
        return (
          <Chip
            icon={<CheckCircle />}
            label="Success"
            size="small"
            color="success"
            variant="outlined"
            sx={{ height: 20, "& .MuiChip-label": { fontSize: "0.65rem" } }}
          />
        );
      case "no_output":
        return (
          <Chip
            icon={<RemoveCircleOutline />}
            label="No output"
            size="small"
            color="default"
            variant="outlined"
            sx={{ height: 20, "& .MuiChip-label": { fontSize: "0.65rem" } }}
          />
        );
      case "failed":
        return (
          <Chip
            icon={<ErrorOutline />}
            label="Failed"
            size="small"
            color="warning"
            variant="outlined"
            sx={{ height: 20, "& .MuiChip-label": { fontSize: "0.65rem" } }}
          />
        );
      case "timed_out":
        return (
          <Chip
            icon={<TimerOff />}
            label="Timed out"
            size="small"
            color="error"
            variant="outlined"
            sx={{ height: 20, "& .MuiChip-label": { fontSize: "0.65rem" } }}
          />
        );
      default:
        return null;
    }
  };

  const handleStartAnalysis = async () => {
    if (selectedPlugins.length === 0) {
      display_message("warning", "Please select at least one plugin");
      return;
    }

    try {
      setProcessing(true);
      await axiosInstance.post(`/api/evidence/tasks/selective-extraction/`, {
        id: evidenceId,
        plugins: selectedPlugins,
        run_timeliner: runTimeliner,
        pid: pidFilter ? parseInt(pidFilter) : null,
        skip_completed: skipCompleted && hasExecutedPlugins,
        plugin_timeout: enableTimeout && pluginTimeout ? parseInt(pluginTimeout) : null,
      });
      display_message("info", "Analysis started");
      if (onExtractionStarted) {
        onExtractionStarted();
      }
    } catch (error) {
      display_message("error", `Failed to start analysis: ${error}`);
      setProcessing(false);
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" height="60vh">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Paper elevation={3} sx={{ p: 3 }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            {onBack && (
              <IconButton onClick={onBack} size="small">
                <ArrowBack />
              </IconButton>
            )}
            <Typography variant="h5" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <Extension color="primary" />
              Plugin Selection
            </Typography>
          </Box>
          <Chip
            label={`${selectedPlugins.length} / ${totalPlugins} plugins selected`}
            color="primary"
            variant="outlined"
          />
        </Box>

        {/* Linux kernel-symbol (ISF) status — extraction is gated until ready */}
        {isLinux && isfStatus !== "ready" && (
          <Alert
            severity={isfStatus.startsWith("failed") ? "error" : "info"}
            icon={isfStatus.startsWith("failed") ? undefined : <CircularProgress size={18} />}
            sx={{ mb: 2 }}
            action={
              isfStatus.startsWith("failed") ? (
                <Button color="inherit" size="small" onClick={handleRetryIsf} disabled={isfRetrying}>
                  Retry
                </Button>
              ) : undefined
            }
          >
            <Typography variant="subtitle2">
              Kernel symbols (ISF):{" "}
              {(
                {
                  pending: "waiting…",
                  detecting: "detecting kernel banner…",
                  resolving: "looking up matching ISF…",
                  verifying: "verifying ISF against the image…",
                  failed_banner: "banner not found",
                  failed_isf: "no matching ISF",
                } as Record<string, string>
              )[isfStatus] || isfStatus}
            </Typography>
            {isfMessage && <Typography variant="body2">{isfMessage}</Typography>}
            {isfBanner && (
              <Typography
                variant="caption"
                component="pre"
                sx={{ mt: 1, whiteSpace: "pre-wrap", fontFamily: "monospace" }}
              >
                {isfBanner}
              </Typography>
            )}
            {isfGuidance && isfStatus.startsWith("failed") && (
              <Box sx={{ mt: 1 }}>
                <Typography variant="body2" sx={{ fontWeight: 600 }}>
                  Build it manually, then upload it in the Symbols page:
                </Typography>
                {isfGuidance.package && (
                  <Typography variant="body2">Package: {isfGuidance.package}</Typography>
                )}
                {isfGuidance.where && (
                  <Typography variant="body2" sx={{ wordBreak: "break-all" }}>
                    Where: {isfGuidance.where}
                  </Typography>
                )}
                <ol style={{ margin: "4px 0 0 18px" }}>
                  {(isfGuidance.steps || []).map((step: string, i: number) => (
                    <li key={i}>
                      <Typography variant="caption">{step}</Typography>
                    </li>
                  ))}
                </ol>
              </Box>
            )}
          </Alert>
        )}

        {/* Global controls */}
        <Box sx={{ display: "flex", alignItems: "flex-start", gap: 3, mb: 2, flexWrap: "wrap" }}>
          <Box sx={{ display: "flex", flexDirection: "column", gap: 0 }}>
            <FormControlLabel
              control={
                <Checkbox
                  checked={allSelected}
                  indeterminate={someSelected}
                  onChange={(e) => handleSelectAll(e.target.checked)}
                />
              }
              label="Select All Plugins"
            />
            <FormControlLabel
              control={
                <Checkbox
                  checked={runTimeliner}
                  onChange={(e) => setRunTimeliner(e.target.checked)}
                />
              }
              label={
                <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                  <Timeline fontSize="small" />
                  Include Timeliner
                </Box>
              }
            />
            {hasExecutedPlugins && (
              <FormControlLabel
                control={
                  <Checkbox
                    checked={skipCompleted}
                    onChange={(e) => setSkipCompleted(e.target.checked)}
                  />
                }
                label={
                  <Tooltip title="Skip plugins that already completed with results">
                    <span>Skip successful plugins</span>
                  </Tooltip>
                }
              />
            )}
          </Box>
          <TextField
            label="PID Filter (optional)"
            type="number"
            size="small"
            value={pidFilter}
            onChange={(e) => setPidFilter(e.target.value)}
            sx={{ width: 200 }}
            helperText="Filter process-based plugins by PID"
          />
          <Box sx={{ display: "flex", flexDirection: "column" }}>
            <FormControlLabel
              control={
                <Checkbox
                  checked={enableTimeout}
                  onChange={(e) => setEnableTimeout(e.target.checked)}
                />
              }
              label={
                <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                  <Timer fontSize="small" />
                  Plugin Timeout
                </Box>
              }
            />
            {enableTimeout && (
              <TextField
                label="Timeout (seconds)"
                type="number"
                size="small"
                value={pluginTimeout}
                onChange={(e) => setPluginTimeout(e.target.value)}
                sx={{ width: 160, ml: 4 }}
                helperText="Per-plugin time limit"
                inputProps={{ min: 10 }}
              />
            )}
          </Box>
        </Box>

        <Divider sx={{ mb: 2 }} />

        <TextField
          size="small"
          placeholder="Search plugins..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          sx={{ mb: 2, width: 300 }}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <Search fontSize="small" />
              </InputAdornment>
            ),
          }}
        />

        {/* Category accordions */}
        {Object.keys(categories).sort().map((category) => {
          const allPlugins = getCategoryPlugins(category);
          const query = searchQuery.toLowerCase();
          const plugins = query
            ? allPlugins.filter(
                (p) =>
                  p.name.toLowerCase().includes(query) ||
                  (p.description && p.description.toLowerCase().includes(query))
              )
            : allPlugins;
          if (plugins.length === 0) return null;
          const selectedCount = getSelectedCountForCategory(category);
          const allCategorySelected = selectedCount === plugins.length;
          const someCategorySelected = selectedCount > 0 && !allCategorySelected;
          const color = categoryColors[category] || "info";

          return (
            <Accordion key={`${category}-${searchQuery ? "search" : "browse"}`} defaultExpanded={!!searchQuery}>
              <AccordionSummary expandIcon={<ExpandMore />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                  <Checkbox
                    checked={allCategorySelected}
                    indeterminate={someCategorySelected}
                    onClick={(e) => e.stopPropagation()}
                    onChange={(e) => handleCategoryToggle(category, e.target.checked)}
                  />
                  <Chip label={category} color={color} size="small" variant="outlined" />
                  <Typography variant="body2" color="text.secondary">
                    {selectedCount} / {plugins.length} selected
                  </Typography>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <List dense>
                  {plugins.map((plugin) => {
                    const required = isRequired(plugin.name);
                    const shortName = plugin.name.split(".").pop() || plugin.name;

                    return (
                      <ListItem key={plugin.name} sx={{ py: 0.5 }}>
                        <Tooltip title={required ? "Required for Investigate & Explore tabs" : ""}>
                          <span>
                            <Checkbox
                              checked={selectedPlugins.includes(plugin.name) || required}
                              onChange={() => handlePluginToggle(plugin.name)}
                              disabled={required}
                            />
                          </span>
                        </Tooltip>
                        <ListItemText
                          primary={
                            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                              {shortName}
                              {required && (
                                <Chip
                                  icon={<Lock />}
                                  label="required"
                                  size="small"
                                  color="warning"
                                  variant="outlined"
                                  sx={{ height: 20, "& .MuiChip-label": { fontSize: "0.65rem" } }}
                                />
                              )}
                              {getStatusChip(plugin.execution_status)}
                            </Box>
                          }
                          secondary={plugin.description}
                        />
                      </ListItem>
                    );
                  })}
                </List>
              </AccordionDetails>
            </Accordion>
          );
        })}

        {Object.keys(categories).length === 0 && (
          <Alert severity="warning">
            No plugins available for this evidence OS.
          </Alert>
        )}

        {/* Action bar */}
        <Box mt={4} display="flex" justifyContent="center" alignItems="center" gap={2}>
          <Tooltip
            title={!isfReady ? "Waiting for Linux kernel symbols (ISF) to be ready" : ""}
          >
            <span>
              <Button
                variant="outlined"
                size="large"
                color="error"
                startIcon={processing ? <CircularProgress size={20} /> : <PlayArrow />}
                onClick={handleStartAnalysis}
                disabled={processing || selectedPlugins.length === 0 || !isfReady}
              >
                {processing ? "Processing..." : "Start Analysis"}
              </Button>
            </span>
          </Tooltip>
        </Box>
      </Paper>
    </Box>
  );
};

export default PluginSelector;
