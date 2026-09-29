import React, { useState, useCallback, useEffect, useMemo, useRef } from "react";
import {
  Box,
  Button,
  Paper,
  TextField,
  Typography,
  Grid,
  List,
  ListItem,
  ListItemText,
  Checkbox,
  FormControlLabel,
  FormControl,
  FormLabel,
  Radio,
  RadioGroup,
  Divider,
  Alert,
  Chip,
  CircularProgress,
  IconButton,
  Tooltip,
} from "@mui/material";
import Slide from "@mui/material/Slide";
import {
  Security,
  PlayArrow,
  CheckCircle,
  Delete,
  Close as CloseIcon,
  Download,
} from "@mui/icons-material";
import SearchIcon from '@mui/icons-material/Search';
import { DataGrid, GridColDef } from "@mui/x-data-grid";
import axiosInstance from "../../utils/axiosInstance";
import { YaraRuleSet, YaraRule, TaskData } from "../../types";
import { useSnackbar } from "../SnackbarProvider";

interface YaraScanProps {
  evidenceId: string;
  evidenceOs?: string;
}

interface ScanHistory {
  id: string;
  timestamp: string;
  ruleset_name: string;
  results: any[];
  description: string;
  scanName: string;
  plugin_name?: string;
  count?: number;
}

const YaraScan: React.FC<YaraScanProps> = ({ evidenceId, evidenceOs }) => {
  // Per-process user-space scan uses VadYaraScan on Windows (VADs) and
  // VmaYaraScan on Linux (VMAs) — surface the right plugin/region per OS.
  const isLinuxScan = evidenceOs === "linux";
  const vadPluginId = isLinuxScan
    ? "linux.vmayarascan.VmaYaraScan"
    : "windows.vadyarascan.VadYaraScan";
  const vadRegion = isLinuxScan ? "VMA" : "VAD";
  const { display_message } = useSnackbar();
  const ws = useRef<WebSocket | null>(null);
  const [rulesets, setRulesets] = useState<YaraRuleSet[]>([]);
  const [rules, setRules] = useState<YaraRule[]>([]);
  const [selectedRulesets, setSelectedRulesets] = useState<number[]>([]);
  const [selectedRules, setSelectedRules] = useState<number[]>([]);
  const [scanResults, setScanResults] = useState<any[]>([]);
  const [rulesetsLoading, setRulesetsLoading] = useState(false);
  const [rulesLoading, setRulesLoading] = useState(false);
  const [processing, setProcessing] = useState(false);
  const [hasResults, setHasResults] = useState(false);
  const [scanHistory, setScanHistory] = useState<ScanHistory[]>([]);
  const [rulesetSearch, setRulesetSearch] = useState<string>("");
  const [ruleSearch, setRuleSearch] = useState<string>("");
  const [rulesTotal, setRulesTotal] = useState(0);
  const [rulesPagination, setRulesPagination] = useState({ page: 0, pageSize: 25 });
  const [currentScanId, setCurrentScanId] = useState<string>("");
  const [transitioning, setTransitioning] = useState(false);
  const [scanResultsTotal, setScanResultsTotal] = useState(0);
  const [scanResultsPagination, setScanResultsPagination] = useState({ page: 0, pageSize: 100 });
  const [scanResultsLoading, setScanResultsLoading] = useState(false);
  const [exportLoading, setExportLoading] = useState(false);
  const [scanScope, setScanScope] = useState<"vad" | "kernel">("vad");

  const fetchScanResults = useCallback((page: number, pageSize: number) => {
    setScanResultsLoading(true);
    axiosInstance.get(`/api/evidence/${evidenceId}/yarascan/results/`, {
      params: { page: page + 1, page_size: pageSize },
    })
      .then((res) => {
        setScanResults(res.data.results ?? []);
        setScanResultsTotal(res.data.count ?? 0);
      })
      .catch((err) => display_message("error", `Failed to load scan results: ${err}`))
      .finally(() => setScanResultsLoading(false));
  }, [evidenceId, display_message]);

  const fetchRules = useCallback((search: string, page: number, pageSize: number) => {
    setRulesLoading(true);
    axiosInstance.get("/api/yararules/", {
      params: {
        status: 100,
        is_active: true,
        page: page + 1,
        page_size: pageSize,
        ...(search ? { search } : {}),
      },
    })
      .then((rulesResponse) => {
        setRules(rulesResponse.data.results ?? []);
        setRulesTotal(rulesResponse.data.count ?? 0);
      })
      .catch((error) => display_message("error", `Failed to fetch rules: ${error}`))
      .finally(() => setRulesLoading(false));
  }, [display_message]);

  const fetchYaraData = useCallback(async () => {
    setRulesetsLoading(true);

    axiosInstance.get("/api/yararulesets/")
      .then((rulesetsResponse) => {
        const compiledRulesets = (rulesetsResponse.data.results ?? rulesetsResponse.data).filter(
          (ruleset: YaraRuleSet) => ruleset.status === 100
        );
        setRulesets(compiledRulesets);
      })
      .catch((error) => display_message("error", `Failed to fetch rulesets: ${error}`))
      .finally(() => setRulesetsLoading(false));

    fetchRules("", 0, 25);
  }, [display_message, fetchRules]);

  // Debounced server-side search — resets to page 0
  useEffect(() => {
    const timer = setTimeout(() => {
      setRulesPagination(prev => ({ ...prev, page: 0 }));
      fetchRules(ruleSearch, 0, rulesPagination.pageSize);
    }, 400);
    return () => clearTimeout(timer);
  }, [ruleSearch]); // eslint-disable-line react-hooks/exhaustive-deps

  // Fetch when pagination changes
  useEffect(() => {
    fetchRules(ruleSearch, rulesPagination.page, rulesPagination.pageSize);
  }, [rulesPagination.page, rulesPagination.pageSize]); // eslint-disable-line react-hooks/exhaustive-deps

  // Fetch results when scan results pagination changes
  useEffect(() => {
    if (hasResults) {
      fetchScanResults(scanResultsPagination.page, scanResultsPagination.pageSize);
    }
  }, [scanResultsPagination.page, scanResultsPagination.pageSize]); // eslint-disable-line react-hooks/exhaustive-deps

  const loadScanHistoryFromBackend = useCallback(async (forceLoadResults = false) => {
    try {
      const response = await axiosInstance.get(`/api/evidence/${evidenceId}/yarascan/history/`);
      if (response.data && response.data.length > 0) {
        const scan = response.data[0];
        const description = scan.description || "";

        let scanName = "Latest YARA Scan";
        if (description.includes('using')) {
          const usingMatch = description.match(/using (.+?) - /);
          if (usingMatch && usingMatch[1]) {
            const scanInfo = usingMatch[1];
            if (scanInfo.match(/\d+ individual rule/)) {
              const ruleCount = scanInfo.match(/(\d+) individual rule/)?.[1] || "Unknown";
              scanName = `${ruleCount} Individual Rule${parseInt(ruleCount) !== 1 ? 's' : ''}`;
            } else if (scanInfo.startsWith('ruleset:')) {
              scanName = scanInfo.replace('ruleset: ', '');
            } else if (scanInfo.startsWith('rulesets:')) {
              const rulesetsStr = scanInfo.replace('rulesets: ', '');
              const rulesetList = rulesetsStr.split(', ');
              scanName = rulesetList.length > 2
                ? `${rulesetList.slice(0, 2).join(', ')}, +${rulesetList.length - 2}`
                : rulesetsStr;
            } else if (scanInfo === 'All Active Rules') {
              scanName = 'All Active Rules';
            } else {
              scanName = scanInfo;
            }
          }
        }

        const backendHistory: ScanHistory[] = [{
          id: "latest",
          timestamp: new Date().toISOString(),
          ruleset_name: scanName,
          results: [],
          description: description,
          scanName: scanName,
          plugin_name: scan.name,
          count: scan.count ?? 0,
        }];

        setScanHistory(backendHistory);

        if (forceLoadResults || !hasResults) {
          setCurrentScanId("latest");
          setHasResults(true);
          fetchScanResults(0, 100);
        }
      } else {
        setScanHistory([]);
      }
    } catch (error) {
      console.error("Error loading scan history from backend:", error);
      display_message("error", "Failed to load scan history");
    }
  }, [evidenceId, hasResults, display_message, fetchScanResults]);

  const deleteScan = useCallback(async (scan: ScanHistory) => {
    try {
      await axiosInstance.delete(`/api/evidence/${evidenceId}/yarascan/${scan.plugin_name}/`);
      display_message("success", "Scan deleted successfully");
      
      if (currentScanId === scan.id) {
        setHasResults(false);
        setScanResults([]);
        setCurrentScanId("");
      }
      
      loadScanHistoryFromBackend(false);
    } catch (error) {
      console.error("Error deleting scan:", error);
      display_message("error", "Failed to delete scan");
    }
  }, [evidenceId, currentScanId, display_message, loadScanHistoryFromBackend]);

  const deleteCurrentScan = useCallback(async () => {
    if (scanHistory.length > 0) {
      await deleteScan(scanHistory[0]);
    }
  }, [scanHistory, deleteScan]);

  const loadScanFromHistory = useCallback(async (scan: ScanHistory) => {
    setTransitioning(true);
    setCurrentScanId(scan.id);
    setHasResults(true);
    setScanResultsPagination({ page: 0, pageSize: 100 });
    fetchScanResults(0, 100);
    setTimeout(() => setTransitioning(false), 300);
  }, [fetchScanResults]);

  const checkIfYaraScanTaskRunning = useCallback(async () => {
    try {
      const response = await axiosInstance.get(`/api/evidence/${evidenceId}/tasks/`);
      const tasksData: TaskData[] = response.data;

      const isYaraScanTaskRunning = tasksData.some((task) => {
        return (
          task.task_name === "volatility_engine.tasks.start_yarascan" &&
          task.status === "STARTED"
        );
      });

      setProcessing(isYaraScanTaskRunning);
    } catch (error) {
      console.error("Error checking YaraScan task status", error);
    }
  }, [evidenceId]);

  useEffect(() => {
    fetchYaraData();
    loadScanHistoryFromBackend(false);
    checkIfYaraScanTaskRunning();
  }, [fetchYaraData, checkIfYaraScanTaskRunning]);

  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const port = window.location.port ? `:${window.location.port}` : "";
    const wsUrl = `${protocol}://${window.location.hostname}${port}/ws/engine/${evidenceId}/`;

    ws.current = new WebSocket(wsUrl);

    ws.current.onopen = () => {
      console.log("YaraScan WebSocket connected");
    };

    ws.current.onmessage = (event) => {
      const data = JSON.parse(event.data);
      console.log("YaraScan WebSocket message:", data);

      const message = data.message;
      if (message.name === "yarascan") {
        if (message.status === "finished") {
          setProcessing(false);
          if (message.result !== "false") {
            setTimeout(async () => {
              await loadScanHistoryFromBackend(true);
              display_message("success", "YaraScan completed successfully");
            }, 1500);
          } else {
            display_message("warning", "YaraScan did not return any results");
          }
        } else if (message.status === "stopped") {
          setProcessing(false);
          display_message("info", "YARA scan was stopped");
        } else if (message.status === "error") {
          setProcessing(false);
          display_message(
            "error",
            message.error
              ? `YaraScan failed: ${message.error}`
              : "YaraScan failed"
          );
        }
      }
    };

    ws.current.onclose = () => {
      console.log("YaraScan WebSocket disconnected");
    };

    return () => {
      if (ws.current) {
        ws.current.close();
      }
    };
  }, [evidenceId, loadScanHistoryFromBackend, display_message]);

  const handleRulesetToggle = (rulesetId: number) => {
    setSelectedRulesets((prev) =>
      prev.includes(rulesetId)
        ? prev.filter((id) => id !== rulesetId)
        : [...prev, rulesetId]
    );
  };

  // IDs of rules already covered by a selected ruleset
  const coveredRuleIds = useMemo(() => {
    if (selectedRulesets.length === 0) return new Set<number>();
    return new Set(
      rules
        .filter(r => {
          const rs = r.linked_yararuleset;
          if (!rs) return false;
          const rsId = typeof rs === 'object' ? rs.id : rs;
          return selectedRulesets.includes(rsId as number);
        })
        .map(r => r.id)
    );
  }, [selectedRulesets, rules]);

  const handleStopYaraScan = async () => {
    try {
      await axiosInstance.post(`/api/evidence/tasks/yarascan/stop/`, { id: evidenceId });
      display_message("info", "YARA scan stopped");
      setProcessing(false);
    } catch (error) {
      display_message("error", `Failed to stop scan: ${error}`);
    }
  };

  const handleRunYaraScan = async () => {
    if (selectedRulesets.length === 0 && selectedRules.length === 0) {
      display_message("warning", "Please select at least one ruleset or rule");
      return;
    }

    // Exclude individual rules already covered by a selected ruleset
    const effectiveRules = selectedRules.filter(id => !coveredRuleIds.has(id));

    try {
      setProcessing(true);
      await axiosInstance.post(`/api/evidence/tasks/yarascan/`, {
        id: evidenceId,
        rulesets: selectedRulesets,
        rules: effectiveRules,
        scan_scope: scanScope,
      });
      display_message("info", "YaraScan task started");
    } catch (error) {
      display_message("error", `Failed to start YaraScan: ${error}`);
      setProcessing(false);
    }
  };

  const handleNewScan = () => {
    setTransitioning(true);
    setTimeout(() => {
      setHasResults(false);
      setTransitioning(false);
    }, 300);
  };

  const handleExportAllCSV = useCallback(async () => {
    if (scanResultsTotal === 0) return;
    setExportLoading(true);
    try {
      const pageSize = 500;
      const totalPages = Math.ceil(scanResultsTotal / pageSize);
      const allResults: any[] = [];
      for (let page = 1; page <= totalPages; page++) {
        const res = await axiosInstance.get(`/api/evidence/${evidenceId}/yarascan/results/`, {
          params: { page, page_size: pageSize },
        });
        allResults.push(...(res.data.results ?? []));
      }
      if (allResults.length === 0) return;

      const headers = Object.keys(allResults[0]).filter(k => k !== '__children');
      const csvRows = [
        headers.join(','),
        ...allResults.map(row =>
          headers.map(h => {
            const val = row[h];
            if (val === null || val === undefined) return '';
            return `"${String(val).replace(/"/g, '""')}"`;
          }).join(',')
        ),
      ];
      const blob = new Blob([csvRows.join('\n')], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `yarascan_evidence_${evidenceId}.csv`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      display_message('error', `Export failed: ${err}`);
    } finally {
      setExportLoading(false);
    }
  }, [evidenceId, scanResultsTotal, display_message]);

  // Decode a YARA match Value to readable ASCII.
  // Handles the Python bytes repr format produced by Volatility3 yarascan:
  //   b'http://...'             — ASCII content, chars appear literally
  //   b'h\x00t\x00t\x00p\x00'  — UTF-16LE (wide string), null bytes interleaved
  // Also handles legacy formats: \x48\x65... and "48 65 6c..." (space-separated hex).
  const decodeHexString = (hexStr: string): string => {
    if (!hexStr || typeof hexStr !== 'string') return '';
    try {
      let content: string | null = null;

      // Python bytes repr: b'...' or b"..."
      if ((hexStr.startsWith("b'") && hexStr.endsWith("'")) ||
          (hexStr.startsWith('b"') && hexStr.endsWith('"'))) {
        content = hexStr.slice(2, -1);
      }

      if (content !== null) {
        // Parse Python escape sequences mixed with literal printable chars.
        // e.g. "h\x00t\x00t\x00p\x00" → "http" (null bytes skipped)
        let result = '';
        let i = 0;
        while (i < content.length) {
          if (content[i] === '\\') {
            i++;
            if (i >= content.length) break;
            if (content[i] === 'x') {
              const hex = content.slice(i + 1, i + 3);
              i += 3;
              const code = parseInt(hex, 16);
              if (!isNaN(code) && code >= 32 && code <= 126) result += String.fromCharCode(code);
              // null bytes and control chars silently skipped
            } else {
              // \n \r \t \0 \\ \' \" — only re-add escaped printable chars
              if (content[i] === '\\' || content[i] === "'" || content[i] === '"') result += content[i];
              i++;
            }
          } else {
            const code = content.charCodeAt(i);
            if (code >= 32 && code <= 126) result += content[i];
            i++;
          }
        }
        return result;
      }

      // Fallback: \x48\x65... or "48 65 6c..." formats
      const escapedMatches = hexStr.match(/\\x([0-9a-fA-F]{2})/g);
      if (escapedMatches && escapedMatches.length > 0) {
        return escapedMatches
          .map(m => parseInt(m.slice(2), 16))
          .filter(c => c >= 32 && c <= 126)
          .map(c => String.fromCharCode(c))
          .join('');
      }
      const trimmed = hexStr.trim();
      if (/^([0-9a-fA-F]{2}(\s+|$))+$/.test(trimmed)) {
        return trimmed.split(/\s+/)
          .map(h => parseInt(h, 16))
          .filter(c => c >= 32 && c <= 126)
          .map(c => String.fromCharCode(c))
          .join('');
      }
      return '';
    } catch {
      return '';
    }
  };

  // DataGrid columns for scan results - same structure as PluginDataGrid
  const resultColumns: GridColDef[] = useMemo(() => {
    if (scanResults.length === 0) return [];
    
    const columns = Object.keys(scanResults[0])
      .filter(key => key !== 'id' && key !== '__children')
      .map(key => ({
        field: key,
        headerName: key,
        flex: 1,
        minWidth: 150,
        renderCell: (params) => {
          if (key === "File output" && params.value !== "Disabled") {
            return (
              <Button
                variant="outlined"
                size="small"
                onClick={() => window.open(`/media/${evidenceId}/${params.value}`)}
              >
                Download
              </Button>
            );
          }

          if (key === "Disasm" || key === "Hexdump") {
            return <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all', overflow: 'auto', maxWidth: '100%' }}>{params.value}</pre>;
          }

          return typeof params.value === "boolean" ? (
            params.value ? (
              <Checkbox checked={true} color="success" />
            ) : (
              <IconButton color="error">
                <CloseIcon />
              </IconButton>
            )
          ) : params.value !== null && params.value !== undefined ? (
            <span style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', overflowWrap: 'anywhere', display: 'block', width: '100%' }}>{String(params.value)}</span>
          ) : (
            ""
          );
        },
      }));
    
    // Add decoded value column after Value column (case-insensitive field name search)
    const valueFieldName = Object.keys(scanResults[0]).find(k => k.toLowerCase() === 'value');
    const valueIndex = valueFieldName ? columns.findIndex(col => col.field === valueFieldName) : -1;
    if (valueIndex !== -1 && valueFieldName) {
      columns.splice(valueIndex + 1, 0, {
        field: 'DecodedValue',
        headerName: 'Decoded Value',
        flex: 1,
        minWidth: 150,
        renderCell: (params) => {
          const valueField = params.row[valueFieldName];
          const decoded = decodeHexString(valueField);
          return decoded ? (
            <span style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', overflowWrap: 'anywhere', display: 'block', width: '100%' }}>{decoded}</span>
          ) : null;
        },
      });
    }
    
    return columns;
  }, [scanResults, evidenceId]);


  if (!hasResults) {
    return (
      <Slide direction="left" in={!transitioning} timeout={300}>
        <Box sx={{ p: 3 }}>
          <Paper elevation={3} sx={{ p: 3 }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
              <Typography variant="h5" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <Security color="primary" />
                YARA Scan Configuration
              </Typography>
              {scanHistory.length > 0 && (
                <Chip
                  label="View Latest Scan Results"
                  variant="outlined"
                  color="primary"
                  onClick={() => {
                    loadScanFromHistory(scanHistory[0]);
                  }}
                  clickable
                />
              )}
            </Box>

            <FormControl component="fieldset" sx={{ mb: 3 }} disabled={processing}>
              <FormLabel component="legend" sx={{ mb: 1, fontWeight: 500 }}>
                Scan scope
              </FormLabel>
              <RadioGroup
                row
                value={scanScope}
                onChange={(e) => setScanScope(e.target.value as "vad" | "kernel")}
              >
                <FormControlLabel
                  value="vad"
                  control={<Radio />}
                  label={
                    <Box>
                      <Typography variant="body2" component="span" sx={{ fontWeight: 500 }}>
                        Process memory ({vadRegion})
                      </Typography>
                      <Typography
                        variant="caption"
                        component="div"
                        sx={{ fontFamily: "monospace", color: "text.secondary" }}
                      >
                        {vadPluginId}
                      </Typography>
                      <Typography variant="caption" component="div" color="text.secondary">
                        Recommended for malware. Scans every process {vadRegion}.
                      </Typography>
                    </Box>
                  }
                  sx={{ mr: 4, alignItems: "flex-start" }}
                />
                <FormControlLabel
                  value="kernel"
                  control={<Radio />}
                  label={
                    <Box>
                      <Typography variant="body2" component="span" sx={{ fontWeight: 500 }}>
                        Kernel layer
                      </Typography>
                      <Typography
                        variant="caption"
                        component="div"
                        sx={{ fontFamily: "monospace", color: "text.secondary" }}
                      >
                        yarascan.YaraScan
                      </Typography>
                      <Typography variant="caption" component="div" color="text.secondary">
                        For rootkits and kernel-mode threats. Faster, narrower coverage.
                      </Typography>
                    </Box>
                  }
                  sx={{ alignItems: "flex-start" }}
                />
              </RadioGroup>
            </FormControl>

            <Grid container spacing={3}>
              <Grid size={6}>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                    <Typography variant="h6">Available Rulesets</Typography>
                    <TextField
                      size="small"
                      placeholder="Search rulesets"
                      value={rulesetSearch}
                      onChange={(e) => setRulesetSearch(e.target.value)}
                      InputProps={{
                        startAdornment: <SearchIcon fontSize="small" sx={{ mr: 1 }} />,
                      }}
                      sx={{ width: 240 }}
                    />
                  </Box>
                <Divider sx={{ mb: 2 }} />
                
                {rulesetsLoading ? (
                  <Box display="flex" justifyContent="center" py={4}><CircularProgress size={24} /></Box>
                ) : rulesets.length === 0 ? (
                  <Alert severity="info">
                    No compiled rulesets available. Please compile rulesets first.
                  </Alert>
                ) : (() => {
                  const filteredRulesets = rulesets.filter(rs => rs.name.toLowerCase().includes(rulesetSearch.toLowerCase()));
                  const allSelected = filteredRulesets.length > 0 && filteredRulesets.every(rs => selectedRulesets.includes(rs.id));
                  const someSelected = filteredRulesets.some(rs => selectedRulesets.includes(rs.id));
                  return (
                    <Paper variant="outlined" sx={{ maxHeight: 400, overflow: "auto", p: 2 }}>
                      <FormControlLabel
                        sx={{ px: 1, mb: 0.5 }}
                        control={
                          <Checkbox
                            checked={allSelected}
                            indeterminate={!allSelected && someSelected}
                            onChange={() => {
                              if (allSelected) {
                                setSelectedRulesets(prev => prev.filter(id => !filteredRulesets.some(rs => rs.id === id)));
                              } else {
                                setSelectedRulesets(prev => [...new Set([...prev, ...filteredRulesets.map(rs => rs.id)])]);
                              }
                            }}
                          />
                        }
                        label={<Typography variant="body2" color="text.secondary">Select all</Typography>}
                      />
                      <Divider sx={{ mb: 0.5 }} />
                      <List dense>
                        {filteredRulesets.map((ruleset) => (
                          <ListItem key={ruleset.id} sx={{ py: 1 }}>
                            <Checkbox
                              checked={selectedRulesets.includes(ruleset.id)}
                              onChange={() => handleRulesetToggle(ruleset.id)}
                            />
                            <ListItemText
                              primary={ruleset.name}
                              secondary={`${ruleset.rules?.length || 0} rules`}
                            />
                            <CheckCircle color="success" fontSize="small" />
                          </ListItem>
                        ))}
                      </List>
                    </Paper>
                  );
                })()}
              </Grid>

              <Grid size={6}>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                  <Typography variant="h6">
                    Individual Rules
                  </Typography>
                  <TextField
                    size="small"
                    placeholder="Search rules"
                    value={ruleSearch}
                    onChange={(e) => setRuleSearch(e.target.value)}
                    InputProps={{
                      startAdornment: <SearchIcon fontSize="small" sx={{ mr: 1 }} />,
                    }}
                    sx={{ width: 240 }}
                  />
                </Box>
                <Divider sx={{ mb: 2 }} />

                <DataGrid
                  rows={rules}
                  columns={[
                    {
                      field: "name",
                      headerName: "Rule",
                      flex: 1,
                      renderCell: (params) => {
                        const covered = coveredRuleIds.has(params.row.id);
                        return (
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                            <span>{params.value}</span>
                            {covered && <Chip label="covered" size="small" color="info" variant="outlined" />}
                          </Box>
                        );
                      },
                    },
                    {
                      field: "linked_yararuleset",
                      headerName: "Ruleset",
                      flex: 1,
                      renderCell: (params) => {
                        const rs = params.row.linked_yararuleset;
                        return rs && typeof rs === "object" ? rs.name : (rs ?? "—");
                      },
                    },
                  ] as GridColDef[]}
                  checkboxSelection
                  disableRowSelectionOnClick
                  keepNonExistentRowsSelected
                  isRowSelectable={(params) => !coveredRuleIds.has(params.id as number)}
                  rowSelectionModel={{ type: "include" as const, ids: new Set(selectedRules) }}
                  onRowSelectionModelChange={(model) => {
                    const ids = Array.from((model as { type: string; ids: Set<number> }).ids)
                      .map(Number)
                      .filter(id => !coveredRuleIds.has(id));
                    setSelectedRules(ids);
                  }}
                  paginationMode="server"
                  rowCount={rulesTotal}
                  paginationModel={rulesPagination}
                  onPaginationModelChange={setRulesPagination}
                  pageSizeOptions={[25, 50, 100]}
                  loading={rulesLoading}
                  density="compact"
                  sx={{ height: 400, border: "1px solid", borderColor: "divider" }}
                />
              </Grid>
            </Grid>

            <Box mt={4} display="flex" justifyContent="center" alignItems="center" gap={2}>
              {processing ? (
                <Button
                  variant="outlined"
                  size="large"
                  color="warning"
                  startIcon={<CircularProgress size={20} />}
                  onClick={handleStopYaraScan}
                >
                  Stop Scan
                </Button>
              ) : (
                <Button
                  variant="outlined"
                  size="large"
                  color="error"
                  startIcon={<PlayArrow />}
                  onClick={handleRunYaraScan}
                  disabled={selectedRulesets.length === 0 && selectedRules.length === 0}
                >
                  Run YARA Scan
                </Button>
              )}

              <Typography variant="body2" color="text.secondary">
                Selected: {selectedRulesets.length} rulesets, {selectedRules.length} rules
              </Typography>
            </Box>
          </Paper>
        </Box>
      </Slide>
    );
  }

  return (
    <Slide direction="right" in={!transitioning} timeout={300}>
      <Box sx={{ flexGrow: 1 }}>
        <Box sx={{ mb: 2, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <Typography variant="h5" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <Security color="primary" />
            YARA Scan Results
          </Typography>
          <Box sx={{ display: "flex", gap: 1 }}>
            <Button
              variant="outlined"
              startIcon={exportLoading ? <CircularProgress size={16} /> : <Download />}
              onClick={handleExportAllCSV}
              disabled={exportLoading || scanResultsTotal === 0}
            >
              Export CSV
            </Button>
            {scanHistory.length > 0 && (
              <Button
                variant="outlined"
                color="error"
                startIcon={<Delete />}
                onClick={deleteCurrentScan}
              >
                Delete Scan
              </Button>
            )}
            <Button
              variant="contained"
              onClick={handleNewScan}
            >
              New Scan
            </Button>
          </Box>
        </Box>
        
        <Box sx={{ height: "calc(100vh - 200px)", width: "100%" }}>
          <DataGrid
            disableDensitySelector
            showToolbar
            slotProps={{
              toolbar: {
                csvOptions: { disableToolbarButton: true },
                printOptions: { disableToolbarButton: true },
              },
            }}
            rows={scanResults.map((result, index) => ({
              ...result,
              id: scanResultsPagination.page * scanResultsPagination.pageSize + index,
            }))}
            columns={resultColumns}
            density="compact"
            sx={{
              height: "100%",
              '& .MuiDataGrid-cell': {
                padding: '8px',
                display: 'flex',
                alignItems: 'flex-start',
                overflow: 'hidden',
              },
              '& .MuiDataGrid-columnHeader': {
                whiteSpace: 'normal',
                lineHeight: 'normal',
              }
            }}
            getRowId={(row) => row.id}
            paginationMode="server"
            rowCount={scanResultsTotal}
            paginationModel={scanResultsPagination}
            onPaginationModelChange={setScanResultsPagination}
            pageSizeOptions={[50, 100, 200]}
            loading={transitioning || scanResultsLoading}
            getEstimatedRowHeight={() => 36}
            getRowHeight={() => "auto"}
          />
        </Box>
      </Box>
    </Slide>
  );
};

export default YaraScan;