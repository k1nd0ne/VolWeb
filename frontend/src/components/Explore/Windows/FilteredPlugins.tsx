import React, { useState, useEffect } from "react";
import axiosInstance from "../../../utils/axiosInstance";
import {
  CircularProgress,
  List,
  ListItemIcon,
  ListItem,
  ListItemText,
  Button,
} from "@mui/material";
import {
  AddCircleOutline,
  AlignHorizontalLeft,
  BugReport,
  Cancel,
  Fingerprint,
  InfoRounded,
  PermIdentity,
  Terminal,
} from "@mui/icons-material";
import Grid from "@mui/material/Grid2";
import { ProcessInfo, EnrichedProcessData } from "../../../types";

interface FilteredPluginsProps {
  process: ProcessInfo;
  enrichedData: EnrichedProcessData | null;
  show: boolean;
}

const FilteredPlugins: React.FC<FilteredPluginsProps> = ({
  process,
  enrichedData,
  show,
}) => {
  const [loading, setLoading] = useState(true);

  return (
    <Grid container>
      <Grid size={12}>Test</Grid>
    </Grid>
  );
};

export default FilteredPlugins;

// <Grid size={10}>
//   {/* Enriched data */}
//   {/* DLL List */}
//   {enrichedData["volatility3.plugins.windows.dlllist.DllList"] && (
//     <Accordion>
//       <AccordionSummary expandIcon={<ExpandMoreIcon />}>
//         <Typography>Loaded DLLs</Typography>
//       </AccordionSummary>
//       <AccordionDetails>
//         <EnrichedDataGrid
//           data={
//             enrichedData["volatility3.plugins.windows.dlllist.DllList"]
//           }
//         />
//       </AccordionDetails>
//     </Accordion>
//   )}

//   {/* Environment Variables */}
//   {enrichedData["volatility3.plugins.windows.envars.Envars"] && (
//     <Accordion>
//       <AccordionSummary expandIcon={<ExpandMoreIcon />}>
//         <Typography>Environment Variables</Typography>
//       </AccordionSummary>
//       <AccordionDetails>
//         <EnrichedDataGrid
//           data={enrichedData["volatility3.plugins.windows.envars.Envars"]}
//         />
//       </AccordionDetails>
//     </Accordion>
//   )}

//   {/* SIDs */}
//   {enrichedData["volatility3.plugins.windows.getsids.GetSIDs"] && (
//     <Accordion>
//       <AccordionSummary expandIcon={<ExpandMoreIcon />}>
//         <Typography>Security Identifiers (SIDs)</Typography>
//       </AccordionSummary>
//       <AccordionDetails>
//         <EnrichedDataGrid
//           data={
//             enrichedData["volatility3.plugins.windows.getsids.GetSIDs"]
//           }
//         />
//       </AccordionDetails>
//     </Accordion>
//   )}

//   {/* Privileges */}
//   {enrichedData["volatility3.plugins.windows.privileges.Privs"] && (
//     <Accordion>
//       <AccordionSummary expandIcon={<ExpandMoreIcon />}>
//         <Typography>Privileges</Typography>
//       </AccordionSummary>
//       <AccordionDetails>
//         <EnrichedDataGrid
//           data={
//             enrichedData["volatility3.plugins.windows.privileges.Privs"]
//           }
//         />
//       </AccordionDetails>
//     </Accordion>
//   )}

//   {/* Threads */}
//   {enrichedData["volatility3.plugins.windows.threads.Threads"] && (
//     <Accordion>
//       <AccordionSummary expandIcon={<ExpandMoreIcon />}>
//         <Typography>Threads</Typography>
//       </AccordionSummary>
//       <AccordionDetails>
//         <EnrichedDataGrid
//           data={
//             enrichedData["volatility3.plugins.windows.threads.Threads"]
//           }
//         />
//       </AccordionDetails>
//     </Accordion>
//   )}

//   {/* PsScan */}
//   {enrichedData["volatility3.plugins.windows.psscan.PsScan"] && (
//     <Accordion>
//       <AccordionSummary expandIcon={<ExpandMoreIcon />}>
//         <Typography>Process Scan (PsScan)</Typography>
//       </AccordionSummary>
//       <AccordionDetails>
//         <EnrichedDataGrid
//           data={enrichedData["volatility3.plugins.windows.psscan.PsScan"]}
//         />
//       </AccordionDetails>
//     </Accordion>
//   )}

//   {/* PsXView */}
//   {enrichedData["volatility3.plugins.windows.psxview.PsXView"] && (
//     <Accordion>
//       <AccordionSummary expandIcon={<ExpandMoreIcon />}>
//         <Typography>PsXView</Typography>
//       </AccordionSummary>
//       <AccordionDetails>
//         <EnrichedDataGrid
//           data={
//             enrichedData["volatility3.plugins.windows.psxview.PsXView"]
//           }
//         />
//       </AccordionDetails>
//     </Accordion>
//   )}

//   {/* ThrdScan */}
//   {enrichedData["volatility3.plugins.windows.thrdscan.ThrdScan"] && (
//     <Accordion>
//       <AccordionSummary expandIcon={<ExpandMoreIcon />}>
//         <Typography>Thread Scan (ThrdScan)</Typography>
//       </AccordionSummary>
//       <AccordionDetails>
//         <EnrichedDataGrid
//           data={
//             enrichedData["volatility3.plugins.windows.thrdscan.ThrdScan"]
//           }
//         />
//       </AccordionDetails>
//     </Accordion>
//   )}
// </Grid>
