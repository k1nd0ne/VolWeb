import React, { useState, useEffect } from "react";
import axiosInstance from "../../../utils/axiosInstance";
import {
  CircularProgress,
  Typography,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  List,
  ListItemIcon,
  ListItem,
  ListItemText,
} from "@mui/material";
import Grid from "@mui/material/Grid2";
import { useParams } from "react-router-dom";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import EnrichedDataGrid from "./EnrichedDataGrid";
import {
  AddCircleOutline,
  AlignHorizontalLeft,
  BugReport,
  Cancel,
  ExitToApp,
  Fingerprint,
  InfoRounded,
  PermIdentity,
  Terminal,
} from "@mui/icons-material";

// Define the ProcessInfo interface
interface ProcessInfo {
  PID: number;
  PPID: number;
  ImageFileName: string | null;
  OffsetV: number | null;
  Threads: number | null;
  Handles: number | null;
  SessionId: number | null;
  Wow64: boolean | null;
  CreateTime: string | null;
  ExitTime: string | null;
  __children: ProcessInfo[];
  anomalies: string[] | undefined;
}

// Define the structure of the enriched process data
interface EnrichedProcessData {
  pslist: ProcessInfo;
  "volatility3.plugins.windows.cmdline.CmdLine"?: { Args: string }[];
  "volatility3.plugins.windows.sessions.Sessions"?: {
    "Session ID": number;
    Process: string;
    "User Name": string;
    "Create Time": string;
  }[];
  [key: string]: any;
}

interface ProcessDetailsProps {
  process: ProcessInfo;
}

const ProcessDetails: React.FC<ProcessDetailsProps> = ({ process }) => {
  const [enrichedData, setEnrichedData] = useState<EnrichedProcessData | null>(
    null,
  );
  const [loading, setLoading] = useState(true);
  const { id } = useParams<{ id: string }>();

  useEffect(() => {
    // Fetch the enriched process data
    const fetchData = async () => {
      setLoading(true);
      try {
        const response = await axiosInstance.get(
          `/api/evidence/${id}/process/${process.PID}/enriched/`,
        );
        setEnrichedData(response.data.data);
      } catch (error) {
        console.error("Error fetching enriched process data:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [process.PID, id]);

  if (loading) {
    return <CircularProgress />;
  }

  if (!enrichedData) {
    return <Typography variant="body1">No data available.</Typography>;
  }

  return (
    <List dense>
      <ListItem>
        <ListItemIcon>
          <InfoRounded />
        </ListItemIcon>
        <ListItemText primary={<strong>PID:</strong>} secondary={process.PID} />
      </ListItem>
      <ListItem>
        <ListItemIcon>
          <Fingerprint />
        </ListItemIcon>
        <ListItemText
          primary={<strong>ImageFileName:</strong>}
          secondary={process.ImageFileName}
        />
      </ListItem>
      <ListItem>
        <ListItemIcon>
          <AlignHorizontalLeft />
        </ListItemIcon>
        <ListItemText
          primary={<strong>PPID:</strong>}
          secondary={process.PPID}
        />
      </ListItem>
      <ListItem>
        <ListItemIcon>
          <AddCircleOutline />
        </ListItemIcon>
        <ListItemText
          primary={<strong>CreateTime:</strong>}
          secondary={process.CreateTime}
        />
      </ListItem>
      <ListItem>
        <ListItemIcon>
          <Cancel />
        </ListItemIcon>
        <ListItemText
          primary={<strong>ExitTime:</strong>}
          secondary={process.ExitTime || "N/A"}
        />
      </ListItem>
      {enrichedData["volatility3.plugins.windows.cmdline.CmdLine"] && (
        <ListItem>
          <ListItemIcon>
            <Terminal />
          </ListItemIcon>
          <ListItemText
            primary={<strong>Command Line Arguments:</strong>}
            secondary={
              enrichedData["volatility3.plugins.windows.cmdline.CmdLine"][0]
                .Args || "N/A"
            }
          />
        </ListItem>
      )}
      {enrichedData["volatility3.plugins.windows.sessions.Sessions"] &&
        enrichedData["volatility3.plugins.windows.sessions.Sessions"].map(
          (session, index) => (
            <ListItem key={index}>
              <ListItemIcon>
                <PermIdentity />
              </ListItemIcon>
              <ListItemText
                primary={
                  <strong>{`Session ID ${session["Session ID"] || "N/A"}`}</strong>
                }
                secondary={`User Name: ${session["User Name"] || "N/A"}`}
              />
            </ListItem>
          ),
        )}
      {process.anomalies && process.anomalies.length > 0 && (
        <ListItem>
          <ListItemIcon>
            <BugReport />
          </ListItemIcon>
          <ListItemText
            primary={<strong>Anomalies:</strong>}
            secondary={
              <ul>
                {process.anomalies.map((anomaly, index) => (
                  <li key={index}>{anomaly}</li>
                ))}
              </ul>
            }
          />
        </ListItem>
      )}
    </List>

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
  );
};

export default ProcessDetails;
