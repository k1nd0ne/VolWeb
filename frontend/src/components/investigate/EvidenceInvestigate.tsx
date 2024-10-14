import React, { useEffect, useState } from "react";
import Box from "@mui/material/Box";
import Grid from "@mui/material/Grid2";
import PsTree from "./PsTree";
import PluginDashboard from "./PluginDashboard";
import ProcessMetadata from "./ProcessMetadata";
import axiosInstance from "../../utils/axiosInstance";
import { ProcessInfo } from "../../types";
const EvidenceInvestigate: React.FC = () => {
  const [processMetadata, setProcessMetadata] = useState<ProcessInfo | null>(
    null,
  );

  return (
    <Box sx={{ flexGrow: 1 }}>
      <Grid container spacing={2}>
        <Grid size={3}>
          <PsTree setProcessMetadata={setProcessMetadata} />
        </Grid>
        <Grid size={3}>
          <ProcessMetadata processMetadata={processMetadata} />
        </Grid>
        <Grid size={6}>
          <PluginDashboard />
        </Grid>
      </Grid>
    </Box>
  );
};

export default EvidenceInvestigate;
