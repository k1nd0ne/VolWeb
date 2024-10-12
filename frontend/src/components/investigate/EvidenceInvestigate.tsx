import React from "react";
import Box from "@mui/material/Box";
import Grid from "@mui/material/Grid2";
import PsTree from "./PsTree";

const EvidenceInvestigate: React.FC = () => {
  return (
    <Box sx={{ flexGrow: 1 }}>
      <Grid container spacing={2}>
        <Grid size={4}>
          <PsTree />
        </Grid>
        <Grid size={4}>Windows.Info.Result</Grid>
      </Grid>
    </Box>
  );
};

export default EvidenceInvestigate;
