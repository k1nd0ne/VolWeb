import React from "react";
import Box from "@mui/material/Box";
import Grid from "@mui/material/Grid2";

const EvicenceMetadata: React.FC = () => {
  return (
    <Box sx={{ flexGrow: 1 }}>
      <Grid container spacing={2}>
        <Grid size={8}>Analysis summary</Grid>
        <Grid size={4}>Windows.Info.Result</Grid>
        <Grid size={6}>LOOT</Grid>
        <Grid size={6}>IOCS</Grid>
      </Grid>
    </Box>
  );
};

export default EvicenceMetadata;
