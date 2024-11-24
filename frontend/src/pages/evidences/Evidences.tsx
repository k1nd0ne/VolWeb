import React from "react";
import EvidenceList from "../../components/Lists/EvidenceList";
import Box from "@mui/material/Box";
import { useSnackbar } from "../../components/SnackbarProvider";

const EvidencePage: React.FC = () => {
  const { display_message } = useSnackbar();
  return (
    <Box>
      <EvidenceList />
    </Box>
  );
};
export default EvidencePage;
