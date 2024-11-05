import React, { useState } from "react";
import { Button, CircularProgress } from "@mui/material";
import { Download } from "@mui/icons-material";
import axios from "axios";

interface DumpButtonProps {
  evidenceId: string | undefined;
  pid: number | undefined;
}

const DumpButton: React.FC<DumpButtonProps> = ({ evidenceId, pid }) => {
  const [loading, setLoading] = useState(false);

  const handleDump = async () => {
    setLoading(true);
    try {
      await axios.post(`/api/evidence/tasks/dump/process/`, {
        pid,
        evidenceId,
      });
      // You can handle the response here if needed
    } catch (error) {
      // Handle the error appropriately
      console.error("Error dumping process:", error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Button
      variant="outlined"
      sx={{ mr: 2 }}
      color="error"
      size="small"
      onClick={handleDump}
      disabled={loading}
      startIcon={loading ? <CircularProgress size={20} /> : <Download />}
    >
      Dump
    </Button>
  );
};

export default DumpButton;
