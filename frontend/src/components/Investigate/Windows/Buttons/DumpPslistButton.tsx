import React from "react";
import { Button, CircularProgress } from "@mui/material";
import { Download } from "@mui/icons-material";
import axiosInstance from "../../../../utils/axiosInstance";
import { useSnackbar } from "../../../SnackbarProvider";

interface DumpPslistButtonProps {
  evidenceId: string | undefined;
  pid: number | undefined;
  loading: boolean;
  setLoading: (loading: boolean) => void;
}

const DumpPslistButton: React.FC<DumpPslistButtonProps> = ({
  evidenceId,
  pid,
  loading,
  setLoading,
}) => {
  const { display_message } = useSnackbar();

  const handleDump = async () => {
    setLoading(true);
    try {
      await axiosInstance.post(`/api/evidence/tasks/dump/process/pslist/`, {
        pid,
        evidenceId,
      });
    } catch (error) {
      display_message("error", `Error dumping process: ${error}`);
      console.error("Error dumping process:", error);
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
      {loading ? "Dumping..." : "Dump (pslist)"}
    </Button>
  );
};

export default DumpPslistButton;
