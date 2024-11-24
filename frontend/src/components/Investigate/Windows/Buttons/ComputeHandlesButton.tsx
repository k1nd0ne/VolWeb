import React, { useState } from "react";
import {
  Button,
  CircularProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  IconButton,
} from "@mui/material";
import { Close, Settings } from "@mui/icons-material";
import axiosInstance from "../../../../utils/axiosInstance";
import { AxiosError } from "axios";
import PluginDataGrid from "../../PluginDataGrid";

interface ComputeHandlesButtonProps {
  evidenceId: string | undefined;
  pid: number;
  loading: boolean;
  setLoading: (loading: boolean) => void;
}

const ComputeHandlesButton: React.FC<ComputeHandlesButtonProps> = ({
  evidenceId,
  pid,
  loading,
  setLoading,
}) => {
  const [openDialog, setOpenDialog] = useState(false);

  const handleComputeHandles = async () => {
    setLoading(true);
    try {
      // First, check if the data exists
      const response = await axiosInstance.get(
        `/api/evidence/${evidenceId}/plugin/volatility3.plugins.windows.handles.Handles.${pid}`,
      );
      if (
        response.data &&
        response.data.artefacts &&
        response.data.artefacts.length > 0
      ) {
        setOpenDialog(true);
        setLoading(false);
      } else {
        await axiosInstance.post(`/api/evidence/tasks/handles/`, {
          pid,
          evidenceId,
        });
      }
    } catch (error) {
      if (
        error instanceof AxiosError &&
        error.response &&
        error.response.status === 404
      ) {
        // Data does not exist, start computation
        await axiosInstance.post(`/api/evidence/tasks/handles/`, {
          pid,
          evidenceId,
        });
        // Loading remains true
      } else {
        // Handle other errors
        console.error("Error computing handles:", error);
        setLoading(false);
        alert("An error occurred while checking or computing handles.");
      }
    }
  };

  const handleCloseDialog = () => {
    setOpenDialog(false);
  };

  return (
    <>
      <Button
        variant="outlined"
        sx={{ mr: 2 }}
        color="secondary"
        size="small"
        onClick={handleComputeHandles}
        disabled={loading}
        startIcon={loading ? <CircularProgress size={20} /> : <Settings />}
      >
        {loading ? "Computing..." : "Fetch Handles"}
      </Button>

      {/* Dialog to display the handles data */}
      <Dialog
        open={openDialog}
        onClose={handleCloseDialog}
        fullWidth
        maxWidth="xl"
        sx={{
          "& .MuiPaper-root": {
            background: "#121212",
          },
          "& .MuiBackdrop-root": {
            backgroundColor: "transparent",
          },
        }}
      >
        <DialogTitle>
          Handles
          <IconButton
            edge="end"
            color="inherit"
            onClick={handleCloseDialog}
            aria-label="close"
            sx={{ position: "absolute", right: 8, top: 8 }}
          >
            <Close />
          </IconButton>
        </DialogTitle>
        <DialogContent>
          {/* Display the PluginDataGrid with the handles data */}
          <PluginDataGrid
            pluginName={`volatility3.plugins.windows.handles.Handles.${pid}`}
          />
        </DialogContent>
      </Dialog>
    </>
  );
};

export default ComputeHandlesButton;
