import React, { useState } from "react";
import { useParams } from "react-router-dom";
import axiosInstance from "../../../../utils/axiosInstance";
import {
  Button,
  Tooltip,
  Dialog,
  DialogContent,
  DialogTitle,
  IconButton,
  Divider,
  Paper,
} from "@mui/material";
import CloseIcon from "@mui/icons-material/Close";
import { FolderOpen } from "@mui/icons-material";
import { Artefact } from "../../../../types";
import FileScan from "../Components/FileScan";
import { useSnackbar } from "../../../SnackbarProvider";

const WindowsFileScanButton: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [open, setOpen] = useState(false);
  const [data, setData] = useState<Artefact[]>([]);
  const { display_message } = useSnackbar();

  const fetchFileScan = async () => {
    try {
      const response = await axiosInstance.get(
        `/api/evidence/${id}/plugin/volatility3.plugins.windows.filescan.FileScan`,
      );

      const artefactsWithId: Artefact[] = [];
      response.data.artefacts.forEach((artefact: Artefact, index: number) => {
        artefactsWithId.push({ ...artefact, id: index });
        if (Array.isArray(artefact.__children) && artefact.__children.length) {
          artefact.__children.forEach((child: Artefact, idx: number) => {
            artefactsWithId.push({ ...child, id: `${index}-${idx}` });
          });
        }
      });
      setData(artefactsWithId);
    } catch (error) {
      display_message("error", `Error fetching filescan details: ${error}`);
      console.error("Error fetching filescan details", error);
    }
  };

  const handleOpen = () => {
    fetchFileScan();
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
  };

  return (
    <>
      <Tooltip title={"FileScan"} arrow key={"FileScan"} placement="top">
        <span>
          <Button
            color={"error"}
            variant="outlined"
            size="small"
            onClick={handleOpen}
            startIcon={<FolderOpen />}
            sx={{
              marginRight: 1,
              marginBottom: 1,
            }}
            disabled={false}
          >
            {"FileScan"}
          </Button>
        </span>
      </Tooltip>
      <Dialog fullWidth={true} maxWidth="xl" open={open} onClose={handleClose}>
        <DialogTitle>FileScan</DialogTitle>
        <Divider sx={{ marginBottom: 1 }} />

        <DialogContent>
          <FileScan data={data} />
        </DialogContent>
      </Dialog>
    </>
  );
};

export default WindowsFileScanButton;
