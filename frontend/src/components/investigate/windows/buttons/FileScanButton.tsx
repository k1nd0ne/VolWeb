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

const FilescanButton: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [open, setOpen] = useState(false);
  const [data, setData] = useState<Artefact[]>([]);

  const fetchFileScan = async () => {
    try {
      const response = await axiosInstance.get(
        `/api/evidence/${id}/plugin/volatility3.plugins.windows.filescan.FileScan`,
      );
      console.log(response.data.artefacts);
      const artefactsWithId: Artefact[] = [];
      response.data.artefacts.forEach((artefact: Artefact, index: number) => {
        artefactsWithId.push({ ...artefact, id: index });
        if (artefact.__children && artefact.__children.length) {
          artefact.__children.map((child: Artefact, idx: number) => {
            artefactsWithId.push({ ...child, id: `${index}-${idx}` });
          });
        }
      });
      setData(artefactsWithId);
    } catch (error) {
      // TODO: Error message
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
      <Dialog fullScreen open={open} onClose={handleClose}>
        <DialogTitle>
          FileScan
          <IconButton
            edge="end"
            color="inherit"
            onClick={handleClose}
            aria-label="close"
            sx={{ position: "absolute", right: 8, top: 8 }}
          >
            <CloseIcon />
          </IconButton>
        </DialogTitle>
        <Divider sx={{ marginBottom: 1 }} />

        <DialogContent>
          <Paper>
            <FileScan data={data} />
          </Paper>
        </DialogContent>
      </Dialog>
    </>
  );
};

export default FilescanButton;
