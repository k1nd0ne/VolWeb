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
import { BugReportRounded } from "@mui/icons-material";
import { Connection } from "../../../../types";
import Malfind from "../components/Malfind";

const MalfindButton: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [open, setOpen] = useState(false);
  const [data, setData] = useState<Connection[]>([]);

  const fetchMalfindGraph = async () => {
    try {
      const response = await axiosInstance.get(
        `/api/evidence/${id}/plugin/volatility3.plugins.windows.malfind.Malfind`,
      );
      console.log(response.data.artefacts);
      setData(response.data.artefacts);
    } catch (error) {
      // TODO: Error message
      console.error("Error fetching malfind details", error);
    }
  };

  const handleOpen = () => {
    fetchMalfindGraph();
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
  };

  return (
    <>
      <Tooltip title={"Malfind"} arrow key={"Malfind"} placement="top">
        <span>
          <Button
            color={"primary"}
            variant="outlined"
            size="small"
            onClick={handleOpen}
            startIcon={<BugReportRounded />}
            sx={{
              marginRight: 1,
              marginBottom: 1,
            }}
            disabled={false}
          >
            {"Malfind"}
          </Button>
        </span>
      </Tooltip>
      <Dialog
        fullScreen
        open={open}
        onClose={handleClose}
        sx={{
          "& .MuiBackdrop-root": {
            backgroundColor: "transparent",
          },
        }}
      >
        <DialogTitle>
          MalFind
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
            <Malfind data={data} />
          </Paper>
        </DialogContent>
      </Dialog>
    </>
  );
};

export default MalfindButton;
