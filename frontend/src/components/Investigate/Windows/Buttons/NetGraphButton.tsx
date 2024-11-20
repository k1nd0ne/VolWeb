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
import NetworkGraph from "../Components/NetworkGraph";
import { BugReportRounded } from "@mui/icons-material";
import { Connection } from "../../../../types";

const NetGraphButton: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [open, setOpen] = useState(false);
  const [data, setData] = useState<Connection[]>([]);

  const fetchNetGraph = async () => {
    try {
      const response = await axiosInstance.get(
        `/api/evidence/${id}/plugin/volatility3.plugins.windows.netscan.NetScan`,
      );
      setData(response.data.artefacts);
    } catch (error) {
      console.error("Error fetching netgraph details", error);
    }
  };

  const handleOpen = () => {
    fetchNetGraph();
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
  };

  return (
    <>
      <Tooltip title={"NetGraph"} arrow key={"NetGraph"} placement="top">
        <span>
          <Button
            color={"info"}
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
            {"Network Graph"}
          </Button>
        </span>
      </Tooltip>
      <Dialog fullScreen open={open} onClose={handleClose}>
        <DialogTitle>
          Network Graph
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
            <NetworkGraph data={data} />
          </Paper>
        </DialogContent>
      </Dialog>
    </>
  );
};

export default NetGraphButton;
