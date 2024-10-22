import React, { useState, useEffect } from "react";
import EvidenceList from "../../components/EvidenceList";

import { Evidence } from "../../types";
import Box from "@mui/material/Box";
import axiosInstance from "../../utils/axiosInstance";
import MessageHandler from "../../components/MessageHandler";

const EvidencePage: React.FC = () => {
  const [evidences, setEvidences] = useState<Evidence[]>([]);
  const [message, setMessage] = useState("");
  const [severity, setSeverity] = useState<
    "error" | "warning" | "info" | "success"
  >("info");
  const [isMessageOpen, setMessageOpen] = useState(false);

  useEffect(() => {
    const fetchCases = async () => {
      try {
        const response = await axiosInstance.get<Evidence[]>("/api/evidences");
        if (Array.isArray(response.data)) {
          setEvidences(response.data);
        } else {
          setSeverity("error");
          setMessage("Received data is not an array");
          setMessageOpen(true);
        }
      } catch (err) {
        setSeverity("error");
        setMessage(`Failed to fetch cases: ${err}`);
        setMessageOpen(true);
      }
    };

    fetchCases();
  }, []);

  const handleMessageClose = () => {
    setMessageOpen(false);
    setMessage("");
  };

  return (
    <Box>
      <EvidenceList evidences={evidences}></EvidenceList>
      <MessageHandler
        open={isMessageOpen}
        message={message}
        severity={severity}
        onClose={handleMessageClose}
      />
    </Box>
  );
};

export default EvidencePage;
