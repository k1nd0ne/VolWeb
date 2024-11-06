import React, { useState, useEffect } from "react";
import SymbolsList from "../../components/SymbolsList";

import { Symbol } from "../../types";
import Box from "@mui/material/Box";
import axiosInstance from "../../utils/axiosInstance";
import MessageHandler from "../../components/MessageHandler";

const SymbolsPage: React.FC = () => {
  const [symbols, setSymbols] = useState<Symbol[]>([]);
  const [message, setMessage] = useState("");
  const [severity, setSeverity] = useState<
    "error" | "warning" | "info" | "success"
  >("info");
  const [isMessageOpen, setMessageOpen] = useState(false);

  useEffect(() => {
    const fetchCases = async () => {
      try {
        const response = await axiosInstance.get<Symbol[]>("/api/symbols");
        if (Array.isArray(response.data)) {
          setSymbols(response.data);
        } else {
          setSeverity("error");
          setMessage("Received data is not an array");
          setMessageOpen(true);
        }
      } catch (err) {
        setSeverity("error");
        setMessage(`Failed to fetch symbols: ${err}`);
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
      <SymbolsList symbols={symbols}></SymbolsList>
      <MessageHandler
        open={isMessageOpen}
        message={message}
        severity={severity}
        onClose={handleMessageClose}
      />
    </Box>
  );
};

export default SymbolsPage;
