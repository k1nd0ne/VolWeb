import React, { useEffect, useState } from "react";
import axiosInstance from "../../utils/axiosInstance";
import { Case } from "../../types";
import Box from "@mui/material/Box";
import AddCaseDialog from "../../components/CaseCreationDialog";
import CaseList from "../../components/CaseList";
import MessageHandler from "../../components/MessageHandler";

const Cases: React.FC = () => {
  const [cases, setCases] = useState<Case[]>([]);
  const [isAddDialogOpen, setAddDialogOpen] = useState(false);

  const [message, setMessage] = useState("");
  const [severity, setSeverity] = useState<
    "error" | "warning" | "info" | "success"
  >("info");
  const [isMessageOpen, setMessageOpen] = useState(false);

  const handleMessageClose = () => {
    setMessageOpen(false);
    setMessage("");
  };

  useEffect(() => {
    const fetchCases = async () => {
      try {
        const response = await axiosInstance.get<Case[]>("/api/cases");
        if (Array.isArray(response.data)) {
          setCases(response.data);
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

  const handleCaseOpening = (id: number) => {
    setSeverity("success");
    setMessage(String(id));
    setMessageOpen(true);
  };

  const handleCreateSuccess = (newCase: Case) => {
    setCases((prevCases) => [...prevCases, newCase]);
    setSeverity("success");
    setMessage("Case created successfully");
    setMessageOpen(true);
  };

  return (
    <Box sx={{ height: "80vh", width: "100%", transform: "translateZ(0px)" }}>
      <h1>Cases</h1>
      <CaseList cases={cases} onOpenCase={handleCaseOpening}></CaseList>
      <AddCaseDialog
        open={isAddDialogOpen}
        onClose={() => setAddDialogOpen(false)}
        onCreateSuccess={handleCreateSuccess}
      />
      <MessageHandler
        open={isMessageOpen}
        message={message}
        severity={severity}
        onClose={handleMessageClose}
      />
    </Box>
  );
};

export default Cases;
