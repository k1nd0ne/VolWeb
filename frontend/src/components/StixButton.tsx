import React from "react";
import Button from "@mui/material/Button";
import GetAppIcon from "@mui/icons-material/GetApp";
import axiosInstance from "../utils/axiosInstance";

interface StixButtonProps {
  caseId: string;
}

const StixButton: React.FC<StixButtonProps> = ({ caseId }) => {
  const exportStixBundle = async () => {
    try {
      const response = await axiosInstance.get(`/core/stix/export/${caseId}/`, {
        responseType: "blob",
      });

      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `stix_bundle_${caseId}.json`);
      document.body.appendChild(link);
      link.click();

      // Check if parentNode exists before removing the link
      if (link.parentNode) {
        link.parentNode.removeChild(link);
      }
    } catch (error) {
      console.error("Error exporting STIX bundle", error);
    }
  };

  return (
    <Button
      variant="outlined"
      color="error"
      startIcon={<GetAppIcon />}
      onClick={exportStixBundle}
    >
      STIX Bundle
    </Button>
  );
};

export default StixButton;
