import React, { useEffect, useState } from "react";
import axiosInstance from "../../../utils/axiosInstance";
import ProcessGraph from "./ProcessGraph";
import { ProcessInfo, Evidence } from "../../../types";
import { Box, CircularProgress } from "@mui/material";
import { annotateProcessData } from "../../../utils/processAnalysis";
interface ExploreProps {
  evidence: Evidence;
}
import { useSnackbar } from "../../SnackbarProvider";

const Explore: React.FC<ExploreProps> = ({ evidence }) => {
  const [data, setData] = useState<ProcessInfo[]>([]); // Initialize with an empty array
  const { display_message } = useSnackbar();

  useEffect(() => {
    const fetchTree = async () => {
      try {
        const response = await axiosInstance.get(
          `/api/evidence/${evidence.id}/plugin/volatility3.plugins.windows.pstree.PsTree/`,
        );
        annotateProcessData(response.data.artefacts);
        setData(response.data.artefacts);
      } catch (error) {
        display_message(
          "error",
          `The pstree data could not be retreived: ${error}`,
        );
        console.error("Error fetching pstree data", error);
      }
    };

    fetchTree();
  }, [evidence.id, display_message]);

  return (
    <Box>
      {data.length > 0 ? <ProcessGraph data={data} /> : <CircularProgress />}
    </Box>
  );
};

export default Explore;
