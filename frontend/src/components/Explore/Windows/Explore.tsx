import React, { useEffect, useState } from "react";
import axiosInstance from "../../../utils/axiosInstance";
import ProcessGraph from "./ProcessGraph";
import { ProcessInfo, Evidence } from "../../../types";
import { Box } from "@mui/material";
interface ExploreProps {
  evidence: Evidence;
}

const Explore: React.FC<ExploreProps> = ({ evidence }) => {
  const [data, setData] = useState<ProcessInfo[]>([]); // Initialize with an empty array

  useEffect(() => {
    const fetchTree = async () => {
      try {
        const response = await axiosInstance.get(
          `/api/evidence/${evidence.id}/plugin/volatility3.plugins.windows.pstree.PsTree/`,
        );
        console.log(response.data);
        setData(response.data.artefacts);
      } catch (error) {
        console.error("Error fetching pstree data", error);
      }
    };

    fetchTree();
  }, [evidence.id]);

  return (
    <Box>
      {data.length > 0 ? <ProcessGraph data={data} /> : <p>Loading...</p>}
    </Box>
  );
};

export default Explore;
