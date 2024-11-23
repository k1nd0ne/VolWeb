import React from "react";
import {
  AccordionSummary,
  Accordion,
  Typography,
  AccordionDetails,
  Box,
} from "@mui/material";
import { ExpandMore } from "@mui/icons-material";
import EnrichedDataGrid from "./EnrichedDataGrid";
import { ProcessInfo, EnrichedProcessData } from "../../../types";

interface FilteredPluginsProps {
  process: ProcessInfo;
  enrichedData: EnrichedProcessData | null;
  show: boolean;
}

const FilteredPlugins: React.FC<FilteredPluginsProps> = ({ enrichedData }) => {
  return (
    <Box>
      {enrichedData &&
        Object.keys(enrichedData).map(
          (key, index) =>
            key !== "pslist" && (
              <Accordion key={index}>
                <AccordionSummary expandIcon={<ExpandMore />}>
                  <Typography>{key}</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <EnrichedDataGrid
                    data={enrichedData[key] as Record<string, unknown>[]}
                  />
                </AccordionDetails>
              </Accordion>
            ),
        )}
    </Box>
  );
};

export default FilteredPlugins;
