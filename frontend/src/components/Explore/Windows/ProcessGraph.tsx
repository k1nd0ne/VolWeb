import "@react-sigma/core/lib/react-sigma.min.css";
import React, { FC, useMemo, useState } from "react";
import {
  SigmaContainer,
  FullScreenControl,
  ZoomControl,
} from "@react-sigma/core";
import { Settings } from "sigma/settings";
import GraphDataController from "./GraphDataController";
import GraphEventsController from "./GraphEventsController";
import { ProcessInfo } from "../../../types";
import {
  CenterFocusWeak,
  ZoomIn,
  ZoomInMap,
  ZoomOut,
  ZoomOutMap,
} from "@mui/icons-material";
import Grid from "@mui/material/Grid2";
import { Box } from "@mui/material";
import ProcessDetails from "./ProcessDetails";

const commonStyles = {
  bgcolor: "background.paper",
  m: 1,
  border: 1,
  width: "5rem",
  height: "5rem",
};
function drawLabel(
  context: CanvasRenderingContext2D,
  data: { x: number; y: number; size: number; label: string; color: string },
  settings: Settings,
): void {
  if (!data.label) return;

  const size = settings.labelSize || 12;
  const font = settings.labelFont || "Arial";
  const weight = settings.labelWeight || "normal";

  context.font = `${weight} ${size}px ${font}`;
  const width = context.measureText(data.label).width + 8;

  context.fillStyle = "#ffffffcc";
  context.fillRect(data.x + data.size, data.y + size / 3 - 15, width, 20);

  context.fillStyle = "#000";
  context.fillText(data.label, data.x + data.size + 3, data.y + size / 3);
}

interface ProcessGraphProps {
  data: ProcessInfo[];
}

const ProcessGraph: FC<ProcessGraphProps> = ({ data }) => {
  const [selectedProcess, setSelectedProcess] = useState<ProcessInfo | null>(
    null,
  );

  const sigmaSettings: Partial<Settings> = useMemo(
    () => ({
      defaultDrawNodeLabel: drawLabel,
      defaultDrawNodeHover: drawLabel,
      defaultEdgeType: "arrow",
      labelDensity: 0.07,
      labelGridCellSize: 60,
      labelRenderedSizeThreshold: 1,
      labelFont: "Lato, sans-serif",
      zIndex: true,
    }),
    [],
  );
  return (
    <Grid container>
      <Grid size={12}>
        <Box style={{ width: "100%", height: "80vh" }}>
          <SigmaContainer
            style={{ backgroundColor: "#121212" }}
            settings={sigmaSettings}
            className="react-sigma"
          >
            <GraphDataController data={data} />
            <GraphEventsController
              data={data}
              onProcessSelect={setSelectedProcess}
            />
            {data && (
              <>
                <div className="controls">
                  <FullScreenControl className="ico">
                    <ZoomOutMap />
                    <ZoomInMap />
                  </FullScreenControl>

                  <ZoomControl className="ico">
                    <ZoomIn />
                    <ZoomOut />
                    <CenterFocusWeak />
                  </ZoomControl>
                </div>

                <div className="panels">
                  <div className="panel">
                    {selectedProcess && (
                      <ProcessDetails process={selectedProcess} />
                    )}
                  </div>
                </div>
              </>
            )}
          </SigmaContainer>
        </Box>
      </Grid>
    </Grid>
  );
};

export default ProcessGraph;
