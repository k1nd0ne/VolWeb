import { FC, useMemo, useState } from "react";
import {
  SigmaContainer,
  FullScreenControl,
  ZoomControl,
} from "@react-sigma/core";
import "@react-sigma/core/lib/style.css";
import { Settings } from "sigma/settings";
import { NodeDisplayData, PartialButFor } from "sigma/types";
import GraphDataController from "./GraphDataController";
import GraphEventsController from "./GraphEventsController";
import { EnrichedProcessData, LinuxProcessInfo } from "../../../types";
import {
  CenterFocusWeak,
  ZoomIn,
  ZoomInMap,
  ZoomOut,
  ZoomOutMap,
} from "@mui/icons-material";
import Grid from "@mui/material/Grid";
import { Box } from "@mui/material";
import ProcessDetails from "./ProcessDetails";
import FilteredPlugins from "./FilteredPlugins";

function drawLabel(
  context: CanvasRenderingContext2D,
  data: PartialButFor<NodeDisplayData, "x" | "y" | "size" | "label" | "color">,
  settings: Settings,
): void {
  if (!data.label) return;

  const size = settings.labelSize || 12;
  const font = settings.labelFont || "Roboto";
  const weight = settings.labelWeight || "normal";

  context.font = `${weight} ${size}px ${font}`;
  const width = context.measureText(data.label).width + 8;

  context.fillStyle = "#ffffffcc";
  context.fillRect(data.x + data.size, data.y + size / 3 - 15, width, 20);

  context.fillStyle = "#000";
  context.fillText(data.label, data.x + data.size + 3, data.y + size / 3);
}

interface ProcessGraphProps {
  data: LinuxProcessInfo[];
}

const ProcessGraph: FC<ProcessGraphProps> = ({ data }) => {
  const [selectedProcess, setSelectedProcess] =
    useState<LinuxProcessInfo | null>(null);

  const [show, setShow] = useState<boolean>(false);

  const [enrichedData, setEnrichedData] = useState<EnrichedProcessData | null>(
    null,
  );

  const sigmaSettings: Partial<Settings> = useMemo(
    () => ({
      defaultDrawNodeLabel: drawLabel,
      defaultDrawNodeHover: drawLabel,
      defaultEdgeType: "arrow",
      renderEdgeLabels: true,
      labelDensity: 0.07,
      labelGridCellSize: 60,
      labelRenderedSizeThreshold: 1,
      labelFont: "Lato, sans-serif",
      zIndex: true,
    }),
    [],
  );

  const sigmaStyle = {
    height: "80vh",
    width: "100%",
    backgroundColor: "#121212",
  };

  return (
    <Grid container>
      <Grid size={12}>
        <Box style={{ width: "100%", height: "80vh" }}>
          <SigmaContainer
            style={sigmaStyle}
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

                {selectedProcess && (
                  <div className="panels">
                    <div className="panel">
                      <ProcessDetails
                        enrichedData={enrichedData}
                        setEnrichedData={setEnrichedData}
                        process={selectedProcess}
                        show={show}
                        setShow={setShow}
                      />
                    </div>
                  </div>
                )}
                {selectedProcess && show && (
                  <div className="panels-2">
                    <div className="panel-2">
                      <FilteredPlugins
                        enrichedData={enrichedData}
                        process={selectedProcess}
                        show={show}
                      />
                    </div>
                  </div>
                )}
              </>
            )}
          </SigmaContainer>
        </Box>
      </Grid>
    </Grid>
  );
};

export default ProcessGraph;
