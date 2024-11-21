import React from "react";
import Box from "@mui/material/Box";
import {
  Card,
  CardContent,
  Divider,
  Typography,
  List,
  ListItem,
  ListItemText,
} from "@mui/material";
import InfoIcon from "@mui/icons-material/Info";
import { ProcessInfo } from "../../../../types";
import { styled } from "@mui/material/styles";
import DumpPslistButton from "../Buttons/DumpPslistButton";
import ComputeHandlesButton from "../Buttons/ComputeHandlesButton";

interface ProcessMetadataProps {
  processMetadata: ProcessInfo;
  id: string | undefined;
  loadingDump: boolean;
  setLoadingDump: (loading: boolean) => void;
  loadingHandles: boolean;
  setLoadingHandles: (loading: boolean) => void;
}

const ValueText = styled("span")(({ theme }) => ({
  color: theme.palette.primary.main,
  "&.wow64": {
    color: "red",
  },
}));

const ProcessMetadata: React.FC<ProcessMetadataProps> = ({
  processMetadata,
  id,
  loadingDump,
  setLoadingDump,
  loadingHandles,
  setLoadingHandles,
}) => {
  return (
    <Box sx={{ flexGrow: 1 }}>
      <Card variant="outlined">
        <CardContent>
          <Typography
            gutterBottom
            sx={{
              color: "text.secondary",
              fontSize: 20,
              display: "flex",
              alignItems: "center",
            }}
          >
            <InfoIcon sx={{ marginRight: 1 }} />
            Metadata
          </Typography>
          <Divider sx={{ marginBottom: 1 }} />
          <List dense={true}>
            {processMetadata ? (
              Object.entries(processMetadata).map(
                ([key, value]) =>
                  key !== "__children" &&
                  key !== "File output" && (
                    <ListItem key={key} sx={{ fontSize: "0.800rem" }}>
                      <ListItemText
                        primary={
                          <>
                            {`${key}: `}
                            <ValueText
                              className={
                                key === "Wow64" && value ? "wow64" : ""
                              }
                              sx={{ fontSize: "0.800rem" }}
                            >
                              {value ? value.toString() : "N/A"}
                            </ValueText>
                          </>
                        }
                      />
                    </ListItem>
                  ),
              )
            ) : (
              <></>
            )}
          </List>
          <Box sx={{ display: "flex", justifyContent: "left", mt: 2 }}>
            <DumpPslistButton
              evidenceId={id}
              pid={processMetadata.PID}
              loading={loadingDump}
              setLoading={setLoadingDump}
            />
            <ComputeHandlesButton
              evidenceId={id}
              pid={processMetadata.PID}
              loading={loadingHandles}
              setLoading={setLoadingHandles}
            />
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
};

export default ProcessMetadata;
