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
import { LinuxProcessInfo } from "../../../../types";
import { styled } from "@mui/material/styles";
import DumpPslistButton from "../Buttons/DumpPslistButton";
import DumpMapsButton from "../Buttons/DumpMapsButton";

interface ProcessMetadataProps {
  processMetadata: LinuxProcessInfo;
  id: string | undefined;
  loadingDumpPslist: boolean;
  setLoadingDumpPslist: (loading: boolean) => void;
  loadingDumpMaps: boolean;
  setLoadingDumpMaps: (loading: boolean) => void;
}

const ValueText = styled("span")(({ theme }) => ({
  color: theme.palette.primary.main,
  // In case we identify some anomalies in the future
  // "&.wow64": {
  //   color: "red",
  // },
}));

const ProcessMetadata: React.FC<ProcessMetadataProps> = ({
  processMetadata,
  id,
  loadingDumpPslist,
  setLoadingDumpPslist,
  loadingDumpMaps,
  setLoadingDumpMaps,
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
                            <ValueText sx={{ fontSize: "0.800rem" }}>
                              {value ? value.toString() : "N/A"}
                            </ValueText>
                          </>
                        }
                      />
                    </ListItem>
                  ),
              )
            ) : (
              <>No Metadata</>
            )}
          </List>
          <Box sx={{ display: "flex", justifyContent: "left", mt: 2 }}>
            <DumpPslistButton
              evidenceId={id}
              pid={processMetadata.PID}
              loading={loadingDumpPslist}
              setLoading={setLoadingDumpPslist}
            />
            <DumpMapsButton
              evidenceId={id}
              pid={processMetadata.PID}
              loading={loadingDumpMaps}
              setLoading={setLoadingDumpMaps}
            />
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
};

export default ProcessMetadata;
