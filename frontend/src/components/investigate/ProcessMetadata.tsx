import React from "react";
import { useParams } from "react-router-dom";
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
import { ProcessInfo } from "../../types";
import { styled } from "@mui/material/styles";
import DumpButton from "./Windows/Buttons/DumpButton";
import ComputeHandlesButton from "./Windows/Buttons/ComputeHandlesButton";

interface ProcessMetadataProps {
  processMetadata: ProcessInfo;
}

const ValueText = styled("span")(({ theme }) => ({
  color: theme.palette.primary.main,
  "&.wow64": {
    color: "red",
  },
}));

const ProcessMetadata: React.FC<ProcessMetadataProps> = ({
  processMetadata,
}) => {
  const { id } = useParams<{ id: string }>();

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
                  key !== "__children" && (
                    <ListItem key={key} sx={{ fontSize: "0.800rem" }}>
                      <ListItemText
                        primary={
                          <>
                            {`${key}: `}
                            <ValueText
                              className={
                                key === "WoW64" && value ? "wow64" : ""
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
            <DumpButton evidenceId={id} pid={processMetadata.PID} />
            <ComputeHandlesButton evidenceId={id} pid={processMetadata.PID} />
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
};

export default ProcessMetadata;
