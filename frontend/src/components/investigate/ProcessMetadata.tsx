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
import { ProcessInfo } from "../../types";
import { styled } from "@mui/material/styles";

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
              Object.entries(processMetadata).map(([key, value]) => (
                <ListItem key={key}>
                  <ListItemText
                    primary={
                      <>
                        {`${key}: `}
                        <ValueText
                          className={key === "WoW64" && value ? "wow64" : ""}
                        >
                          {value?.toString()}
                        </ValueText>
                      </>
                    }
                  />
                </ListItem>
              ))
            ) : (
              <></>
            )}
          </List>
        </CardContent>
      </Card>
    </Box>
  );
};

export default ProcessMetadata;
