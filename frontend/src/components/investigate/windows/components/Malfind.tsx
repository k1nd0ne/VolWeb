import { FC, useState } from "react";
import { Artefact } from "../../../../types";
import {
  List,
  ListItemButton,
  ListItemText,
  Card,
  CardHeader,
  CardContent,
  Typography,
  ListItemIcon,
  Divider,
} from "@mui/material";
import FingerprintIcon from "@mui/icons-material/Fingerprint";
import Grid from "@mui/material/Grid2";
type MalfindProps = {
  data: Artefact[];
};

const Malfind: FC<MalfindProps> = ({ data }) => {
  const [selectedProcess, setSelectedProcess] = useState<Artefact | null>(null);

  const handleProcessClick = (artefact: Artefact) => {
    setSelectedProcess(artefact);
  };

  return (
    <Grid container spacing={2}>
      <Grid size={2}>
        <Card variant="outlined">
          <CardHeader title="Processes" />
          <Divider />
          <List>
            {data.map((artefact, index) => (
              <ListItemButton
                selected={
                  selectedProcess &&
                  selectedProcess["Start VPN"] === artefact["Start VPN"]
                    ? true
                    : false
                }
                dense={true}
                key={index}
                onClick={() => handleProcessClick(artefact)}
              >
                <ListItemIcon>
                  <FingerprintIcon color="secondary" />
                </ListItemIcon>
                <ListItemText
                  primary={`${artefact.Process} - ${artefact.PID}`}
                />
              </ListItemButton>
            ))}
          </List>
        </Card>
      </Grid>

      <Grid size={10}>
        {selectedProcess && (
          <Card variant="outlined">
            <CardHeader
              title={`VPN: ${selectedProcess["Start VPN"]} - ${selectedProcess["End VPN"]}`}
              subheader={
                <Grid container>
                  <Grid size={6}>
                    <List component="div" disablePadding>
                      <ListItemText primary={`Tag: ${selectedProcess.Tag}`} />
                      <ListItemText
                        primary={`Protection: ${selectedProcess.Protection}`}
                        primaryTypographyProps={{ color: "warning" }}
                      />
                    </List>
                  </Grid>
                  <Grid size={6}>
                    <List component="div" disablePadding>
                      <ListItemText
                        primary={`CommitCharge: ${selectedProcess.CommitCharge}`}
                      />
                      <ListItemText
                        primary={`PrivateMemory: ${selectedProcess.PrivateMemory}`}
                      />
                    </List>
                  </Grid>
                </Grid>
              }
            />
            <Divider />

            <CardContent>
              <Grid container spacing={2}>
                <Grid size={6}>
                  <Typography variant="h6">Hexdump</Typography>
                  <pre>{selectedProcess.Hexdump}</pre>
                </Grid>
                <Grid size={6}>
                  <Typography variant="h6">Disasm</Typography>
                  <Typography style={{ fontSize: "0.8em" }} component="pre">
                    {selectedProcess.Disasm}
                  </Typography>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        )}
      </Grid>
    </Grid>
  );
};

export default Malfind;
