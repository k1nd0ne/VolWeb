import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { Case } from "../../types";
import axiosInstance from "../../utils/axiosInstance";
import {
  Typography,
  CircularProgress,
  Card,
  CardContent,
  Divider,
  Stack,
  Container,
} from "@mui/material";
import Grid from "@mui/material/Grid";
import EvidenceList from "../../components/Lists/EvidenceList";
import CaseIndicatorsList from "../../components/Lists/CaseIndicatorsList";
import StixButton from "../../components/StixButton";
import { useSnackbar } from "../../components/SnackbarProvider";
const CaseDetail: React.FC = () => {
  const { display_message } = useSnackbar();

  const { id } = useParams<{ id: string }>();
  const [caseDetail, setCaseDetail] = useState<Case | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchCaseDetail = async () => {
      try {
        const response = await axiosInstance.get(`/api/cases/${id}/`);
        setCaseDetail(response.data);
        setLoading(false);
      } catch (error) {
        display_message("error", `An error fetching case details: ${error}`);
        console.error("Error fetching case details", error);
      }
    };

    fetchCaseDetail();
  }, [id, display_message]);

  if (loading) {
    return <CircularProgress />;
  }

  return (
    caseDetail && (
      <Grid spacing={2} container>
        <Grid size={12}>
          <Card variant="outlined" sx={{ marginBottom: 2 }}>
            <CardContent>
              <Typography variant="h5" component="div">
                {caseDetail.name}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {caseDetail.description}
              </Typography>
              <Typography variant="subtitle1" component="div">
                Last Update: {caseDetail.last_update}
              </Typography>
              <Typography
                variant="subtitle1"
                component="div"
                sx={{ marginTop: 2 }}
              >
                Investigator(s):{" "}
                {caseDetail.linked_users
                  .map((user) => user.username)
                  .join(", ")}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={12}>
          <Typography variant="h5" component="div" sx={{ marginBottom: 2 }}>
            Linked evidences
          </Typography>
          <Divider sx={{ marginBottom: 2 }} />
          <EvidenceList caseId={caseDetail.id} />
        </Grid>
        <Container sx={{ marginTop: 12 }}>
          <Stack
            direction="row"
            spacing={2}
            sx={{ justifyContent: "space-between", alignItems: "center" }}
          >
            <Typography gutterBottom variant="h5" component="div">
              Indicators
            </Typography>
            <StixButton caseId={caseDetail.id} />
          </Stack>

          <CaseIndicatorsList caseId={caseDetail.id} />
        </Container>
      </Grid>
    )
  );
};

export default CaseDetail;
