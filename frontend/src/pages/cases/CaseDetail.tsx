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
} from "@mui/material";
import Grid from "@mui/material/Grid2";
import EvidenceList from "../../components/Lists/EvidenceList";
import CaseIndicatorsList from "../../components/Lists/CaseIndicatorsList";
import StixButton from "../../components/StixButton";
const CaseDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [caseDetail, setCaseDetail] = useState<Case | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchCaseDetail = async () => {
      try {
        const response = await axiosInstance.get(`/api/cases/${id}/`);
        console.log(response.data);
        setCaseDetail(response.data);
      } catch (error) {
        console.error("Error fetching case details", error);
      } finally {
        setLoading(false);
      }
    };

    fetchCaseDetail();
  }, [id]);

  if (loading) {
    return <CircularProgress />;
  }

  return (
    caseDetail && (
      <Grid spacing={2}>
        <Grid size={12}>
          <Card>
            <CardContent>
              <Typography variant="h5" component="div">
                {caseDetail.name}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {caseDetail.description}
              </Typography>
              <Typography variant="subtitle1" component="div">
                Bucket ID: {caseDetail.bucket_id}
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
          <Stack
            direction="row"
            spacing={2}
            sx={{ justifyContent: "space-between", alignItems: "center" }}
          >
            <Typography gutterBottom variant="h5" component="div">
              Indicators
            </Typography>
            <StixButton caseId={caseDetail.id.toString()} />
          </Stack>
          <Divider sx={{ marginBottom: 2 }} />
          <CaseIndicatorsList caseId={caseDetail.id.toString()} />
        </Grid>
        <Grid size={12}>
          <Typography variant="h5" component="div" sx={{ marginBottom: 2 }}>
            Linked evidences
          </Typography>
          <Divider sx={{ marginBottom: 2 }} />
          <EvidenceList caseId={caseDetail.id} />
        </Grid>
      </Grid>
    )
  );
};

export default CaseDetail;
