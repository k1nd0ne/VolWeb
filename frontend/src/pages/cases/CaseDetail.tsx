import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { Case } from "../../types";
import axiosInstance from "../../utils/axiosInstance";
import { Typography, CircularProgress, Card, CardContent } from "@mui/material";

const CaseDetail: React.FC = () => {
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
        console.error("Error fetching case details", error);
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
        </CardContent>
      </Card>
    )
  );
};

export default CaseDetail;
