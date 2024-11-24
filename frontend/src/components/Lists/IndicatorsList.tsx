import { useEffect, useState } from "react";
import {
  Box,
  Typography,
  IconButton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  CircularProgress,
} from "@mui/material";
import { Close as CloseIcon } from "@mui/icons-material";
import axiosInstance from "../../utils/axiosInstance";
import { useSnackbar } from "../SnackbarProvider";
import { Indicator } from "../../types";
interface IndicatorsListProps {
  open: boolean;
  onClose: () => void;
  evidenceId?: string;
  onIndicatorDeleted?: (indicatorId: number) => void;
}

const IndicatorsList: React.FC<IndicatorsListProps> = ({
  open,
  onClose,
  evidenceId,
  onIndicatorDeleted,
}) => {
  const [indicators, setIndicators] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const { display_message } = useSnackbar();

  useEffect(() => {
    if (open) {
      fetchIndicators();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const fetchIndicators = async () => {
    setIsLoading(true);
    try {
      const url = `/core/stix/indicators/evidence/${evidenceId}/`;
      const response = await axiosInstance.get(url);
      setIndicators(response.data);
    } catch (err) {
      display_message("error", `Failed to fetch indicators: ${err}`);
    } finally {
      setIsLoading(false);
    }
  };

  // Handle Delete Indicator
  const handleDelete = async (indicatorId: number) => {
    if (!window.confirm("Are you sure you want to delete this indicator?")) {
      return;
    }

    try {
      await axiosInstance.delete(`/core/stix/indicators/${indicatorId}/`);
      fetchIndicators();
      if (onIndicatorDeleted) {
        onIndicatorDeleted(indicatorId);
      }
    } catch (err) {
      display_message("error", `Failed to delete the indicator: ${err}`);
    }
  };

  return (
    <Box
      sx={{
        padding: 2,
        height: "100%",
        display: "flex",
        flexDirection: "column",
      }}
    >
      <Box display="flex" justifyContent="space-between" alignItems="center">
        <Typography variant="h6" color="warning">
          Indicators
        </Typography>
        <IconButton onClick={onClose}>
          <CloseIcon />
        </IconButton>
      </Box>

      <Box mt={2} flexGrow={1} overflow="auto">
        {isLoading ? (
          <Box
            display="flex"
            justifyContent="center"
            alignItems="center"
            height="100%"
          >
            <CircularProgress />
          </Box>
        ) : (
          <TableContainer component={Box}>
            <Table size="small" aria-label="indicators table">
              <TableHead>
                <TableRow>
                  <TableCell>Type</TableCell>
                  <TableCell>Name</TableCell>
                  <TableCell>Description</TableCell>
                  <TableCell>Value</TableCell>
                  <TableCell>Source</TableCell>
                  <TableCell>Action</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {indicators.length > 0 ? (
                  indicators.map((indicator: Indicator) => (
                    <TableRow key={indicator.id}>
                      <TableCell>
                        <Box
                          sx={{
                            p: 1,
                            textTransform: "uppercase",
                            fontWeight: "600",
                            color: "warning.main",
                            border: "1px solid",
                            borderColor: "warning.light",
                            textAlign: "center",
                          }}
                        >
                          {indicator.type}
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" color="text.secondary">
                          {indicator.name}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" color="text.secondary">
                          {indicator.description}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" color="error">
                          {indicator.value}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" color="text.secondary">
                          {indicator.dump_linked_dump_name}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="outlined"
                          color="error"
                          size="small"
                          onClick={() => handleDelete(indicator.id)}
                        >
                          Remove
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={6} align="center">
                      No indicators found.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Box>
    </Box>
  );
};

export default IndicatorsList;
