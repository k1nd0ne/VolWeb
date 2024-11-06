import React, { useState } from "react";
import { DataGrid, GridColDef, GridToolbar } from "@mui/x-data-grid";
import { Box, Button, CircularProgress } from "@mui/material";
import axiosInstance from "../../../../utils/axiosInstance";
import { useParams } from "react-router-dom";
import { Artefact } from "../../../../types";
interface FileScanProps {
  data: Artefact[];
}

const FileScan: React.FC<FileScanProps> = ({ data }) => {
  const { id: evidenceId } = useParams<{ id: string }>();
  const [loadingRows, setLoadingRows] = useState<{ [key: number]: boolean }>(
    {},
  );

  const columns: GridColDef[] = data[0]
    ? Object.keys(data[0])
        .filter((key) => key !== "__children" && key !== "id")
        .map((key) => ({
          field: key,
          headerName: key,
          flex: 1,
          renderCell: (params) => params.value,
        }))
    : [];

  columns.push({
    field: "actions",
    headerName: "Actions",
    sortable: false,
    renderCell: (params) => {
      const rowId = params.row.id;
      const isLoading = loadingRows[rowId];

      const handleDumpClick = async () => {
        // Set loading state for this row
        setLoadingRows((prev) => ({ ...prev, [rowId]: true }));

        try {
          await axiosInstance.post("/api/evidence/tasks/dump/file/", {
            evidenceId,
            offset: params.row.Offset,
          });
          // Optionally handle success notification
        } catch (error) {
          console.error("Error during dump", error);
          // Optionally handle error notification
        } finally {
          // Reset loading state
          setLoadingRows((prev) => ({ ...prev, [rowId]: false }));
        }
      };

      return (
        <Button
          variant="outlined"
          color="error"
          size="small"
          onClick={handleDumpClick}
          disabled={isLoading}
        >
          {isLoading ? <CircularProgress size={24} /> : "Dump"}
        </Button>
      );
    },
  });

  return (
    <Box>
      <DataGrid
        disableDensitySelector
        slots={{
          toolbar: GridToolbar,
        }}
        slotProps={{
          toolbar: {
            showQuickFilter: true,
          },
        }}
        sx={{ height: "85vh" }}
        rows={data}
        columns={columns}
        getRowId={(row) => row.id}
        pagination
        getRowHeight={() => "auto"}
      />
    </Box>
  );
};

export default FileScan;
