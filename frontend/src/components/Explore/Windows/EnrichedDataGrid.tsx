import React, { useEffect, useState } from "react";
import { Box } from "@mui/material";
import { DataGrid, GridColDef } from "@mui/x-data-grid";

interface EnrichedDataGridProps {
  data: Record<string, unknown>[];
}

const EnrichedDataGrid: React.FC<EnrichedDataGridProps> = ({ data }) => {
  const [columns, setColumns] = useState<GridColDef[]>([]);

  useEffect(() => {
    if (data && data.length > 0) {
      const generatedColumns: GridColDef[] = Object.keys(data[0] ?? {})
        .filter((key) => key !== "__children" && key !== "id")
        .map((key) => ({
          field: key,
          headerName: key,
          flex: 1,
          renderCell: (params) => {
            const value = params.value;
            if (typeof value === "boolean") {
              return value ? "True" : "False";
            } else if (value === null || value === undefined) {
              return "";
            } else if (typeof value === "object") {
              return JSON.stringify(value, null, 2);
            } else {
              return value;
            }
          },
        }));
      setColumns(generatedColumns);
    }
  }, [data]);

  return (
    <Box sx={{ height: "400px", width: "100%" }}>
      <DataGrid
        rows={data.map((row, index) => ({ id: index, ...row }))}
        columns={columns}
        density="compact"
        getRowId={(row) => row.id as string | number}
      />
    </Box>
  );
};

export default EnrichedDataGrid;
