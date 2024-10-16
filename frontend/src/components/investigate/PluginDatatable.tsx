import React, { useEffect, useState } from "react";
import Box from "@mui/material/Box";
import TextField from "@mui/material/TextField";
import DataTable, { createTheme } from "react-data-table-component";
import { useParams } from "react-router-dom";
import axiosInstance from "../../utils/axiosInstance";

createTheme(
  "mui",
  {
    text: {
      primary: "#fff",
      secondary: "rgba(255, 255, 255, 0.7)",
    },
    background: {
      default: "#121212",
    },
    context: {
      background: "#121212",
      text: "#FFFFFF",
    },
    divider: {
      default: "rgba(255, 255, 255, 0.12)",
    },
    button: {
      default: "#fff",
      hover: "rgba(255, 255, 255, 0.08)",
      focus: "rgba(255, 255, 255, 0.16)",
      disabled: "rgba(255, 255, 255, 0.12)",
    },
  },
  "dark",
);

interface PluginDatatableProps {
  pluginName: string;
}

interface Artefact {
  [key: string]: string | number | boolean | null;
}

const PluginDatatable: React.FC<PluginDatatableProps> = ({ pluginName }) => {
  const { id } = useParams<{ id: string }>();
  const [data, setData] = useState<Artefact[]>([]);
  const [searchText, setSearchText] = useState<string>("");

  useEffect(() => {
    const fetchCaseDetail = async () => {
      try {
        const response = await axiosInstance.get(
          `/api/evidence/${id}/plugin/${pluginName}`,
        );
        setData(response.data.artefacts);
      } catch (error) {
        console.error("Error fetching case details", error);
      }
    };

    fetchCaseDetail();
  }, [id, pluginName]);

  const columns = data[0]
    ? Object.keys(data[0])
        .filter((key) => key !== "__children")
        .map((key) => {
          return {
            name: key,
            selector: (row: Artefact) => (row[key] !== null ? row[key] : ""),
            sortable: true,
            compact: true,
            reorder: true,
            wrap: true,
          };
        })
    : [];

  const filteredData = data.filter((item) =>
    Object.values(item).some((value) =>
      value?.toString().toLowerCase().includes(searchText.toLowerCase()),
    ),
  );

  return (
    <Box sx={{ flexGrow: 1, p: 2 }}>
      <Box mb={2}>
        <TextField
          label="Search"
          variant="outlined"
          size="small"
          fullWidth
          value={searchText}
          onChange={(e) => setSearchText(e.target.value)}
        />
      </Box>
      <DataTable theme="mui" columns={columns} data={filteredData} pagination />
    </Box>
  );
};

export default PluginDatatable;
