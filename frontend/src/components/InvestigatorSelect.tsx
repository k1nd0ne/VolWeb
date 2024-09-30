import * as React from "react";
import axiosInstance from "../utils/axiosInstance";
import InputLabel from "@mui/material/InputLabel";
import FormControl from "@mui/material/FormControl";
import Select from "@mui/material/Select";
import MenuItem from "@mui/material/MenuItem";
import CircularProgress from "@mui/material/CircularProgress";

const InvestigatorSelect = () => {
  const [investigators, setInvestigators] = React.useState<string[]>([]);
  const [selectedInvestigators, setSelectedInvestigators] = React.useState<
    string[]
  >([]);
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    const fetchInvestigators = async () => {
      try {
        const response = await axiosInstance.get("/api/users/");
        const usernames = response.data.map((user: any) => user.username);
        setInvestigators(usernames);
      } catch (error) {
        console.error("Error fetching investigators", error);
      } finally {
        setLoading(false);
      }
    };

    fetchInvestigators();
  }, []);

  const handleChange = (event: React.ChangeEvent<{ value: unknown }>) => {
    setSelectedInvestigators(event.target.value as string[]);
  };

  if (loading) {
    return <CircularProgress />;
  }

  return (
    <div>
      <FormControl sx={{ width: 1 }}>
        <InputLabel shrink htmlFor="select-multiple-native">
          Investigators
        </InputLabel>
        <Select
          multiple
          value={selectedInvestigators}
          onChange={handleChange}
          inputProps={{ id: "select-multiple-native" }}
        >
          {investigators.map((name) => (
            <MenuItem key={name} value={name}>
              {name}
            </MenuItem>
          ))}
        </Select>
      </FormControl>
    </div>
  );
};

export default InvestigatorSelect;
