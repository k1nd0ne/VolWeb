import React, { useEffect, useState } from "react";
import { TextField, CircularProgress } from "@mui/material";
import Autocomplete from "@mui/material/Autocomplete";
import axiosInstance from "../utils/axiosInstance";
import { User } from "../types";

const InvestigatorSelect: React.FC<{
  selectedUsers: User[];
  setSelectedUsers: (users: User[]) => void;
}> = ({ selectedUsers, setSelectedUsers }) => {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    const fetchUsers = async () => {
      try {
        const response = await axiosInstance.get("/core/users/");
        setUsers(response.data);
      } catch (error) {
        console.error("Error fetching users", error);
      } finally {
        setLoading(false);
      }
    };

    fetchUsers();
  }, []);

  const availableUsers = users.filter(
    (user) =>
      !selectedUsers.some((selectedUser) => selectedUser.id === user.id),
  );

  return (
    <Autocomplete
      multiple
      options={availableUsers}
      getOptionLabel={(user) =>
        `${user.first_name} ${user.last_name} (${user.username})`
      }
      value={selectedUsers}
      onChange={(_event, newValue) => setSelectedUsers(newValue)}
      renderInput={(params) => (
        <TextField
          {...params}
          variant="outlined"
          label="Investigators"
          placeholder="Select investigators"
          margin="normal"
          fullWidth
          InputProps={{
            ...params.InputProps,
            endAdornment: (
              <>
                {loading ? (
                  <CircularProgress color="inherit" size={20} />
                ) : null}
                {params.InputProps.endAdornment}
              </>
            ),
          }}
        />
      )}
    />
  );
};

export default InvestigatorSelect;
