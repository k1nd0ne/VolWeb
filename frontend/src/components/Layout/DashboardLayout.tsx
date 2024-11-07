import React from "react";
import { AppBar, Toolbar, Typography, Container } from "@mui/material";

const DashboardLayout: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  return (
    <div>
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6">VolWeb Dashboard</Typography>
        </Toolbar>
      </AppBar>
      <Container maxWidth="lg" style={{ marginTop: "2rem" }}>
        {children}
      </Container>
    </div>
  );
};

export default DashboardLayout;
