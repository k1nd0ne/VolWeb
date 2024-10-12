import React from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
} from "react-router-dom";
import { ThemeProvider, createTheme } from "@mui/material/styles";
import CssBaseline from "@mui/material/CssBaseline";
import MiniDrawer from "./components/SideBar";
import Cases from "./pages/cases/Cases";
import Dashboard from "./pages/dashboard/Dashboard";
import Evidences from "./pages/evidences/Evidences";
import Login from "./pages/auth/Login";
import CaseDetail from "./pages/cases/CaseDetail";
import EvidenceDetail from "./pages/evidences/EvidenceDetails";

const darkTheme = createTheme({
  palette: {
    mode: "dark",
  },
});

const PrivateRoute = ({ children }: { children: JSX.Element }) => {
  const isAuthenticated = !!localStorage.getItem("access_token");
  return isAuthenticated ? children : <Navigate to="/login" />;
};

const App: React.FC = () => {
  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <Router>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/"
            element={
              <PrivateRoute>
                <MiniDrawer />
              </PrivateRoute>
            }
          >
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="cases" element={<Cases />} />
            <Route path="evidences" element={<Evidences />} />
            <Route path="evidences/:id" element={<EvidenceDetail />} />
            <Route path="cases/:id" element={<CaseDetail />} />
          </Route>
        </Routes>
      </Router>
    </ThemeProvider>
  );
};

export default App;
