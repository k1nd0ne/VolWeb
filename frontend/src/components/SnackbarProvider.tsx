import React, { createContext, useState, useContext, ReactNode } from "react";
import { Snackbar, Alert, AlertColor } from "@mui/material";

// Define the shape of the context value
interface SnackbarContextValue {
  display_message: (severity: AlertColor, message: string) => void;
}

// Create a Context for the Snackbar
const SnackbarContext = createContext<SnackbarContextValue | undefined>(
  undefined,
);

export const useSnackbar = (): SnackbarContextValue => {
  const context = useContext(SnackbarContext);
  if (!context) {
    throw new Error("useSnackbar must be used within a SnackbarProvider");
  }
  return context;
};

interface SnackbarProviderProps {
  children: ReactNode;
}

export const SnackbarProvider: React.FC<SnackbarProviderProps> = ({
  children,
}) => {
  const [open, setOpen] = useState<boolean>(false);
  const [severity, setSeverity] = useState<AlertColor>("success"); // 'error', 'warning', 'info', 'success'
  const [message, setMessage] = useState<string>("");

  const display_message = (severity: AlertColor, message: string) => {
    setSeverity(severity);
    setMessage(message);
    setOpen(true);
  };

  // Function to handle closing the Snackbar
  const handleClose = (
    _event?: React.SyntheticEvent | Event,
    reason?: string,
  ) => {
    if (reason === "clickaway") {
      return;
    }
    setOpen(false);
  };

  return (
    <SnackbarContext.Provider value={{ display_message }}>
      {children}
      <Snackbar
        open={open}
        autoHideDuration={6000}
        onClose={handleClose}
        anchorOrigin={{ vertical: "bottom", horizontal: "left" }}
      >
        <Alert
          onClose={handleClose}
          severity={severity}
          sx={{ width: "100%" }}
          elevation={6}
          variant="outlined"
        >
          {message}
        </Alert>
      </Snackbar>
    </SnackbarContext.Provider>
  );
};
