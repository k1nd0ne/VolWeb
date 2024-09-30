import React from "react";
import Snackbar from "@mui/material/Snackbar";
import MuiAlert, { AlertProps } from "@mui/material/Alert";

interface MessageHandlerProps {
  open: boolean;
  message: string;
  severity: "error" | "warning" | "info" | "success";
  onClose: () => void;
}

const Alert = React.forwardRef<HTMLDivElement, AlertProps>(
  function Alert(props, ref) {
    return <MuiAlert elevation={6} ref={ref} variant="filled" {...props} />;
  },
);

const MessageHandler: React.FC<MessageHandlerProps> = ({
  open,
  message,
  severity,
  onClose,
}) => {
  return (
    <Snackbar open={open} autoHideDuration={6000} onClose={onClose}>
      <Alert onClose={onClose} severity={severity} sx={{ width: "100%" }}>
        {message}
      </Alert>
    </Snackbar>
  );
};

export default MessageHandler;
