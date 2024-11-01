import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import axiosInstance from "../../utils/axiosInstance";
import { Button, Tooltip } from "@mui/material";

import { BugReportRounded } from "@mui/icons-material";
const UserAssist: React.FC = () => {
    return (
        <Tooltip title={"Test"} arrow key={"Malfind"} placement="top">
            <span>
                <Button
                    color={"primary"}
                    value={"plugin.name"}
                    variant="outlined"
                    size="small"
                    onClick={() => {}}
                    startIcon={<BugReportRounded />}
                    sx={{
                        marginRight: 1,
                        marginBottom: 1,
                    }}
                    disabled={false}
                >
                    {"plugin.name.split('.'').pop()"}
                </Button>
            </span>
        </Tooltip>
    );
};

export default UserAssist;
