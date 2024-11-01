import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import axiosInstance from "../../utils/axiosInstance";
import { Button, Tooltip } from "@mui/material";

import { BugReportRounded } from "@mui/icons-material";
const FileScan: React.FC = () => {
    return (
        <Tooltip
            title={"Test"}
            arrow
            key={"volatility3.plugins.windows.netscan.NetGraph"}
            placement="top"
        >
            <span>
                <Button
                    color={"error"}
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

export default FileScan;
