import React, { useEffect } from "react";
import axiosInstance from "../../utils/axiosInstance";
import Tabs from "@mui/material/Tabs";
import Tab from "@mui/material/Tab";
import Box from "@mui/material/Box";
import EvidenceMetadata from "../../components/EvidenceMetadata";
import InvestigateWindows from "../../components/Investigate/Windows/Components/InvestigateWindows";
import InvestigateLinux from "../../components/Investigate/Linux/Components/InvestigateLinux";
import HomeIcon from "@mui/icons-material/Home";
import TimelineIcon from "@mui/icons-material/Timeline";
import Timeliner from "../../components/Investigate/Timeliner";
import StixModule from "../../components/StixModule";
import Explore from "../../components/Explore/Windows/Explore";
import { Evidence } from "../../types";
import { useParams } from "react-router-dom";
import { Biotech, BlurOn } from "@mui/icons-material";
import { useSnackbar } from "../../components/SnackbarProvider";

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function CustomTabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`simple-tabpanel-${index}`}
      aria-labelledby={`simple-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

function a11yProps(index: number) {
  return {
    id: `simple-tab-${index}`,
    "aria-controls": `simple-tabpanel-${index}`,
  };
}

const EvidenceDetail: React.FC = () => {
  const [value, setValue] = React.useState(0);
  const { display_message } = useSnackbar();
  const { id } = useParams<{ id: string }>();
  const [currentEvidence, setCurrentEvidence] = React.useState<Evidence>();
  useEffect(() => {
    const fetchEvidenceDetails = async () => {
      if (id) {
        try {
          const response = await axiosInstance.get(`/api/evidences/${id}`);
          setCurrentEvidence(response.data);
        } catch (error) {
          display_message(
            "error",
            `Failed to fetch evidence details: ${error}`,
          );
        }
      }
    };

    fetchEvidenceDetails();
  }, [id, display_message]);

  const handleChange = (_: React.SyntheticEvent, newValue: number) => {
    setValue(newValue);
  };

  return (
    <Box sx={{ width: "100%" }}>
      <Box sx={{ borderBottom: 1, borderColor: "divider" }}>
        <Tabs
          variant="fullWidth"
          value={value}
          onChange={handleChange}
          sx={{
            "& .MuiTabs-indicator": {
              backgroundColor: "error.main",
            },
            "& .MuiTab-root.Mui-selected": {
              color: "inherit",
            },
          }}
          style={{ height: "0px" }}
        >
          <Tab
            label="Overview"
            icon={<HomeIcon />}
            iconPosition="start"
            {...a11yProps(0)}
            sx={{
              fontSize: "0.75rem",
            }}
          />
          {currentEvidence && currentEvidence.os === "windows" && (
            <Tab
              label="Explore"
              icon={<BlurOn />}
              iconPosition="start"
              {...a11yProps(1)}
              sx={{ fontSize: "0.75rem" }}
            />
          )}

          {currentEvidence && currentEvidence.os === "linux" && (
            <Tab
              label="Explore (coming soon)"
              icon={<BlurOn />}
              iconPosition="start"
              {...a11yProps(1)}
              disabled
              sx={{ fontSize: "0.75rem" }}
            />
          )}

          <Tab
            label="Investigate"
            icon={<Biotech />}
            iconPosition="start"
            {...a11yProps(2)}
            sx={{ fontSize: "0.75rem" }}
          />
          <Tab
            label="Timeline"
            icon={<TimelineIcon />}
            iconPosition="start"
            {...a11yProps(3)}
            sx={{ fontSize: "0.75rem" }}
          />
        </Tabs>
      </Box>
      <CustomTabPanel value={value} index={0}>
        <EvidenceMetadata evidenceId={id} theme={"dark"} />
      </CustomTabPanel>
      <CustomTabPanel value={value} index={1}>
        {currentEvidence && currentEvidence.os === "windows" && (
          <Explore evidence={currentEvidence} />
        )}
      </CustomTabPanel>
      <CustomTabPanel value={value} index={2}>
        {currentEvidence && currentEvidence.os === "windows" && (
          <InvestigateWindows evidence={currentEvidence} />
        )}
        {currentEvidence && currentEvidence.os === "linux" && (
          <InvestigateLinux evidence={currentEvidence} />
        )}
      </CustomTabPanel>
      <CustomTabPanel value={value} index={3}>
        <Timeliner />
      </CustomTabPanel>
      <StixModule evidenceId={id} />
    </Box>
  );
};

export default EvidenceDetail;
