import React, { useEffect, useCallback } from "react";
import axiosInstance from "../../utils/axiosInstance";
import Tabs from "@mui/material/Tabs";
import Tab from "@mui/material/Tab";
import Box from "@mui/material/Box";
import EvidenceMetadata from "../../components/EvidenceMetadata";
import InvestigateWindows from "../../components/Investigate/Windows/Components/InvestigateWindows";
import InvestigateLinux from "../../components/Investigate/Linux/Components/InvestigateLinux";
import HomeIcon from "@mui/icons-material/Home";
import TimelineIcon from "@mui/icons-material/Timeline";
import SecurityIcon from "@mui/icons-material/Security";
import Timeliner from "../../components/Investigate/Timeliner";
import YaraScan from "../../components/Investigate/YaraScan";
import PluginSelector from "../../components/Investigate/PluginSelector";
import StixModule from "../../components/StixModule";
import ExploreLinux from "../../components/Explore/Linux/Explore";
import ExploreWin from "../../components/Explore/Windows/Explore";
import { Evidence } from "../../types";
import { useParams, useSearchParams, useNavigate } from "react-router-dom";
import { ArrowBack, Biotech, BlurOn } from "@mui/icons-material";
import IconButton from "@mui/material/IconButton";
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
  const navigate = useNavigate();
  const { id } = useParams<{ id: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const [currentEvidence, setCurrentEvidence] = React.useState<Evidence>();
  const showConfigure = searchParams.get("configure") === "true";

  const fetchEvidenceDetails = useCallback(async () => {
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
  }, [id, display_message]);

  useEffect(() => {
    fetchEvidenceDetails();
  }, [fetchEvidenceDetails]);

  const handleChange = (_: React.SyntheticEvent, newValue: number) => {
    setValue(newValue);
  };

  // Show plugin selector when evidence is awaiting plugin selection or configure mode
  if (currentEvidence && (currentEvidence.status === -2 || showConfigure)) {
    return (
      <Box sx={{ width: "100%" }}>
        <PluginSelector
          key={id}
          evidenceId={id!}
          evidenceOs={currentEvidence.os}
          onExtractionStarted={() => {
            navigate(-1);
          }}
          onBack={() => {
            navigate("/evidences");
          }}
        />
      </Box>
    );
  }

  return (
    <Box sx={{ width: "100%" }}>
      <Box sx={{ display: "flex", alignItems: "center", borderBottom: 1, borderColor: "divider" }}>
        <IconButton onClick={() => navigate("/evidences")} size="small" sx={{ ml: 1 }}>
          <ArrowBack />
        </IconButton>
        <Tabs
          variant="fullWidth"
          value={value}
          onChange={handleChange}
          sx={{
            flex: 1,
            "& .MuiTabs-indicator": {
              backgroundColor: "error.main",
            },
            "& .MuiTab-root.Mui-selected": {
              color: "inherit",
            },
          }}
          style={{ height: "60px" }}
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
              label="Explore"
              icon={<BlurOn />}
              iconPosition="start"
              {...a11yProps(1)}
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
          <Tab
            label="YARA Scan"
            icon={<SecurityIcon />}
            iconPosition="start"
            {...a11yProps(4)}
            sx={{ fontSize: "0.75rem" }}
          />
        </Tabs>
      </Box>
      <CustomTabPanel value={value} index={0}>
        <EvidenceMetadata evidenceId={id} theme={"dark"} />
      </CustomTabPanel>
      <CustomTabPanel value={value} index={1}>
        {currentEvidence && currentEvidence.os === "windows" && (
          <ExploreWin evidence={currentEvidence} />
        )}
        {currentEvidence && currentEvidence.os === "linux" && (
          <ExploreLinux evidence={currentEvidence} />
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
      <CustomTabPanel value={value} index={4}>
        {id && <YaraScan evidenceId={id} evidenceOs={currentEvidence?.os} />}
      </CustomTabPanel>
      <StixModule evidenceId={id} />
    </Box>
  );
};

export default EvidenceDetail;