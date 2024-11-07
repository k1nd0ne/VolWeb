import React from "react";
import Tabs from "@mui/material/Tabs";
import Tab from "@mui/material/Tab";
import Box from "@mui/material/Box";
import EvidenceMetadata from "../../components/EvidenceMetadata";
import EvidenceInvestigate from "../../components/investigate/EvidenceInvestigate";
import HomeIcon from "@mui/icons-material/Home";
import SearchIcon from "@mui/icons-material/Search";
import TimelineIcon from "@mui/icons-material/Timeline";
import Timeliner from "../../components/investigate/Timeliner";
import StixModule from "../../components/StixModule";
import { useParams } from "react-router-dom";

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
  const { id } = useParams<{ id: string }>();

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
          <Tab
            label="Investigate"
            icon={<SearchIcon />}
            iconPosition="start"
            {...a11yProps(1)}
            sx={{ fontSize: "0.75rem" }}
          />
          <Tab
            label="Timeline"
            icon={<TimelineIcon />}
            iconPosition="start"
            {...a11yProps(2)}
            sx={{ fontSize: "0.75rem" }}
          />
        </Tabs>
      </Box>
      <CustomTabPanel value={value} index={0}>
        <EvidenceMetadata evidenceId={id} theme={"dark"} />
      </CustomTabPanel>
      <CustomTabPanel value={value} index={1}>
        <EvidenceInvestigate />
      </CustomTabPanel>
      <CustomTabPanel value={value} index={2}>
        <Timeliner />
      </CustomTabPanel>
      <StixModule evidenceId={id} />
    </Box>
  );
};

export default EvidenceDetail;
