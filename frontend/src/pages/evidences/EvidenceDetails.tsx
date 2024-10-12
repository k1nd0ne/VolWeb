import React from "react";
import Tabs from "@mui/material/Tabs";
import Tab from "@mui/material/Tab";
import Box from "@mui/material/Box";
import EvicenceMetadata from "../../components/EvidenceMetadata";
import EvidenceInvestigate from "../../components/investigate/EvidenceInvestigate";

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

  const handleChange = (event: React.SyntheticEvent, newValue: number) => {
    setValue(newValue);
  };

  return (
    <Box sx={{ width: "100%" }}>
      <Box sx={{ borderBottom: 1, borderColor: "divider" }}>
        <Tabs
          value={value}
          centered
          onChange={handleChange}
          aria-label="basic tabs example"
        >
          <Tab
            label="Overview"
            {...a11yProps(0)}
            sx={{ fontSize: "0.75rem" }}
          />
          <Tab
            label="Investigate"
            {...a11yProps(1)}
            sx={{ fontSize: "0.75rem" }}
          />
          <Tab
            label="Timeliner"
            {...a11yProps(2)}
            sx={{ fontSize: "0.75rem" }}
          />
        </Tabs>
      </Box>
      <CustomTabPanel value={value} index={0}>
        <EvicenceMetadata />
      </CustomTabPanel>
      <CustomTabPanel value={value} index={1}>
        <EvidenceInvestigate />
      </CustomTabPanel>
      <CustomTabPanel value={value} index={2}>
        Item Three
      </CustomTabPanel>
    </Box>
  );
};

export default EvidenceDetail;
