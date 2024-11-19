import React from "react";
import {
  Card,
  CardContent,
  Typography,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
} from "@mui/material";
import WorkIcon from "@mui/icons-material/Work";
import { Case } from "../../types";

interface RecentCasesProps {
  cases: Case[];
}

const RecentCases: React.FC<RecentCasesProps> = ({ cases }) => {
  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom>
          Recent Cases
        </Typography>
        <Divider />
        <List>
          {cases.map((caseItem, index) => (
            <ListItem key={index}>
              <ListItemIcon>
                <WorkIcon />
              </ListItemIcon>
              <ListItemText primary={caseItem.name} />
            </ListItem>
          ))}
        </List>
      </CardContent>
    </Card>
  );
};

export default RecentCases;
