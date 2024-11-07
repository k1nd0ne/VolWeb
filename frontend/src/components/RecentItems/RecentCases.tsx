import React from "react";
import {
  Card,
  CardContent,
  Typography,
  List,
  ListItem,
  ListItemText,
} from "@mui/material";

interface CaseItem {
  case_name: string;
}

interface RecentCasesProps {
  cases: CaseItem[];
}

const RecentCases: React.FC<RecentCasesProps> = ({ cases }) => {
  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom>
          Recent Cases
        </Typography>
        <List>
          {cases.map((caseItem, index) => (
            <ListItem key={index} button>
              <ListItemText primary={caseItem.name} />
            </ListItem>
          ))}
        </List>
      </CardContent>
    </Card>
  );
};

export default RecentCases;
