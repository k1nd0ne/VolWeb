import React from "react";
import {
  Card,
  CardContent,
  Typography,
  List,
  ListItem,
  ListItemText,
} from "@mui/material";

interface ISFItem {
  name: string;
}

interface RecentISFProps {
  isfList: ISFItem[];
}

const RecentISF: React.FC<RecentISFProps> = ({ isfList }) => {
  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom>
          Recent ISF
        </Typography>
        <List>
          {isfList.map((isfItem, index) => (
            <ListItem key={index} button>
              <ListItemText primary={isfItem.name} />
            </ListItem>
          ))}
        </List>
      </CardContent>
    </Card>
  );
};

export default RecentISF;
