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
import BackupTableIcon from "@mui/icons-material/BackupTable";
interface ISFItem {
  name: string;
}

interface RecentISFProps {
  isfList: ISFItem[];
}

const RecentISF: React.FC<RecentISFProps> = ({ isfList }) => {
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6" gutterBottom>
          Recent ISF
        </Typography>
        <Divider />
        <List>
          {isfList.map((isfItem, index) => (
            <ListItem key={index}>
              <ListItemIcon>
                <BackupTableIcon />
              </ListItemIcon>
              <ListItemText primary={isfItem.name} />
            </ListItem>
          ))}
        </List>
      </CardContent>
    </Card>
  );
};

export default RecentISF;
