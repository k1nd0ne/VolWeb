import TreeItem, { TreeItemProps } from "@mui/x-tree-view/TreeItem";

interface CustomTreeItemProps extends TreeItemProps {
  pid: number;
}

const CustomTreeItem: React.FC<CustomTreeItemProps> = (props) => {
  const { pid, ...other } = props;

  return (
    <TreeItem
      {...other}
      sx={{
        "& .MuiTreeItem-label": {
          ...(pid === 0 && {
            color: "green", // Apply green color if PID is 0
          }),
        },
      }}
    />
  );
};

export default CustomTreeItem;
