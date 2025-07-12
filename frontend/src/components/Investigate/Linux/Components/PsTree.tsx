import React, { useEffect, useState } from "react";
import Box from "@mui/material/Box";
import { Card, CardContent, Divider } from "@mui/material";
import MemoryIcon from "@mui/icons-material/Memory";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import { styled } from "@mui/material/styles";
import { RichTreeView } from "@mui/x-tree-view/RichTreeView";
import { TreeItem, treeItemClasses } from "@mui/x-tree-view/TreeItem";
import { TreeViewBaseItem } from "@mui/x-tree-view/models";
import axiosInstance from "../../../../utils/axiosInstance";
import { useParams } from "react-router-dom";
import Typography from "@mui/material/Typography";
import { LinuxProcessInfo } from "../../../../types";
import { useSnackbar } from "../../../SnackbarProvider";

// Styled TreeItem component with dashed border for parent nodes
const CustomTreeItem = styled(TreeItem)(() => ({
  [`& .${treeItemClasses.groupTransition}`]: {
    marginLeft: 1,
    paddingLeft: 12,
    borderLeft: `1px dashed grey`,
  },
  [`& .${treeItemClasses.iconContainer}`]: {
    "& .close": {
      opacity: 0.3,
    },
  },
  [`& .MuiTreeItem-label`]: {
    fontSize: "0.800rem !important",
  },
}));

// Helper function to transform artefacts data to TreeViewBaseItem
const transformProcessData = (
  nodes: LinuxProcessInfo[],
): TreeViewBaseItem[] => {
  return nodes.map((node) => ({
    id: node.PID.toString(),
    label: ` ${node.PID.toString()} - ${node.COMM} `,
    children: node.__children ? transformProcessData(node.__children) : [],
  }));
};

// Helper function to extract all node (P)IDs for default expansion
const extractAllNodeIds = (nodes: LinuxProcessInfo[]): string[] => {
  let ids: string[] = [];
  nodes.forEach((node) => {
    ids.push(node.PID.toString());
    if (node.__children && node.__children.length > 0) {
      ids = ids.concat(extractAllNodeIds(node.__children));
    }
  });
  return ids;
};

interface PsTreeProps {
  setProcessMetadata: (processInfo: LinuxProcessInfo) => void;
}

const PsTree: React.FC<PsTreeProps> = ({ setProcessMetadata }) => {
  const { id } = useParams<{ id: string }>();
  const [treeItems, setTreeItems] = useState<TreeViewBaseItem[]>([]);
  const [expanded, setExpanded] = useState<string[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const { display_message } = useSnackbar();

  const fetchProcessMetadata = React.useCallback(
    async (pid: number) => {
      try {
        const response = await axiosInstance.get(
          `/api/evidence/${id}/plugin/volatility3.plugins.linux.pslist.PsList/`,
        );
        const artefacts = response.data.artefacts;
        const foundProcess = artefacts.find(
          (process: { PID: number }) => process.PID === pid,
        );
        if (foundProcess) {
          setProcessMetadata(foundProcess);
        } else {
          console.log(`No process found with PID: ${pid}`);
          display_message("error", `No process found with PID: ${pid}`);
        }
      } catch (error) {
        console.error("Error fetching process details", error);
        display_message("error", `Error fetching process details: ${error}`);
      }
    },
    [id, setProcessMetadata, display_message],
  );

  useEffect(() => {
    const fetchTree = async () => {
      try {
        const response = await axiosInstance.get(
          `/api/evidence/${id}/plugin/volatility3.plugins.linux.pstree.PsTree/`, // TODO: Remove me in future volatility3 release..
        );
        const data: LinuxProcessInfo[] = response.data.artefacts;

        const transformedData = transformProcessData(data);
        setTreeItems(transformedData);

        const allIds = extractAllNodeIds(data);
        setExpanded(allIds);

        if (transformedData.length > 0) {
          setSelected(transformedData[0].id);
          fetchProcessMetadata(Number(transformedData[0].id));
        }
      } catch (error) {
        console.error("Error fetching pstree data", error);
      }
    };

    fetchTree();
  }, [id, fetchProcessMetadata]);

  // Event handler for item selection
  const handleSelect = (
    _event: React.SyntheticEvent,
    selected: string | null,
  ) => {
    if (selected) {
      console.log(`Selected PID: ${selected}`);
      setSelected(selected);
      fetchProcessMetadata(Number(selected));
    }
  };

  return (
    <Box sx={{ minHeight: 352, minWidth: 250 }}>
      <Card variant="outlined">
        <CardContent>
          <Typography
            gutterBottom
            sx={{
              color: "text.secondary",
              fontSize: 20,
              display: "flex",
              alignItems: "center",
            }}
          >
            <AccountTreeIcon sx={{ marginRight: 1 }} />
            Process tree
          </Typography>
          <Divider />
          <div style={{ maxHeight: "70vh", overflowY: "auto" }}>
            <RichTreeView
              expandedItems={expanded}
              selectedItems={selected}
              onSelectedItemsChange={handleSelect}
              slots={{
                expandIcon: MemoryIcon,
                collapseIcon: MemoryIcon,
                endIcon: MemoryIcon,
                item: CustomTreeItem,
              }}
              items={treeItems}
            />
          </div>
        </CardContent>
      </Card>
    </Box>
  );
};

export default PsTree;
