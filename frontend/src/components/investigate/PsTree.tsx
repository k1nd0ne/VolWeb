import React, { useEffect, useState } from "react";
import Box from "@mui/material/Box";
import MemoryIcon from "@mui/icons-material/Memory";
import { styled } from "@mui/material/styles";
import { RichTreeView } from "@mui/x-tree-view/RichTreeView";
import { TreeItem, treeItemClasses } from "@mui/x-tree-view/TreeItem";
import { TreeViewBaseItem } from "@mui/x-tree-view/models";
import axiosInstance from "../../utils/axiosInstance";
import { useParams } from "react-router-dom";

interface ProcessNode {
  PID: number;
  PPID: number;
  ImageFileName: string;
  __children: ProcessNode[];
}

// Styled TreeItem component
const CustomTreeItem = styled(TreeItem)({
  [`& .${treeItemClasses.iconContainer}`]: {
    "& .close": {
      opacity: 0.3,
    },
  },
});

// Helper function to transform artefacts data to TreeViewBaseItem
const transformProcessData = (nodes: ProcessNode[]): TreeViewBaseItem[] => {
  return nodes.map((node) => ({
    id: node.PID.toString(),
    label: ` ${node.PID.toString()} - ${node.ImageFileName} `,
    children: node.__children ? transformProcessData(node.__children) : [],
  }));
};

// Helper function to extract all node (P)IDs for default expansion
const extractAllNodeIds = (nodes: ProcessNode[]): string[] => {
  let ids: string[] = [];
  nodes.forEach((node) => {
    ids.push(node.PID.toString());
    if (node.__children && node.__children.length > 0) {
      ids = ids.concat(extractAllNodeIds(node.__children));
    }
  });
  return ids;
};

const PsTree: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [treeItems, setTreeItems] = useState<TreeViewBaseItem[]>([]);
  const [expanded, setExpanded] = useState<string[]>([]);

  useEffect(() => {
    const fetchCaseDetail = async () => {
      try {
        const response = await axiosInstance.get(
          `/api/evidence/${id}/plugin/windows.pstree.PsTree/`,
        );
        const data: ProcessNode[] = response.data.artefacts;

        // Transform data for RichTreeView
        const transformedData = transformProcessData(data);
        setTreeItems(transformedData);

        // Extract all node IDs for expanded
        const allIds = extractAllNodeIds(data);
        setExpanded(allIds);
      } catch (error) {
        console.error("Error fetching case details", error);
      }
    };

    fetchCaseDetail();
  }, [id]);

  // Event handler for expanded items change
  const handleExpandedItemsChange = (
    _event: React.SyntheticEvent,
    _newExpanded: string[],
  ) => {
    // TODO: Display the info about the process
    console.log("TODO");
  };

  return (
    <Box sx={{ flexGrow: 1, padding: 2 }}>
      <Box sx={{ minHeight: 352, minWidth: 250 }}>
        <RichTreeView
          expandedItems={expanded}
          onExpandedItemsChange={handleExpandedItemsChange}
          slots={{
            expandIcon: MemoryIcon,
            collapseIcon: MemoryIcon,
            endIcon: MemoryIcon,
            item: CustomTreeItem,
          }}
          items={treeItems}
        />
      </Box>
    </Box>
  );
};

export default PsTree;
