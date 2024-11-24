import React, { useEffect, useState } from "react";
import Box from "@mui/material/Box";
import { Card, CardContent, Divider } from "@mui/material";
import MemoryIcon from "@mui/icons-material/Memory";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import { styled } from "@mui/material/styles";
import { TreeItem2, TreeItem2Props } from "@mui/x-tree-view/TreeItem2";
import { treeItemClasses } from "@mui/x-tree-view/TreeItem";
import { RichTreeView } from "@mui/x-tree-view/RichTreeView";
import { TreeViewBaseItem } from "@mui/x-tree-view/models";
import { useTreeItem2Utils } from "@mui/x-tree-view/hooks";
import axiosInstance from "../../../../utils/axiosInstance";
import { useParams } from "react-router-dom";
import Typography from "@mui/material/Typography";
import { ProcessInfo } from "../../../../types";
import { annotateProcessData } from "../../../../utils/processAnalysis";
import { useSnackbar } from "../../../SnackbarProvider";

interface CustomLabelProps {
  children: string;
  className?: string;
  process: ProcessInfo;
}

const CustomTreeItem = styled(
  React.forwardRef(function CustomTreeItem(
    props: TreeItem2Props,
    ref: React.Ref<HTMLLIElement>,
  ) {
    const { publicAPI } = useTreeItem2Utils({
      itemId: props.itemId,
      children: props.children,
    });

    const item = publicAPI.getItem(props.itemId);

    return (
      <TreeItem2
        {...props}
        ref={ref}
        slots={{
          label: CustomLabel,
        }}
        slotProps={{
          label: { process: item?.process } as CustomLabelProps,
        }}
      />
    );
  }),
)(() => ({
  // Apply your custom styles here
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
}));

const transformProcessData = (nodes: ProcessInfo[]): TreeViewBaseItem[] => {
  return nodes.map((node) => ({
    id: node.PID.toString(),
    label: ` ${node.PID.toString()} - ${node.ImageFileName} `,
    children: node.__children ? transformProcessData(node.__children) : [],
    process: node,
  }));
};

const extractAllNodeIds = (nodes: ProcessInfo[]): string[] => {
  let ids: string[] = [];
  nodes.forEach((node) => {
    ids.push(node.PID.toString());
    if (node.__children && node.__children.length > 0) {
      ids = ids.concat(extractAllNodeIds(node.__children));
    }
  });
  return ids;
};

function CustomLabel({ children, className, process }: CustomLabelProps) {
  let style = {};
  if (process.anomalies && process.anomalies.length > 0) {
    style = { color: "orange" };
  }
  return (
    <div className={className}>
      <Typography sx={{ fontSize: "0.800rem" }} style={style}>
        {children}
      </Typography>
    </div>
  );
}

interface PsTreeProps {
  setProcessMetadata: (processInfo: ProcessInfo) => void;
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
          `/api/evidence/${id}/plugin/volatility3.plugins.windows.pslist.PsList/`,
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
          `/api/evidence/${id}/plugin/volatility3.plugins.windows.pstree.PsTree/`,
        );
        const data: ProcessInfo[] = response.data.artefacts;

        annotateProcessData(data);

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
        display_message("error", `Error fetching pstree data ${error}`);
      }
    };

    fetchTree();
  }, [id, fetchProcessMetadata, display_message]);

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
