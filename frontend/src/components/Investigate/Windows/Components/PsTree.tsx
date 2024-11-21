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

// Helper function to transform artefacts data to TreeViewBaseItem
const transformProcessData = (nodes: ProcessInfo[]): TreeViewBaseItem[] => {
  return nodes.map((node) => ({
    id: node.PID.toString(),
    label: ` ${node.PID.toString()} - ${node.ImageFileName} `,
    children: node.__children ? transformProcessData(node.__children) : [],
    process: node, // Include the process info
  }));
};

// Helper function to extract all node (P)IDs for default expansion
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

const flattenProcesses = (processes: ProcessInfo[]): ProcessInfo[] => {
  let result: ProcessInfo[] = [];

  processes.forEach((process) => {
    result.push(process);
    if (process.__children && process.__children.length > 0) {
      result = result.concat(flattenProcesses(process.__children));
    }
  });

  return result;
};

const annotateProcessData = (processTree: ProcessInfo[]): void => {
  const processes = flattenProcesses(processTree);

  const processesByPID = new Map<number, ProcessInfo>();
  const processesByName = new Map<string, ProcessInfo[]>();

  processes.forEach((process) => {
    processesByPID.set(process.PID, process);

    const nameLower = (process.ImageFileName ?? "").toLowerCase();

    if (!processesByName.has(nameLower)) {
      processesByName.set(nameLower, []);
    }
    processesByName.get(nameLower)!.push(process);

    // Initialize anomalies array in process
    process.anomalies = [];
  });

  // Check number of instances
  ["smss.exe", "wininit.exe", "services.exe", "lsass.exe"].forEach(
    (processName) => {
      const instances = processesByName.get(processName) || [];
      if (instances.length !== 1) {
        // Mark all instances as anomalous
        instances.forEach((proc) =>
          proc.anomalies?.push("Unexpected number of instances"),
        );
      }
    },
  );

  // Check parent-child relationships
  processes.forEach((process) => {
    const nameLower = (process.ImageFileName ?? "").toLowerCase();

    if (nameLower === "smss.exe") {
      // Expected PPID is 4
      if (process.PPID !== 4) {
        process.anomalies?.push("Unexpected parent PID");
      }
    } else if (nameLower === "svchost.exe") {
      // Expected parent is 'services.exe' or another 'svchost.exe'
      const servicesProcesses = processesByName.get("services.exe") || [];
      if (servicesProcesses.length === 1) {
        const servicesPID = servicesProcesses[0].PID;
        if (process.PPID !== servicesPID) {
          const parentProcess = processesByPID.get(process.PPID);
          if (
            (parentProcess?.ImageFileName ?? "").toLowerCase() !== "svchost.exe"
          ) {
            process.anomalies?.push("Unexpected parent PID");
          }
        }
      } else {
        process.anomalies?.push(
          "Cannot verify parent PID (services.exe not found or multiple instances)",
        );
      }
    }
  });

  // Verify processes are running in expected sessions
  processes.forEach((process) => {
    const nameLower = (process.ImageFileName ?? "").toLowerCase();

    if (
      ["smss.exe", "wininit.exe", "services.exe", "lsass.exe"].includes(
        nameLower,
      )
    ) {
      if (process.SessionId !== null && process.SessionId !== 0) {
        process.anomalies?.push("Unexpected SessionId (should be 0)");
      }
    }
  });

  // Flag specific processes and those that have exited unexpectedly
  processes.forEach((process) => {
    const nameLower = (process.ImageFileName ?? "").toLowerCase();

    // List of suspicious process names
    const suspiciousProcesses = [
      "powershell.exe",
      "cmd.exe",
      "net.exe",
      "net1.exe",
      "psexec.exe",
      "psexesvc.exe",
      "schtasks.exe",
      "at.exe",
      "sc.exe",
      "wmic.exe",
      "wmiprvse.exe",
      "wsmprovhost.exe",
    ];

    if (suspiciousProcesses.includes(nameLower)) {
      process.anomalies?.push("Suspicious process");
    }

    if (
      [
        "smss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "csrss.exe",
      ].includes(nameLower)
    ) {
      if (process.ExitTime) {
        process.anomalies?.push("Exited unexpectedly");
      }
    }
  });
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

  useEffect(() => {
    const fetchTree = async () => {
      try {
        const response = await axiosInstance.get(
          `/api/evidence/${id}/plugin/volatility3.plugins.windows.pstree.PsTree/`,
        );
        const data: ProcessInfo[] = response.data.artefacts;

        // Annotate processes with anomalies
        annotateProcessData(data);

        // Transform data for RichTreeView
        const transformedData = transformProcessData(data);
        setTreeItems(transformedData);

        // Extract all node IDs for expanded
        const allIds = extractAllNodeIds(data);
        setExpanded(allIds);

        // Select the first item by default
        if (transformedData.length > 0) {
          setSelected(transformedData[0].id);
          fetchProcessMetadata(Number(transformedData[0].id));
        }
      } catch (error) {
        console.error("Error fetching pstree data", error);
      }
    };

    fetchTree();
  }, [id]);

  const fetchProcessMetadata = async (pid: number) => {
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
        // TODO: Error message
      }
    } catch (error) {
      console.error("Error fetching case details", error);
      // TODO: Error message
    }
  };

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
                item: CustomTreeItem, // Use the custom tree item here
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
