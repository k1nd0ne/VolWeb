export interface User {
  id: number;
  username: string;
}

export interface Case {
  id: number;
  name: string;
  description: string;
  bucket_id: string;
  linked_users: Array<User>;
  last_update: string;
}

export interface Evidence {
  id: number;
  name: string;
  os: string;
  status: number;
}

export interface CloudStorage {
  endpoint: string;
  access_key: string;
  secret_key: string;
  region: string;
}

export interface ProcessInfo {
  PID: number;
  PPID: number;
  ImageFileName: string | null;
  OffsetV: number | null;
  Threads: number | null;
  Handles: number | null;
  SessionId: number | null;
  Wow64: boolean | null;
  CreateTime: string | null;
  ExitTime: string | null;
  __children: ProcessInfo[];
  anomalies: string[] | undefined;
}

export interface NetworkInfo {
  __children: string[];
  Offset: number;
  Proto: string;
  LocalAddr: string;
  LocalPort: number;
  ForeignAddr: string;
  ForeignPort: number;
  State: string;
  PID: number;
  Owner: string;
  Created: string;
  id: number;
}

interface KnownEnrichedData {
  pslist: ProcessInfo;
  "volatility3.plugins.windows.cmdline.CmdLine"?: { Args: string }[];
  "volatility3.plugins.windows.sessions.Sessions"?: {
    "Session ID": number;
    Process: string;
    "User Name": string;
    "Create Time": string;
  }[];
  "volatility3.plugins.windows.netscan.NetScan"?: NetworkInfo[];
  "volatility3.plugins.windows.netstat.NetStat"?: NetworkInfo[];
}

export interface EnrichedProcessData extends KnownEnrichedData {
  [key: string]: ProcessInfo | NetworkInfo | unknown;
}

export interface ProcessInfo {
  PID: number; // Process ID
  PPID: number; // Parent Process ID
  ImageFileName: string | null; // Executable file name
  OffsetV: number | null; // Memory offset as a virtual address
  Threads: number | null; // Number of threads
  Handles: number | null; // Number of handles
  SessionId: number | null; // Session ID, null if not applicable
  Wow64: boolean | null; // 32-bit process on 64-bit Windows
  CreateTime: string | null; // ISO string representing creation time
  ExitTime: string | null; // ISO string representing exit time, null if not applicable
  __children: ProcessInfo[];
  anomalies: string[] | undefined; // Add this line to include anomalies
}

export interface Plugin {
  name: string;
  icon: string;
  description: string;
  display: string;
  category: string;
  result: boolean;
}

export interface Artefact {
  [key: string]: object;
}

export interface Connection {
  __children: Connection[];
  Offset: number;
  Proto: string;
  LocalAddr: string;
  LocalPort: number;
  ForeignAddr: string;
  ForeignPort: number;
  State: string;
  PID: number;
  Owner: string;
  Created: string;
  id: number;
}

// Define the structure of a graph node
interface GraphNode {
  id: string;
  label: string;
  x: number;
  y: number;
  size: number;
}

// Define the structure of a graph edge
interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface Symbol {
  id: number;
  name: string;
  os: string;
  description: number;
}
