export interface Case {
    id: number;
    name: string;
    description: string;
    bucket_id: string;
    linked_users: Array<string>;
    last_update: string;
}

export interface User {
    id: number;
    username: string;
    email: string;
    first_name: string;
    last_name: string;
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
    [key: string]: any;
}

export interface Connection {
    __children: any[];
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
