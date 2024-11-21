import React from "react";

// Define the ProcessInfo interface
interface ProcessInfo {
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

interface ProcessDetailsProps {
  process: ProcessInfo;
}

const ProcessDetails: React.FC<ProcessDetailsProps> = ({ process }) => (
  <div style={{ marginLeft: "20px" }}>
    <h3>Process Details</h3>
    <p>
      <strong>PID:</strong> {process.PID}
    </p>
    <p>
      <strong>ImageFileName:</strong> {process.ImageFileName}
    </p>
    <p>
      <strong>PPID:</strong> {process.PPID}
    </p>
    <p>
      <strong>CreateTime:</strong> {process.CreateTime}
    </p>
    <p>
      <strong>ExitTime:</strong> {process.ExitTime}
    </p>
    {process.anomalies && process.anomalies.length > 0 && (
      <div>
        <strong>Anomalies:</strong>
        <ul>
          {process.anomalies.map((anomaly, index) => (
            <li key={index}>{anomaly}</li>
          ))}
        </ul>
      </div>
    )}
  </div>
);

export default ProcessDetails;
