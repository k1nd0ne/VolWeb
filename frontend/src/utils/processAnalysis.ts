import { ProcessInfo } from "../types";

export const flattenProcesses = (processes: ProcessInfo[]): ProcessInfo[] => {
  let result: ProcessInfo[] = [];

  processes.forEach((process) => {
    result.push(process);
    if (process.__children && process.__children.length > 0) {
      result = result.concat(flattenProcesses(process.__children));
    }
  });

  return result;
};

export const annotateProcessData = (processTree: ProcessInfo[]): void => {
  const processes = flattenProcesses(processTree);

  const processesByPID = new Map<number, ProcessInfo>();
  const processesByName = new Map<string, ProcessInfo[]>();

  // Prepare instance counts
  const instanceExpectedSingles = [
    "smss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
  ];
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

  processes.forEach((process) => {
    processesByPID.set(process.PID, process);

    const nameLower = (process.ImageFileName ?? "").toLowerCase();

    if (!processesByName.has(nameLower)) {
      processesByName.set(nameLower, []);
    }
    processesByName.get(nameLower)!.push(process);

    // Initialize anomalies array in process
    process.anomalies = [];

    if (process.Wow64) {
      process.anomalies.push("Wow64 is enabled for this process.");
    }

    // Check number of instances
    if (instanceExpectedSingles.includes(nameLower)) {
      const instances = processesByName.get(nameLower) || [];
      if (instances.length !== 1) {
        process.anomalies.push("Unexpected number of instances");
      }
    }

    // Check parent-child relationships
    if (nameLower === "smss.exe" && process.PPID !== 4) {
      process.anomalies.push("Unexpected parent PID");
    } else if (nameLower === "svchost.exe") {
      const servicesProcesses = processesByName.get("services.exe") || [];
      if (
        servicesProcesses.length !== 1 ||
        (servicesProcesses.length === 1 &&
          process.PPID !== servicesProcesses[0].PID &&
          (
            processesByPID.get(process.PPID)?.ImageFileName ?? ""
          ).toLowerCase() !== "svchost.exe")
      ) {
        process.anomalies.push(
          servicesProcesses.length !== 1
            ? "Cannot verify parent PID (services.exe not found or multiple instances)"
            : "Unexpected parent PID",
        );
      }
    }

    // Verify processes are running in expected sessions
    if (
      instanceExpectedSingles.includes(nameLower) &&
      process.SessionId !== 0 &&
      process.SessionId
    ) {
      process.anomalies.push("Unexpected SessionId (should be 0)");
    }

    // Flag specific processes and those that have exited unexpectedly
    if (suspiciousProcesses.includes(nameLower)) {
      process.anomalies.push("The process is usually suspicious");
    }

    if (
      [
        "smss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "csrss.exe",
      ].includes(nameLower) &&
      process.ExitTime
    ) {
      process.anomalies.push("Exited unexpectedly");
    }
  });
};
