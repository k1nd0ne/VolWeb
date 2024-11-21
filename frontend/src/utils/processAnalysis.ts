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
