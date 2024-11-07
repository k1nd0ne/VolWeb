interface Task {
  date_created: string;
}

interface TaskStats {
  dates: string[];
  counts: number[];
}

export const countTasksByDate = (taskArray: Task[]): TaskStats => {
  const dateCounts: { [key: string]: number } = {};
  taskArray.forEach((task) => {
    const date = task.date_created.split("T")[0];
    dateCounts[date] = (dateCounts[date] || 0) + 1;
  });
  const dates = Object.keys(dateCounts).sort();
  const counts = dates.map((date) => dateCounts[date]);

  return { dates, counts };
};
