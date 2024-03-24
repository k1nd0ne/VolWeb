function build_donut(total_evidences_windows, total_evidences_linux) {
  var options = {
    series: [total_evidences_windows, total_evidences_linux],
    labels: ["Windows", "Linux"],
    chart: {
      width: 380,
      type: "donut",
      background: "transparent",
      foreColor: "#fff",
    },
    plotOptions: {
      pie: {
        startAngle: -90,
        endAngle: 270,
      },
    },
    dataLabels: {
      enabled: false,
    },
    fill: {
      type: "gradient",
      gradientToColors: ["#790909", "#670979"], // custom colors for the donut
      colors: ["#790909", "#670979"], // set the donut color the same as the markers
    },
    legend: {
      formatter: function (val, opts) {
        return val + " - " + opts.w.globals.series[opts.seriesIndex];
      },
      labels: {
        colors: theme !== "dark" ? "#101418" : "#fff",
      },
      markers: {
        fillColors: ["#790909", "#670979"],
      },
    },
    title: {
      text: "Operating system repartition",
      style: {
        color: theme !== "dark" ? "#101418" : "#fff",
      },
    },
    responsive: [
      {
        breakpoint: 480,
        options: {
          chart: {
            width: 200,
          },
          legend: {
            position: "bottom",
          },
        },
      },
    ],
  };

  var os_chart = new ApexCharts(document.querySelector("#os_stats"), options);
  os_chart.render();
}

function build_graph(dates, counts) {
  theme = document
    .querySelector("[data-bs-theme]")
    .getAttribute("data-bs-theme");
  var options2 = {
    theme: {
      mode: theme,
      palette: "palette1",
      monochrome: {
        enabled: true,
        color: "#9a0000",
        shadeTo: "light",
        shadeIntensity: 0.65,
      },
    },
    series: [
      {
        name: "Analysis Started",
        data: counts,
      },
    ],
    chart: {
      background: theme === "dark" ? "#101418" : "#fff",
      type: "area",
      height: 350,
      zoom: {
        enabled: false,
      },
      background: "transparent",
      foreColor: theme !== "dark" ? "#101418" : "#fff",
    },
    dataLabels: {
      enabled: false,
    },
    stroke: {
      curve: "smooth",
    },
    title: {
      text: "Analysis",
      align: "left",
      style: {
        color: theme !== "dark" ? "#101418" : "#fff",
      },
    },
    subtitle: {
      text: "Started analysis in time",
      align: "left",
      style: {
        color: theme !== "dark" ? "#101418" : "#fff",
      },
    },
    labels: dates,
    yaxis: {
      opposite: true,
      labels: {
        style: {
          colors: theme !== "dark" ? "#101418" : "#fff",
        },
      },
    },
    xaxis: {
      labels: {
        style: {
          colors: theme !== "dark" ? "#101418" : "#fff",
        },
      },
    },
    legend: {
      horizontalAlign: "left",
      labels: {
        colors: theme !== "dark" ? "#101418" : "#fff",
      },
    },
  };

  var evidences_chart = new ApexCharts(
    document.querySelector("#evidences_chart"),
    options2,
  );
  evidences_chart.render();
}

$(document).ready(function () {
  get_statistics();
});

function countTasksByDate(taskArray) {
  let dateCounts = {};
  taskArray.forEach((task) => {
    let date = task.date_created.split("T")[0];

    if (!dateCounts[date]) {
      dateCounts[date] = 0;
    }
    dateCounts[date]++;
  });
  let dates = Object.keys(dateCounts);
  let counts = dates.map((date) => dateCounts[date]);

  return {
    dates: dates,
    counts: counts,
  };
}

function get_statistics() {
  $.ajax({
    url: "/statistics/",
    dataType: "JSON",
    success: function (data) {
      $("#evidence_count").text(data.total_evidences);
      $("#total_evidences_progress").text(data.total_evidences_progress);
      $("#case_count").text(data.total_cases);
      $("#users_count").text(data.total_users);
      $("#symbols_count").text(data.total_symbols);

      let tasks_stats = countTasksByDate(data.tasks);
      tasks_stats.dates;
      tasks_stats.counts;
      if (data.total_evidences_progress > 0) {
        $(".box-processing").addClass("not-completed");
      }
      $("#cases_placeholder").hide();

      $.each(data.last_5_cases, function (_i, caseItem) {
        //TODO : Create a link to the case when the case page is created.
        const li_item = document.createElement("li");
        li_item.setAttribute("class", "list-group-item");
        li_item.textContent = caseItem.case_name;
        $("#recent_cases").append(li_item);
      });

      $("#isf_placeholder").hide();
      $.each(data.last_5_isf, function (_i, isfItem) {
        const li_item = document.createElement("li");
        li_item.setAttribute("class", "list-group-item");
        li_item.textContent = isfItem.name;
        $("#recent_isf").append(li_item);
      });
      $("#loading-content").addClass("d-none");
      $("#main-content").removeClass("d-none");
      build_graph(tasks_stats.dates, tasks_stats.counts);
      build_donut(data.total_evidences_windows, data.total_evidences_linux);
    },
  });
}
