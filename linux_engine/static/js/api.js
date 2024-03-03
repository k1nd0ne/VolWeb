function display_psaux(evidence_id, process_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/psaux/${process_id}/`,
    dataType: "json",
    success: function (data) {
      $(".p_cmdline").text(data[0].ARGS);
    },
    error: function (xhr, status, error) {
      $(".p_cmdline").text("Unavailable");
    },
  });
}

function display_lsof(evidence_id, process_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/lsof/${process_id}/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                        <th>FD</th>
                        <th>PID</th>
                        <th>Process</th>
                        <th>Path</th>
                        <th></th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data,
        aoColumns: [
          { data: "FD" },
          { data: "PID" },
          { data: "Process" },
          { data: "Path" },
          {
            mData: "id",
            mRender: function (id, type, row) {
              return generate_label(row);
            },
          },
        ],
        aLengthMenu: [
          [25, 50, 75, -1],
          [25, 50, 75, "All"],
        ],
        iDisplayLength: 25,
        searchBuilder: true,
      });
      artefact_datatable.searchBuilder
        .container()
        .prependTo(artefact_datatable.table().container());
      $("#artefacts_source_title").text("Open files");
      $("#artefacts_modal").modal("show");
    },
    error: function (xhr, status, error) {
      if (xhr.status === 404) {
        toastr.warning("Open files are not available for this memory image.");
      } else {
        toastr.error(`An error occured : ${xhr.status}`);
      }
    },
  });
}

function display_elfs(evidence_id, process_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/elfs/${process_id}/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                        <th>PID</th>
                        <th>Process</th>
                        <th>Start</th>
                        <th>End</th>
                        <th>File Path</th>
                        <th></th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data,
        aoColumns: [
          { data: "PID" },
          { data: "Process" },
          { data: "Start" },
          { data: "End" },
          { data: "File Path" },
          {
            mData: "id",
            mRender: function (id, type, row) {
              return generate_label(row);
            },
          },
        ],
        aLengthMenu: [
          [25, 50, 75, -1],
          [25, 50, 75, "All"],
        ],
        iDisplayLength: 25,
        searchBuilder: true,
      });
      artefact_datatable.searchBuilder
        .container()
        .prependTo(artefact_datatable.table().container());
      $("#artefacts_source_title").text("Executables and Linkable Formats");
      $("#artefacts_modal").modal("show");
    },
    error: function (xhr, status, error) {
      if (xhr.status === 404) {
        toastr.warning("Open files are not available for this memory image.");
      } else {
        toastr.error(`An error occured : ${xhr.status}`);
      }
    },
  });
}

function display_psscan(evidence_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/psscan/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                        <th>COMM</th>
                        <th>EXIT_STATE</th>
                        <th>OFFSET (P)</th>
                        <th>PID</th>
                        <th>PPID</th>
                        <th>TID</th>
                        <th></th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data,
        aoColumns: [
          { data: "COMM" },
          { data: "EXIT_STATE" },
          { data: "OFFSET (P)" },
          { data: "PID" },
          { data: "PPID" },
          { data: "TID" },
          {
            mData: "id",
            mRender: function (id, type, row) {
              return generate_label(row);
            },
          },
        ],
        aLengthMenu: [
          [25, 50, 75, -1],
          [25, 50, 75, "All"],
        ],
        iDisplayLength: 25,
        searchBuilder: true,
      });
      artefact_datatable.searchBuilder
        .container()
        .prependTo(artefact_datatable.table().container());
      $("#artefacts_source_title").text("Process Scan");
      $("#artefacts_modal").modal("show");
    },
    error: function (xhr, status, error) {
      if (xhr.status === 404) {
        toastr.warning("Open files are not available for this memory image.");
      } else {
        toastr.error(`An error occured : ${xhr.status}`);
      }
    },
  });
}

function display_bash(evidence_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/bash/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                        <th>PID</th>
                        <th>Process</th>
                        <th>CommandTime</th>
                        <th>Command</th>
                        <th></th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data,
        aoColumns: [
          { data: "PID" },
          { data: "Process" },
          { data: "CommandTime" },
          { data: "Command" },
          {
            mData: "id",
            mRender: function (id, type, row) {
              return generate_label(row);
            },
          },
        ],
        aLengthMenu: [
          [25, 50, 75, -1],
          [25, 50, 75, "All"],
        ],
        iDisplayLength: 25,
        searchBuilder: true,
      });
      artefact_datatable.searchBuilder
        .container()
        .prependTo(artefact_datatable.table().container());
      $("#artefacts_source_title").text("Bash");
      $("#artefacts_modal").modal("show");
    },
    error: function (xhr, status, error) {
      if (xhr.status === 404) {
        toastr.warning("Open files are not available for this memory image.");
      } else {
        toastr.error(`An error occured : ${xhr.status}`);
      }
    },
  });
}

function generate_label(row) {
  return "<small class='d-inline-flex px-1 fw-semibold text-primary-emphasis border border-primary-subtle'>OBSERVABLE</small>";
  // return "<small class='d-inline-flex fw-semibold text-danger-emphasis border border-danger-subtle'>INDICATOR</small>";
}

function display_network(evidence_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/sockstat/`,
    dataType: "json",
    success: function (data) {
      $("#sockstat_datatable").DataTable().destroy();
      sockstat_data = $("#sockstat_datatable").DataTable({
        aaData: data,
        aoColumns: [
          { data: "Sock Offset" },
          { data: "Pid" },
          { data: "Family" },
          { data: "Proto" },
          { data: "Type" },
          { data: "Source Addr" },
          { data: "Source Port" },
          { data: "Destination Addr" },
          { data: "Destination Port" },
          { data: "State" },
          { data: "FD" },
          { data: "Filter" },
          { data: "NetNS" },
          {
            mData: "id",
            mRender: function (id, type, row) {
              return generate_label(row);
            },
          },
        ],
        aLengthMenu: [
          [5, 10, 50, -1],
          [5, 10, 50, "All"],
        ],
        iDisplayLength: 5,
        searchBuilder: true,
      });
      sockstat_data.searchBuilder
        .container()
        .prependTo(sockstat_data.table().container());

      $("#sockstat_datatable").show();
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });

  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/netgraph/`,
    dataType: "json",
    success: function (data) {
      if (data.artefacts !== null) {
        generate_network_visualisation(data);
      }
    },
  });
  $("#network").modal("show");
}

function display_timeline(evidence_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/timeline/`,
    dataType: "json",
    success: function (data) {
      theme = document
        .querySelector("[data-bs-theme]")
        .getAttribute("data-bs-theme");
      let seriesData = [];
      if (data.artefacts) {
        data.artefacts.forEach((item) => {
          seriesData.push({ x: item[0], y: item[1] });
        });
      }
      var options = {
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
            data: seriesData,
          },
        ],
        chart: {
          background: theme === "dark" ? "#212529" : "#fff",
          type: "area",
          stacked: false,
          height: 500,
          zoom: {
            type: "x",
            enabled: true,
            autoScaleYaxis: true,
          },
          events: {
            markerClick: function (
              event,
              chartContext,
              { seriesIndex, dataPointIndex, config },
            ) {
              var timestamp =
                chartContext.w.config.series[seriesIndex].data[dataPointIndex]
                  .x;
              display_timeliner(evidence_id, timestamp);
            },
            zoomed: function (chartContext, { xaxis, yaxis }) {
              console.log(data.artefacts[xaxis.min - 1][0]);
              console.log(data.artefacts[xaxis.max - 1][0]);
              display_timeliner(
                evidence_id,
                data.artefacts[xaxis.min - 1][0],
                data.artefacts[xaxis.max - 1][0],
              );
            },
          },
        },
        dataLabels: {
          enabled: false,
        },
        markers: {
          size: 0,
        },
        title: {
          text: "Timeline of events",
          align: "left",
        },
        fill: {
          type: "gradient",
          gradient: {
            shadeIntensity: 1,
            inverseColors: false,
            opacityFrom: 0.5,
            opacityTo: 0,
            stops: [0, 70, 80, 100],
          },
        },
        yaxis: {
          tickAmount: 4,
          labels: {
            formatter: function (val) {
              return val.toFixed(0);
            },
          },
          title: {
            text: "Event Count",
          },
        },
        xaxis: {},
        tooltip: {
          shared: false,
          y: {
            formatter: function (val) {
              return val.toFixed(0);
            },
          },
        },
      };

      var chart = new ApexCharts(document.querySelector("#timeline"), options);
      chart.render();
    },
    error: function (xhr, status, error) {
      toastr.error("The timeline failed to load : " + status);
    },
  });
}

function display_timeliner(evidence_id, timestamp_min, timestamp_max) {
  $("#timeline_datatable").DataTable().destroy();
  $("#timeline_datatable").DataTable({
    processing: true,
    serverSide: true,
    ajax: {
      url: `${baseURL}/${evidence_id}/timeliner/?timestamp_min=${timestamp_min}&timestamp_max=${timestamp_max}`,
      type: "GET",
      data: function (d) {
        d.timestamp_min = timestamp_min;
        d.timestamp_max = timestamp_max;
      },
    },
    aoColumns: [
      { data: "Plugin" },
      { data: "Description", width: "40%" },
      { data: "Created Date" },
      { data: "Accessed Date" },
      { data: "Changed Date" },
      { data: "Modified Date" },
      {
        data: "id",
        render: function (data, type, row) {
          return generate_label(row);
        },
      },
    ],
    aLengthMenu: [
      [25, 50, 75, -1],
      [25, 50, 75, "All"],
    ],
    iDisplayLength: 25,
    searchBuilder: true,
  });
}
