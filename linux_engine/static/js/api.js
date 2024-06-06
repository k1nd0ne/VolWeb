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

function display_envars(evidence_id, process_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/envars/${process_id}/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                        <th>PID</th>
                        <th>PPID</th>
                        <th>Process</th>
                        <th>Key</th>
                        <th>Value</th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data,
        aoColumns: [
          { data: "PID" },
          { data: "PPID" },
          { data: "COMM" },
          { data: "KEY" },
          { data: "VALUE" },
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
      $("#artefacts_source_title").text("Envars");
      $("#artefacts_modal").modal("show");
    },
    error: function (xhr, status, error) {
      if (xhr.status === 404) {
        toastr.warning("Envars are not available for this memory image.");
      } else {
        toastr.error(`An error occured : ${xhr.status}`);
      }
    },
  });
}

function display_capabilities(evidence_id, process_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/capabilities/${process_id}/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                        <th>Pid</th>
                        <th>PPid</th>
                        <th>Tid</th>
                        <th>EUID</th>
                        <th>Name</th>
                        <th>cap_ambient</th>
                        <th>cap_bounding</th>
                        <th>cap_effective</th>
                        <th>cap_inheritable</th>
                        <th>cap_permitted</th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data,
        aoColumns: [
          { data: "Pid" },
          { data: "PPid" },
          { data: "Tid" },
          { data: "EUID" },
          { data: "Name" },
          { data: "cap_ambient" },
          { data: "cap_bounding" },
          { data: "cap_effective" },
          { data: "cap_inheritable" },
          { data: "cap_permitted" },
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
      $("#artefacts_source_title").text("Capabilities");
      $("#artefacts_modal").modal("show");
    },
    error: function (xhr, status, error) {
      if (xhr.status === 404) {
        toastr.warning("Capabilities are not available for this memory image.");
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
        toastr.warning("Process Scan is not available for this memory image.");
      } else {
        toastr.error(`An error occured : ${xhr.status}`);
      }
    },
  });
}

function display_library_list(evidence_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/library_list/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                        <th>LoadAddress</th>
                        <th>Pid</th>
                        <th>Name</th>
                        <th>Path</th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data,
        aoColumns: [
          { data: "LoadAddress" },
          { data: "Pid" },
          { data: "Name" },
          { data: "Path" },
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
        toastr.warning("Library list is not available for this memory image.");
      } else {
        toastr.error(`An error occured : ${xhr.status}`);
      }
    },
  });
}

function display_kmsg(evidence_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/kmsg/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                        <th>Caller</th>
                        <th>Facility</th>
                        <th>Level</th>
                        <th>Message</th>
                        <th>timestamp</th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data,
        aoColumns: [
          { data: "caller" },
          { data: "facility" },
          { data: "level" },
          { data: "line" },
          { data: "timestamp" },
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
      $("#artefacts_source_title").text("Kernel Messages");
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

function display_tty_check(evidence_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/tty_check/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                        <th>Address</th>
                        <th>Module</th>
                        <th>Name</th>
                        <th>Symbol</th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data,
        aoColumns: [
          { data: "Address" },
          { data: "Module" },
          { data: "Name" },
          { data: "Symbol" },
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

function display_mount_info(evidence_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/mountinfo/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                        <th>FIELDS</th>
                        <th>FSTYPE</th>
                        <th>MAJOR:MINOR</th>
                        <th>MNT_NS_ID</th>
                        <th>MOUNT ID</th>
                        <th>MOUNT_OPTIONS</th>
                        <th>MOUNT_POINT</th>
                        <th>MOUNT_SRC</th>
                        <th>PARENT_ID</th>
                        <th>ROOT</th>
                        <th>SB_OPTIONS</th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data,
        aoColumns: [
          { data: "FIELDS" },
          { data: "FSTYPE" },
          { data: "MAJOR:MINOR" },
          { data: "MNT_NS_ID" },
          { data: "MOUNT ID" },
          { data: "MOUNT_OPTIONS" },
          { data: "MOUNT_POINT" },
          { data: "MOUNT_SRC" },
          { data: "PARENT_ID" },
          { data: "ROOT" },
          { data: "SB_OPTIONS" },
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
      $("#artefacts_source_title").text("Mount Information");
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
          background: theme === "dark" ? "#101418" : "#fff",
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
    ],
    aLengthMenu: [
      [25, 50, 75, -1],
      [25, 50, 75, "All"],
    ],
    iDisplayLength: 25,
    searchBuilder: true,
  });
}

function display_malfind(evidence_id) {
  /*
    Get the malfind data from the API and display them using the
    "build_malfind_process_card" function from visualisation.js
  */
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/malfind/`,
    dataType: "json",
    beforeSend: function () {
      $("#malfind_process_list").empty();
      $("#malfind_process_menu").show();
      $("#malfind_process_loading").show();
    },
    success: function (data, status, xhr) {
      if (data.artefacts && data.artefacts.length > 0) {
        $.each(data.artefacts, function (_, value) {
          build_malfind_process_card(value);
        });
      } else {
        $("#malfind_process_list").html(
          `<i class="text-info">Malfind did not return any results.</i>`,
        );
      }
    },
    complete: function (data) {
      $("#malfind_process_loading").hide();
      $("#malfind_process_list").show();
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred while fetching result : " + error);
    },
  });
}

function display_lsmod(evidence_id) {
  /*
    Get the kernel_modules data from the API and display them using datatables
  */
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/lsmod/`,
    dataType: "json",
    beforeSend: function () {
      $("#ir_artefacts_datatable").DataTable().destroy();
      $("#ir_artefacts_body").hide();
      $("#ir_details").show();
      $("#ir_artefacts_loading").show();
      $("#ir_artefacts_title").text("Kernel Modules");
    },
    success: function (data, status, xhr) {
      if (data.artefacts && data.artefacts.length > 0) {
        $("#ir_artefacts_body").html(
          `<table id="ir_artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
            >
                    <thead>
                        <tr>
                            <th>Offset</th>
                            <th>Name</th>
                            <th>Size</th>
                        </tr>
                    </thead>
                </table>`,
        );
        ir_artefacts_datatable = $("#ir_artefacts_datatable").DataTable({
          aaData: data.artefacts,
          aoColumns: [{ data: "Offset" }, { data: "Name" }, { data: "Size" }],
          aLengthMenu: [
            [25, 50, 75, -1],
            [25, 50, 75, "All"],
          ],
          iDisplayLength: 25,
          searchBuilder: true,
        });
        ir_artefacts_datatable.searchBuilder
          .container()
          .prependTo(ir_artefacts_datatable.table().container());
      } else {
        $("#ir_artefacts_body").html(
          "<i>Kernel Modules data are not available</i>",
        );
      }
    },
    complete: function (data) {
      $("#ir_artefacts_loading").hide();
      $("#ir_artefacts_body").show();
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred while fetching the modules : " + error);
    },
  });
}
