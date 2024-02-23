function display_sids(evidence_id, process_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/sids/${process_id}/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                          <th>Process</th>
                          <th>Name</th>
                          <th>SID</th>
                          <th></th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data,
        aoColumns: [
          { data: "Process" },
          { data: "Name" },
          { data: "SID" },
          {
            mData: "id",
            mRender: function (_id, _type, row) {
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
        .prependTo($(artefact_datatable.table().container()));
      $("#artefacts_source_title").text("Security IDs");
      $("#artefacts_modal").modal("show");
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });
}

function display_privs(evidence_id, process_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/privileges/${process_id}/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                        <th>Process</th>
                        <th>Privilege</th>
                        <th>Description</th>
                        <th>Value</th>
                        <th>Attributes</th>
                        <th></th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data,
        aoColumns: [
          { data: "Process" },
          { data: "Privilege" },
          { data: "Description" },
          { data: "Value" },
          { data: "Attributes" },
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
      $("#artefacts_source_title").text("Privileges");
      $("#artefacts_modal").modal("show");
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
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
                        <th>Process</th>
                        <th>Block</th>
                        <th>Variable</th>
                        <th>Value</th>
                        <th></th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data,
        aoColumns: [
          { data: "Process" },
          { data: "Block" },
          { data: "Variable" },
          { data: "Value" },
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
      $("#artefacts_source_title").text("Environnement Variables ");
      $("#artefacts_modal").modal("show");
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });
}

function display_registry(evidence_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/registry/hivelist/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                        <th>Offset</th>
                        <th>FileFullPath</th>
                        <th>Action</th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data.artefacts,
        aoColumns: [
          { data: "Offset" },
          { data: "FileFullPath" },
          {
            mData: "id",
            mRender: function (id, type, row) {
              return generate_hive_download(row, data.evidence);
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
      $("#artefacts_source_title").text("Registry Hive List");
      $("#artefacts_modal").modal("show");
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });
}

function display_svcscan(evidence_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/svcscan/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                        <th>Offset</th>
                        <th>PID</th>
                        <th>Order</th>
                        <th>Name</th>
                        <th>Display</th>
                        <th>Binary</th>
                        <th>Start</th>
                        <th>State</th>
                        <th>Type</th>
                        <th></th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data.artefacts,
        aoColumns: [
          { data: "Offset" },
          { data: "PID" },
          { data: "Order" },
          { data: "Name" },
          { data: "Display" },
          { data: "Binary" },
          { data: "Start" },
          { data: "State" },
          { data: "Type" },
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
      $("#artefacts_modal").modal("show");
      $("#artefacts_source_title").text("Service Scan");
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });
}

function display_dlllist(evidence_id, process_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/dlllist/${process_id}/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                        <th>Process</th>
                        <th>Base</th>
                        <th>Name</th>
                        <th>Path</th>
                        <th>LoadTime</th>
                        <th>Size</th>
                        <th></th>
                      </tr>
                  </thead>
              </table>`,
      );
      artefact_datatable = $("#artefacts_datatable").DataTable({
        aaData: data,
        aoColumns: [
          { data: "Process" },
          { data: "Base" },
          { data: "Name" },
          { data: "Path" },
          { data: "LoadTime" },
          { data: "Size" },
          {
            mData: "id",
            mRender: function (_id, _type, row) {
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
      $("#artefacts_modal").modal("show");
      $("#artefacts_source_title").text("DllList");
    },
    error: function (_xhr, _status, error) {
      toastr.error("An error occurred : " + error);
    },
  });
}

function display_filescan(evidence_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/filescan/`,
    dataType: "json",
    success: function (data) {
      $("#artefacts_datatable").DataTable().destroy();
      $("#artefacts_body").html(
        `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
          >
                  <thead>
                      <tr>
                        <th>Offset</th>
                        <th>Name</th>
                        <th>Size</th>
                        <th>Action</th>
                        <th></th>
                      </tr>
                  </thead>
              </table>`,
      );

      artefacts_datatable = $("#artefacts_datatable").DataTable({
        aaData: data.artefacts,
        aoColumns: [
          { data: "Offset" },
          { data: "Name" },
          { data: "Size" },
          {
            mData: "id",
            mRender: function (id, type, row) {
              return generate_file_download_btn(row);
            },
          },
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
      artefacts_datatable.searchBuilder
        .container()
        .prependTo(artefacts_datatable.table().container());
      $("#artefacts_modal").modal("show");
      $(".btn-dump-file").on("click", function () {
        file_id = $(this).attr("id");
        dump_file(evidence_id, file_id);
      });
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });
}

function display_network(evidence_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/netstat/`,
    dataType: "json",
    success: function (data) {
      $("#netstat_datatable").DataTable().destroy();
      try {
        netstat_data = $("#netstat_datatable").DataTable({
          aaData: data.artefacts,
          aoColumns: [
            { data: "Proto" },
            { data: "LocalAddr" },
            { data: "LocalPort" },
            { data: "ForeignAddr" },
            { data: "ForeignPort" },
            { data: "State" },
            { data: "Offset" },
            { data: "Created" },
            { data: "Owner" },
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
        netstat_data.searchBuilder
          .container()
          .prependTo(netstat_data.table().container());
      } catch {
        toastr.warning("An error occured when loading data for 'netstat'.");
      }
      $("#netstat_datatable").show("fast");
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });

  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/netscan/`,
    dataType: "json",
    success: function (data) {
      $("#netscan_datatable").DataTable().destroy();
      try {
        netscan_data = $("#netscan_datatable").DataTable({
          aaData: data.artefacts,
          aoColumns: [
            { data: "Proto" },
            { data: "LocalAddr" },
            { data: "LocalPort" },
            { data: "ForeignAddr" },
            { data: "ForeignPort" },
            { data: "State" },
            { data: "Offset" },
            { data: "Created" },
            { data: "Owner" },
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
        netscan_data.searchBuilder
          .container()
          .prependTo(netscan_data.table().container());
      } catch {
        toastr.warning("An error occured when loading data for 'netscan'.");
      }

      $("#netscan_datatable").show();
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
      data.artefacts.forEach((item) => {
        seriesData.push({ x: item[0], y: item[1] });
      });
      var options = {
        theme: {
          mode: theme,
          palette: "palette1",
          monochrome: {
            enabled: true,
            color: "#6f42c1",
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
          height: 350,
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
              display_timeliner(evidence_id, data.artefacts[xaxis.min - 1][0]);
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
      toastr.error("An error occurred : " + error);
    },
  });
}

function display_sessions(evidence_id, process_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/sessions/${process_id}/`,
    dataType: "json",
    success: function (data) {
      $(".p_session_username").text(data[0]["User Name"]);
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });
}
function display_cmdline(evidence_id, process_id) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/cmdline/${process_id}/`,
    dataType: "json",
    success: function (data) {
      $(".p_cmdline").text(data[0].Args);
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });
}

function display_timeliner(evidence_id, timestamp) {
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/timeliner/${timestamp}/`,
    dataType: "json",
    success: function (data) {
      $("#timeline_datatable").DataTable().destroy();
      timeline_data = $("#timeline_datatable").DataTable({
        aaData: data,
        aoColumns: [
          { data: "Created Date" },
          { data: "Accessed Date" },
          { data: "Changed Date" },
          { data: "Description" },
          { data: "Modified Date" },
          { data: "Plugin" },
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
      timeline_data.searchBuilder
        .container()
        .prependTo(timeline_data.table().container());
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });
}

function display_credentials(evidence_id) {
  /*
    Get the hashdump, lsadump, cachedump data from the API and display them
    using the "build_credential_card" function from visualisation.js
  */
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/hashdump/`,
    dataType: "json",
    success: function (data) {
      if (data.artefacts.length > 0) {
        $.each(data.artefacts, function (_, value) {
          build_credential_card("Hashdump", value);
        });
      }
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });

  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/cachedump/`,
    dataType: "json",
    success: function (data) {
      if (data.artefacts.length > 0) {
        $.each(data, function (_, value) {
          build_credential_card("Cachedump", value);
        });
      }
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });

  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/lsadump/`,
    dataType: "json",
    success: function (data) {
      if (data.artefacts.length > 0) {
        $.each(data, function (_, value) {
          build_credential_card("Lsadump", value);
        });
      }
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });
  $("#credentials").modal("show");
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
      if (data.artefacts.length > 0) {
        $.each(data.artefacts, function (_, value) {
          build_malfind_process_card(value);
        });
      } else {
        document.getElementById("malfind_process_list").textContent =
          "Nothing was found by Malfind";
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

function display_ldrmodules(evidence_id) {
  /*
    Get the ldrmodules data from the API and display them using datatables
  */
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/ldrmodules/`,
    dataType: "json",
    beforeSend: function () {
      $("#ldrmodules_datatable").hide();
      $("#ldrmodule_details").show();
      $("#ldrmodules_process_loading").show();
    },
    success: function (data, status, xhr) {
      if (data.artefacts.length > 0) {
        $("#ldrmodules_datatable").DataTable().destroy();
        ldrmodules_data = $("#ldrmodules_datatable").DataTable({
          aaData: data.artefacts,
          aoColumns: [
            { data: "Base" },
            { data: "Process" },
            { data: "Pid" },
            { data: "MappedPath" },
            { data: "InInit" },
            { data: "InLoad" },
            { data: "InMem" },
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
        ldrmodules_data.searchBuilder
          .container()
          .prependTo(ldrmodules_data.table().container());
      }
    },
    complete: function (data) {
      $("#ldrmodules_process_loading").hide();
      $("#ldrmodules_datatable").show();
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred while fetching the modules : " + error);
    },
  });
}

function display_kernel_modules(evidence_id) {
  /*
    Get the kernel_modules data from the API and display them using datatables
  */
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/modules/`,
    dataType: "json",
    beforeSend: function () {
      $("#kernel_modules_datatable").hide();
      $("#kernel_modules_details").show();
      $("#kernel_modules_loading").show();
    },
    success: function (data, status, xhr) {
      if (data.artefacts.length > 0) {
        $("#kernel_modules_datatable").DataTable().destroy();
        kernel_modules_data = $("#kernel_modules_datatable").DataTable({
          aaData: data.artefacts,
          aoColumns: [
            { data: "Base" },
            { data: "Name" },
            { data: "Offset" },
            { data: "Path" },
            { data: "Size" },
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
        kernel_modules_data.searchBuilder
          .container()
          .prependTo(kernel_modules_data.table().container());
      }
    },
    complete: function (data) {
      $("#kernel_modules_loading").hide();
      $("#kernel_modules_datatable").show();
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred while fetching the modules : " + error);
    },
  });
}

function display_ssdt(evidence_id) {
  /*
    Get the ssdt data from the API and display them using datatables
  */
  $.ajax({
    type: "GET",
    url: `${baseURL}/${evidence_id}/ssdt/`,
    dataType: "json",
    beforeSend: function () {
      $("#ssdt_datatable").hide();
      $("#ssdt_details").show();
      $("#ssdt_loading").show();
    },
    success: function (data, status, xhr) {
      if (data.artefacts.length > 0) {
        $("#kernel_modules_datatable").DataTable().destroy();
        ssdt_data = $("#ssdt_datatable").DataTable({
          aaData: data.artefacts,
          aoColumns: [
            { data: "Address" },
            { data: "Index" },
            { data: "Module" },
            { data: "Symbol" },
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
        ssdt_data.searchBuilder
          .container()
          .prependTo(ssdt_data.table().container());
      }
    },
    complete: function (data) {
      $("#ssdt_loading").hide();
      $("#ssdt_datatable").show();
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred while fetching the ssdt : " + error);
    },
  });
}

function generate_label(row) {
  return "<small class='d-inline-flex px-1 fw-semibold text-primary-emphasis border border-primary-subtle'>OBSERVABLE</small>";
  // return "<small class='d-inline-flex fw-semibold text-danger-emphasis border border-danger-subtle'>INDICATOR</small>";
}

function generate_file_download_btn(data) {
  btn = document.createElement("a");
  btn.setAttribute("class", "btn btn-sm btn-outline-primary p-1 btn-dump-file");
  btn.textContent = "Dump";
  btn.setAttribute("id", data.Offset);
  return btn.outerHTML;
}

function generate_hive_download(data, evidence_data) {
  if (data["File output"]) {
    link = document.createElement("a");
    link.setAttribute(
      "href",
      "/media/" + evidence_data + "/" + data["File output"],
    );
    link.setAttribute("target", "_blank");
    link.setAttribute("class", "btn btn-sm btn-outline-success p-1");
    link.textContent = "Download";
    return link.outerHTML;
  } else {
    return "N/A";
  }
}
