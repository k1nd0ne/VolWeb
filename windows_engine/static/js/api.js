function display_sids(evidence_id, process_id) {
  $("#sids").modal("show");
  $.ajax({
    type: "GET",
    url: "/api/windows/" + evidence_id + "/sids/" + process_id + "/",
    dataType: "json",
    success: function (data) {
      try {
        sids_data.destroy();
      } catch {
        //Nothing to do, the datatable will be created.
      }
      try {
        sids_data = $("#sids_datatable").DataTable({
          aaData: data,
          aoColumns: [
            { data: "Process" },
            { data: "Name" },
            { data: "SID" },
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
        sids_data.searchBuilder.container().prependTo(sids_data.table().container());
      } catch {
        toastr.warning("An error occured when loading data for 'sids'.");
      }
      $("#sids_datatable").show("fast");
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });
}

function display_privs(evidence_id, process_id) {
  $("#privs").modal("show");
  $.ajax({
    type: "GET",
    url: "/api/windows/" + evidence_id + "/privileges/" + process_id + "/",
    dataType: "json",
    success: function (data) {
      try {
        privs_data.destroy();
      } catch {
        //Nothing to do, the datatable will be created.
      }

      try {
        privs_data = $("#privs_datatable").DataTable({
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
        privs_data.searchBuilder.container().prependTo(privs_data.table().container());
      } catch {
        toastr.warning("An error occured when loading data for 'privileges'.");
      }

      $("#privs_datatable").show("fast");
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });
}

function display_envars(evidence_id, process_id) {
  $("#envars").modal("show");
  $.ajax({
    type: "GET",
    url: "/api/windows/" + evidence_id + "/envars/" + process_id + "/",
    dataType: "json",
    success: function (data) {
      try {
        envars_data.destroy();
      } catch {
        //Nothing to do, the datatable will be created.
      }
      try {
        envars_data = $("#envars_datatable").DataTable({
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
        envars_data.searchBuilder.container().prependTo(envars_data.table().container());
      } catch {
        toastr.warning("An error occured when loading data for 'envars'.");
      }
      $("#envars_datatable").show("fast");
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });
}


function display_registry(evidence_id) {
  $("#registry").modal("show");
  $.ajax({
    type: "GET",
    url: "/api/windows/" + evidence_id + "/registry/hivelist/",
    dataType: "json",
    success: function (data) {
      try {
        hivelist_data.destroy();
      } catch {
        // Nothing to do, the datatable will be created.
      }
        hivelist_data = $("#hivelist_datatable").DataTable({
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
        hivelist_data.searchBuilder.container().prependTo(hivelist_data.table().container());
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });
}


function display_svcscan(evidence_id) {
  $("#svcscan").modal("show");
  $.ajax({
    type: "GET",
    url: "/api/windows/" + evidence_id + "/svcscan/",
    dataType: "json",
    success: function (data) {
      try {
        svcscan_data.destroy();
      } catch {
        // Nothing to do, the datatable will be created.
      }
      try {
        svcscan_data = $("#svcscan_datatable").DataTable({
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
        svcscan_data.searchBuilder.container().prependTo(svcscan_data.table().container());
      } catch {
        toastr.warning("An error occured when loading data for 'svcscan'.");
      }
      $("#svcscan_datatable").show("fast");
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });
}




function display_dlllist(evidence_id, process_id) {
  $("#dlllist").modal("show");
  $.ajax({
    type: "GET",
    url: "/api/windows/" + evidence_id + "/dlllist/" + process_id + "/",
    dataType: "json",
    success: function (data) {
      try {
        dlllist_data.destroy();
      } catch {
        //Nothing to do, the datatable will be created.
      }
      try {
        dlllist_data = $("#dlllist_datatable").DataTable({
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
        dlllist_data.searchBuilder.container().prependTo(dlllist_data.table().container());
      } catch {
        toastr.warning("An error occured when loading data for 'dlllist'.");
      }
      $("#dlllist_datatable").show("fast");
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });
}

function display_filescan(evidence_id) {
  $("#filescan").modal("show");
  $.ajax({
    type: "GET",
    url: "/api/windows/" + evidence_id + "/filescan/",
    dataType: "json",
    success: function (data) {
      try {
        filescan_data.destroy();
      } catch {
        //Nothing to do, the datatable will be created.
      }
      try {
        filescan_data = $("#filescan_datatable").DataTable({
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
        filescan_data.searchBuilder.container().prependTo(filescan_data.table().container());
      } catch {
        toastr.warning("An error occured when loading data for 'filescan'.");
      }
      $("#filescan_datatable").show("fast");
      $('.btn-dump-file').off('click');
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
  $("#network").modal("show");
  $.ajax({
    type: "GET",
    url: "/api/windows/" + evidence_id + "/netstat/",
    dataType: "json",
    success: function (data) {
      try {
        netstat_data.destroy();
      } catch {
        //Nothing to do, the datatable will be created.
      }

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
        netstat_data.searchBuilder.container().prependTo(netstat_data.table().container());
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
    url: "/api/windows/" + evidence_id + "/netscan/",
    dataType: "json",
    success: function (data) {
      try {
        netscan_data.destroy();
      } catch {
        //Nothing to do, the datatable will be created.
      }
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
        netscan_data.searchBuilder.container().prependTo(netscan_data.table().container());
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
    url: "/api/windows/" + evidence_id + "/netgraph/",
    dataType: "json",
    success: function (data) {
      if(data.artefacts !== null){
        generate_network_visualisation(data);
      }
    }
  });
}

function display_timeline(evidence_id) {
  $.ajax({
    type: "GET",
    url: "/api/windows/" + evidence_id + "/timeline/",
    dataType: "json",
    success: function (data) {

      theme = document.querySelector('[data-bs-theme]').getAttribute('data-bs-theme');
      let seriesData = [];
      data.artefacts.forEach(item => {
        seriesData.push({ x: item[0], y: item[1] });
      });
      var options = {
        theme: {
          mode: theme,
          palette: 'palette1',
          monochrome: {
            enabled: true,
            color: '#6f42c1',
            shadeTo: 'light',
            shadeIntensity: 0.65
          },
        },
        series: [{
          data: seriesData
        }],
        chart: {
          background: (theme === "dark" ? "#212529" : "#fff"),
          type: 'area',
          stacked: false,
          height: 350,
          zoom: {
            type: 'x',
            enabled: true,
            autoScaleYaxis: true
          },
          events: {
            markerClick: function (event, chartContext, { seriesIndex, dataPointIndex, config }) {
              var timestamp = chartContext.w.config.series[seriesIndex].data[dataPointIndex].x;
              display_timeliner(evidence_id, timestamp);
            },
            zoomed: function (chartContext, { xaxis, yaxis }) {
              display_timeliner(evidence_id, data.artefacts[xaxis.min - 1][0]);
            }
          }
        },
        dataLabels: {
          enabled: true
        },
        markers: {
          size: 0,
        },
        title: {
          text: 'Timeline of events',
          align: 'left'
        },
        fill: {
          type: 'gradient',
          gradient: {
            shadeIntensity: 1,
            inverseColors: false,
            opacityFrom: 0.5,
            opacityTo: 0,
            stops: [0, 70, 80, 100]
          },
        },
        yaxis: {
          labels: {
            formatter: function (val) {
              return (val).toFixed(0);
            },
          },
          title: {
            text: 'Event Count'
          },
        },
        xaxis: {

        },
        tooltip: {
          shared: false,
          y: {
            formatter: function (val) {
              return (val).toFixed(0)
            }
          }
        }
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
    url: "/api/windows/" + evidence_id + "/sessions/" + process_id + "/",
    dataType: "json",
    success: function (data) {
      $(".p_session_username").text(data[0]['User Name']);
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });
}
function display_cmdline(evidence_id, process_id) {
  $.ajax({
    type: "GET",
    url: "/api/windows/" + evidence_id + "/cmdline/" + process_id + "/",
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
    url: "/api/windows/" + evidence_id + "/timeliner/" + timestamp + "/",
    dataType: "json",
    success: function (data) {
      try {
        timeline_data.destroy();
      } catch {
        //Nothing to do, the datatable will be created.
      }
      try {
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
        timeline_data.searchBuilder.container().prependTo(timeline_data.table().container());

      } catch {
        toastr.error("The timline data could not be displayed.");
      }
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
    url: "/api/windows/" + evidence_id + "/hashdump/",
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
    url: "/api/windows/" + evidence_id + "/cachedump/",
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
    url: "/api/windows/" + evidence_id + "/lsadump/",
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
    url: "/api/windows/" + evidence_id + "/malfind/",
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
      }
      else {
        document.getElementById("malfind_process_list").textContent = "Nothing was found by Malfind";
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
    url: "/api/windows/" + evidence_id + "/ldrmodules/",
    dataType: "json",
    beforeSend: function () {
      $("#ldrmodules_datatable").hide();
      $('#ldrmodule_details').show();
      $('#ldrmodules_process_loading').show();
    },
    success: function (data, status, xhr) {
      if (data.artefacts.length > 0) {
        try {
          ldrmodules_data.destroy();
        } catch {
          //Nothing to do, the datatable will be created.
        }
        try {
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
          ldrmodules_data.searchBuilder.container().prependTo(ldrmodules_data.table().container());

        } catch {
          toastr.error("The ldrmodules data could not be displayed.");
        }
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
    url: "/api/windows/" + evidence_id + "/modules/",
    dataType: "json",
    beforeSend: function () {
      $("#kernel_modules_datatable").hide();
      $('#kernel_modules_details').show();
      $('#kernel_modules_loading').show();
    },
    success: function (data, status, xhr) {
      if (data.artefacts.length > 0) {
        try {
          kernel_modules_data.destroy();
        } catch {
          //Nothing to do, the datatable will be created.
        }

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
        kernel_modules_data.searchBuilder.container().prependTo(kernel_modules_data.table().container());
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
    url: "/api/windows/" + evidence_id + "/ssdt/",
    dataType: "json",
    beforeSend: function () {
      $("#ssdt_datatable").hide();
      $('#ssdt_details').show();
      $('#ssdt_loading').show();
    },
    success: function (data, status, xhr) {
      if (data.artefacts.length > 0) {
        try {
          ssdt_data.destroy();
        } catch {
          //Nothing to do, the datatable will be created.
        }

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
        ssdt_data.searchBuilder.container().prependTo(ssdt_data.table().container());
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

function generate_label(row){
  return "<small class='d-inline-flex px-1 fw-semibold text-primary-emphasis border border-primary-subtle'>OBSERVABLE</small>"

  return "<small class='d-inline-flex fw-semibold text-danger-emphasis border border-danger-subtle'>INDICATOR</small>"

}

function generate_file_download_btn(data) {
  btn = document.createElement('a');
  btn.setAttribute('class', 'btn btn-sm btn-outline-primary p-1 btn-dump-file')
  btn.textContent = "Dump";
  btn.setAttribute('id', data.Offset);
  return btn.outerHTML;
}

function generate_hive_download(data, evidence_data) {
  if (data["File output"]) {
    console.log(data["File output"])
    link = document.createElement('a');
    link.setAttribute('href', '/media/' + evidence_data + '/' + data["File output"]);
    link.setAttribute('target','_blank');
    link.setAttribute('class','btn btn-sm btn-outline-success p-1')
    link.textContent = "Download";
    return link.outerHTML;
  }
  else{
    return "N/A";
  }
}