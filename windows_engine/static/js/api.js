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
                return generate_tag("sids", row);
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
                return generate_tag("privileges", row);
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
                return generate_tag("envars", row);
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
          aaData: data,
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
                return generate_tag("svcscan", row);
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
                return generate_tag("dlllist", row);
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
          aaData: data,
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
                return generate_tag("filescan", row);
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
          aaData: data,
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
                return generate_tag("netstat", row);
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
          aaData: data,
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
                return generate_tag("netscan", row);
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

      $("#netscan_datatable").show("fast");
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
      try {
        theme = document.querySelector('[data-bs-theme]').getAttribute('data-bs-theme');
        $("#net_graph").empty();
        var data = JSON.parse(data[0].graph);
        // create a data tree
        // create a chart and set the data
        var netchart = anychart.graph(data);
        netchart
          .background()
          .fill((theme == "dark" ? "#212529" : "#FFF"));
        netchart
          .nodes()
          .normal()
          .fill(theme == "light" ? "#212529" : "#FFF");
        netchart
          .nodes()
          .hovered()
          .fill(theme == "light" ? "#212529" : "#FFF");
        netchart.nodes().labels().enabled(true);
        netchart.nodes().labels().format("{%id} ({%Owner(s)})");
        netchart.nodes().labels().fontSize(12);
        netchart.nodes().labels().fontWeight(600);
        netchart
          .nodes()
          .labels()
          .fontColor(theme == "light" ? "#212529" : "#FFF");
        netchart
          .edges()
          .normal()
          .stroke(theme == "light" ? "#212529" : "#FFF", 1);
        netchart
          .edges()
          .hovered()
          .stroke(theme == "light" ? "#212529" : "#FFF", 2);
        netchart.edges().selected().stroke("#dc3545", 3);

        // configure tooltips of nodes
        netchart.nodes().tooltip().useHtml(true);
        netchart
          .nodes()
          .tooltip()
          .format(
            "<span style='font-weight:bold'>Involved PIDs : {%Involved_PIDs}</span><br><spanstyle='font-weight:bold'>Owner : {%Owner(s)}</span><br><span style='font-weight:bold'>Local Ports: {%Local_Ports}</span>"
          );
        var animationSettings = netchart.animation();
        animationSettings.duration(1000);
        animationSettings.enabled(true);
        netchart.container("net_graph");

        netchart.interactivity().scrollOnMouseWheel(false);
        netchart.interactivity().zoomOnMouseWheel(false);
        // add a zoom control panel
        var zoomController = anychart.ui.zoom();
        zoomController.target(netchart);
        zoomController.render();

        // initiate drawing the chart
        netchart.draw();
      } catch {
        toastr.error("The network graph could not be displayed.");
      }
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });
}

function display_timeline(evidence_id) {
  $.ajax({
    type: "GET",
    url: "/api/windows/" + evidence_id + "/timeline/",
    dataType: "json",
    success: function (evidence_data) {
      try {
        theme = document.querySelector('[data-bs-theme]').getAttribute('data-bs-theme');
        var data = JSON.parse(evidence_data[0].graph);
        var chart = anychart.line();
        var series = chart.line(data);
        chart.xScroller(true);
        chart.listen("click", function (x) {
          index = x.pointIndex;
          display_timeliner(evidence_id, data[index][0]);
        });
        var xAxis = chart.xAxis();
        xAxis.title("Time");
        var yAxis = chart.yAxis();
        yAxis.title("Events");
        chart
          .background()
          .fill(theme == "dark" ? "#212529" : "#FFF");
        series.stroke({
          color: theme == "light" ? "#212529" : "#FFF",
          thickness: 2,
        });
        var animationSettings = chart.animation();
        animationSettings.duration(1000);
        animationSettings.enabled(true);
        chart.container("timeline");
        chart.draw();
      } catch {
        toastr.error("The timline data could not be displayed.");
      }
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
            { data: "CreatedDate" },
            { data: "AccessedDate" },
            { data: "ChangedDate" },
            { data: "Description" },
            { data: "ModifiedDate" },
            { data: "Plugin" },
            {
              mData: "id",
              mRender: function (id, type, row) {
                return generate_tag("timeliner", row);
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
      $.each(data, function (_, value) {
        build_credential_card("Hashdump", value);
      });
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
      $.each(data, function (_, value) {
        build_credential_card("Cachedump", value);
      });
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
      $.each(data, function (_, value) {
        build_credential_card("Lsadump", value);
      });
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
      if (data.length > 0){
        $.each(data, function (_, value) {
          build_malfind_process_card(value);
        });
      }
      else{
        let div = document.getElementById("malfind_process_list").textContent="Nothing was found by Malfind";
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
      if (data.length > 0){
        try {
          ldrmodules_data.destroy();
        } catch {
          //Nothing to do, the datatable will be created.
        }
        try {
          ldrmodules_data = $("#ldrmodules_datatable").DataTable({
            aaData: data,
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
                  return generate_tag("ldrmodules", row);
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
      console.log(data);
      if (data.length > 0){
        try {
          kernel_modules_data.destroy();
        } catch {
          //Nothing to do, the datatable will be created.
        }

          kernel_modules_data = $("#kernel_modules_datatable").DataTable({
            aaData: data,
            aoColumns: [
              { data: "Base" },
              { data: "Name" },
              { data: "Offset" },
              { data: "Path" },
              { data: "Size" },
              {
                mData: "id",
                mRender: function (id, type, row) {
                  return generate_tag("modules", row);
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
      console.log(data);
      if (data.length > 0){
        try {
          ssdt_data.destroy();
        } catch {
          //Nothing to do, the datatable will be created.
        }

          ssdt_data = $("#ssdt_datatable").DataTable({
            aaData: data,
            aoColumns: [
              { data: "Address" },
              { data: "Index" },
              { data: "Module" },
              { data: "Symbol" },
              {
                mData: "id",
                mRender: function (id, type, row) {
                  return generate_tag("ssdt", row);
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

function generate_file_download_btn(data){
  console.log(data);
  btn = document.createElement('a');
  btn.setAttribute('class','btn btn-sm btn-outline-primary p-1 btn-dump-file')
  btn.textContent = "Dump";
  btn.setAttribute('id',data.id);
  return btn.outerHTML;
}