function display_sids(evidence_id, process_id){
    $("#sids").modal('show');
    $.ajax({
        type: "GET",
        url: "/api/windows/"+evidence_id+"/sids/"+process_id+"/",
        dataType: "json",
        success: function(data){
            try{
                sids_data.api().destroy();
            }
            catch{
                //Nothing to do, the datatable will be created.
            }
        
            sids_data = $('#sids_datatable').dataTable({    
                "aaData" : data,
                "aoColumns": [
                    { "data": "Process" },
                    { "data": "Name" },
                    { "data": "SID" },
                    {"mData": "id",
                        "mRender": function (id, type, row) {
                            return generate_tag(row); 
                        }
                    }
                ],
                "aLengthMenu": [[25, 50, 75, -1], [25, 50, 75, "All"]],
                "iDisplayLength": 25
            });
            
            $('#sids_datatable').show("fast");
        }
      });
    
}

function display_privs(evidence_id, process_id){
    $("#privs").modal('show');
    $.ajax({
        type: "GET",
        url: "/api/windows/"+evidence_id+"/privileges/"+process_id+"/",
        dataType: "json",
        success: function(data){
            try{
                privs_data.api().destroy();
            }
            catch{
                //Nothing to do, the datatable will be created.
            }
            

            privs_data = $('#privs_datatable').dataTable({    
                "aaData" : data,
                "aoColumns": [
                    { "data": "Process" },
                    { "data": "Privilege" },
                    { "data": "Description" },
                    { "data": "Value" },
                    { "data": "Attributes" },
                    {"mData": "id",
                        "mRender": function (id, type, row) {
                            return generate_tag(row); 
                        }
                    }
                ],
                "aLengthMenu": [[25, 50, 75, -1], [25, 50, 75, "All"]],
                "iDisplayLength": 25
            });
            $('#privs_datatable').show("fast");
        }
      });
    
}


function display_envars(evidence_id, process_id){
    $("#envars").modal('show');
    $.ajax({
        type: "GET",
        url: "/api/windows/"+evidence_id+"/envars/"+process_id+"/",
        dataType: "json",
        success: function(data){
            try{
                envars_data.api().destroy();
            }
            catch{
                //Nothing to do, the datatable will be created.
            }
            

            envars_data = $('#envars_datatable').dataTable({    
                "aaData" : data,
                "aoColumns": [
                    { "data": "Process" },
                    { "data": "Block" },
                    { "data": "Description" },
                    { "data": "Variable" },
                    { "data": "Value" },
                    {"mData": "id",
                        "mRender": function (id, type, row) {
                            return generate_tag(row); 
                        }
                    }
                ],
                "aLengthMenu": [[25, 50, 75, -1], [25, 50, 75, "All"]],
                "iDisplayLength": 25
            });
            $('#envars_datatable').show("fast");
        }
      });
    
}

function display_dlllist(evidence_id, process_id){
    $("#dlllist").modal('show');
    $.ajax({
        type: "GET",
        url: "/api/windows/"+evidence_id+"/dlllist/"+process_id+"/",
        dataType: "json",
        success: function(data){
            try{
                dlllist_data.api().destroy();
            }
            catch{
                //Nothing to do, the datatable will be created.
            }
            

            dlllist_data = $('#dlllist_datatable').dataTable({    
                "aaData" : data,
                "aoColumns": [
                    { "data": "Process" },
                    { "data": "Base" },
                    { "data": "Name" },
                    { "data": "Path" },
                    { "data": "LoadTime" },
                    { "data": "Size" },
                    {"mData": "id",
                        "mRender": function (id, type, row) {
                            return generate_tag(row); 
                        }
                    }
                ],
                "aLengthMenu": [[25, 50, 75, -1], [25, 50, 75, "All"]],
                "iDisplayLength": 25
            });
            $('#dlllist_datatable').show("fast");
        }
      });
    
}

function display_network(evidence_id){
    $("#network").modal('show');
    $.ajax({
        type: "GET",
        url: "/api/windows/"+evidence_id+"/netstat/",
        dataType: "json",
        success: function(data){
            try{
                netstat_data.api().destroy();
            }
            catch{
                //Nothing to do, the datatable will be created.
            }

            netstat_data = $('#netstat_datatable').dataTable({    
                "aaData" : data,
                "aoColumns": [
                    { "data": "Proto" },
                    { "data": "LocalAddr" },
                    { "data": "LocalPort" },
                    { "data": "ForeignAddr" },
                    { "data": "ForeignPort" },
                    { "data": "State" },
                    { "data": "Offset" },
                    { "data": "Created" },
                    { "data": "Owner" },
                    {"mData": "id",
                        "mRender": function (id, type, row) {
                            return generate_tag(row); 
                        }
                    }
                ],
                "aLengthMenu": [[25, 50, 75, -1], [25, 50, 75, "All"]],
                "iDisplayLength": 25
            });
            $('#netstat_datatable').show("fast");
        }
      });

      $.ajax({
        type: "GET",
        url: "/api/windows/"+evidence_id+"/netscan/",
        dataType: "json",
        success: function(data){
            try{
                netscan_data.api().destroy();
            }
            catch{
                //Nothing to do, the datatable will be created.
            }
            
            netscan_data = $('#netscan_datatable').dataTable({    
                "aaData" : data,
                "aoColumns": [
                    { "data": "Proto" },
                    { "data": "LocalAddr" },
                    { "data": "LocalPort" },
                    { "data": "ForeignAddr" },
                    { "data": "ForeignPort" },
                    { "data": "State" },
                    { "data": "Offset" },
                    { "data": "Created" },
                    { "data": "Owner" },
                    {"mData": "id",
                        "mRender": function (id, type, row) {
                            return generate_tag(row); 
                        }
                    }
                ],
                "aLengthMenu": [[25, 50, 75, -1], [25, 50, 75, "All"]],
                "iDisplayLength": 25
            });
            $('#netscan_datatable').show("fast");
        }
      });

      $.ajax({
        type: "GET",
        url: "/api/windows/"+evidence_id+"/netgraph/",
        dataType: "json",
        success: function(data){
            $('#net_graph').empty();
            var data = JSON.parse(data[0].graph);
            // create a data tree
            // create a chart and set the data
            var netchart = anychart.graph(data);
            netchart.nodes().normal().fill("#000");
            netchart.nodes().hovered().fill("#000");
            netchart.nodes().labels().enabled(true);
            netchart.nodes().labels().format("{%id} ({%Owner(s)})");
            netchart.nodes().labels().fontSize(12);
            netchart.nodes().labels().fontWeight(600);
            netchart.nodes().labels().fontColor("#000");
            netchart.edges().normal().stroke("#212529", 1);
            netchart.edges().hovered().stroke("#212529", 2);
            netchart.edges().selected().stroke("#dc3545", 3);

            // configure tooltips of nodes
            netchart.nodes().tooltip().useHtml(true);
            netchart.nodes().tooltip().format(
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
          
        }
      });
    
}

function display_timeline(evidence_id){
    $.ajax({
        type: "GET",
        url: "/api/windows/"+evidence_id+"/timeline/",
        dataType: "json",
        success: function(evidence_data){
            // create data
            console.log(evidence_data)
            var data = JSON.parse(evidence_data[0].graph);
            // create a chart
            var chart = anychart.line();
            // create a line series and set the data
            var series = chart.line(data);
            chart.xScroller(true);
            chart.listen("click", function(x) {
                index = x.pointIndex;
                display_timeliner(evidence_id, data[index][0]);
            });

            // set the titles of the axes
            var xAxis = chart.xAxis();
            xAxis.title("Time");
            var yAxis = chart.yAxis();
            yAxis.title("Events");
            chart.background().fill("#FFF");
            series.stroke({color: "#000", thickness: 2});
            var animationSettings = chart.animation();

            animationSettings.duration(1000);
            animationSettings.enabled(true);
            // set the container id
            chart.container("timeline");
            // initiate drawing the chart
            chart.draw();
        },
        error: function(xhr, status, error) {
            // Handle error response
            console.log(xhr.responseText);
            alert("An error occurred while submitting the form.");
        }
    });
}


function display_sessions(evidence_id, process_id){
    $.ajax({
        type: "GET",
        url: "/api/windows/"+evidence_id+"/sessions/"+process_id+"/",
        dataType: "json",
        success: function(data){
            $(".p_session_username").text(data[0].UserName)
        }
      });
}
function display_cmdline(evidence_id, process_id){
    $.ajax({
        type: "GET",
        url: "/api/windows/"+evidence_id+"/cmdline/"+process_id+"/",
        dataType: "json",
        success: function(data){
            $(".p_cmdline").text(data[0].Args)
        }
      });
}

function display_timeliner(evidence_id, timestamp){
    $.ajax({
        type: "GET",
        url: "/api/windows/"+evidence_id+"/timeliner/"+timestamp+"/",
        dataType: "json",
        success: function(data){
            try{
                timeline_data.api().destroy();
            }
            catch{
                //Nothing to do, the datatable will be created.
            }
            timeline_data = $('#timeline_datatable').dataTable({    
                "aaData" : data,
                "aoColumns": [
                    { "data": "CreatedDate" },
                    { "data": "AccessedDate" },
                    { "data": "ChangedDate" },
                    { "data": "Description" },
                    { "data": "ModifiedDate" },
                    { "data": "Plugin" },
                    {"mData": "id",
                        "mRender": function (id, type, row) {
                            return generate_tag('timeliner',row); 
                        }
                    }
                ],
                "aLengthMenu": [[25, 50, 75, -1], [25, 50, 75, "All"]],
                "iDisplayLength": 25
            });
        },
        error: function(xhr, status, error) {
            // Handle error response
            console.log(xhr.responseText);
            alert("An error occurred while submitting the form.");
        }
    });
}