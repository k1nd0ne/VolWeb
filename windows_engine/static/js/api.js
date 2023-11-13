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
            try{
                sids_data = $('#sids_datatable').dataTable({    
                    "aaData" : data,
                    "aoColumns": [
                        { "data": "Process" },
                        { "data": "Name" },
                        { "data": "SID" },
                        {"mData": "id",
                            "mRender": function (id, type, row) {
                                return generate_tag('sids',row); 
                            }
                        }
                    ],
                    "aLengthMenu": [[25, 50, 75, -1], [25, 50, 75, "All"]],
                    "iDisplayLength": 25
                });
            }
            catch{
                toastr.warning("An error occured when loading data for 'sids'.");
            }
            $('#sids_datatable').show("fast");
        },
        error: function(xhr, status, error) {
            toastr.error("An error occurred : "  + error);
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
            
            try{
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
                                return generate_tag('privileges',row); 
                            }
                        }
                    ],
                    "aLengthMenu": [[25, 50, 75, -1], [25, 50, 75, "All"]],
                    "iDisplayLength": 25
                });
            }
            catch{
                toastr.warning("An error occured when loading data for 'privileges'.");
            }

            $('#privs_datatable').show("fast");
        },
        error: function(xhr, status, error) {
            toastr.error("An error occurred : "  + error);
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
            try{
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
                                return generate_tag('envars',row); 
                            }
                        }
                    ],
                    "aLengthMenu": [[25, 50, 75, -1], [25, 50, 75, "All"]],
                    "iDisplayLength": 25
                });
            }
            catch{
                toastr.warning("An error occured when loading data for 'envars'.");
            }
            $('#envars_datatable').show("fast");
        },
        error: function(xhr, status, error) {
            toastr.error("An error occurred : "  + error);
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
            try{
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
                                return generate_tag('dlllist',row); 
                            }
                        }
                    ],
                    "aLengthMenu": [[25, 50, 75, -1], [25, 50, 75, "All"]],
                    "iDisplayLength": 25
                });
            }
            catch{
                toastr.warning("An error occured when loading data for 'dlllist'.");
            }
            $('#dlllist_datatable').show("fast");
        },
        error: function(xhr, status, error) {
            toastr.error("An error occurred : "  + error);
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

            try{
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
                                return generate_tag('netstat',row); 
                            }
                        }
                    ],
                    "aLengthMenu": [[25, 50, 75, -1], [25, 50, 75, "All"]],
                    "iDisplayLength": 25
                });
            }
            catch{
                toastr.warning("An error occured when loading data for 'netstat'.");
            }
            $('#netstat_datatable').show("fast");
        },
        error: function(xhr, status, error) {
            toastr.error("An error occurred : "  + error);
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
            try{
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
                                return generate_tag('netscan',row); 
                            }
                        }
                    ],
                    "aLengthMenu": [[25, 50, 75, -1], [25, 50, 75, "All"]],
                    "iDisplayLength": 25
                });
            }
            catch{
                toastr.warning("An error occured when loading data for 'netscan'.");
            }

            $('#netscan_datatable').show("fast");
        },
        error: function(xhr, status, error) {
            toastr.error("An error occurred : "  + error);
        }
      });

      $.ajax({
        type: "GET",
        url: "/api/windows/"+evidence_id+"/netgraph/",
        dataType: "json",
        success: function(data){

            try{
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
            catch{
                toastr.error("The network graph could not be displayed.");
            }

        },
        error: function(xhr, status, error) {
            toastr.error("An error occurred : "  + error);
        }
      });
    
}

function display_timeline(evidence_id){
    $.ajax({
        type: "GET",
        url: "/api/windows/"+evidence_id+"/timeline/",
        dataType: "json",
        success: function(evidence_data){
            try{
                var data = JSON.parse(evidence_data[0].graph);
                var chart = anychart.line();
                var series = chart.line(data);
                chart.xScroller(true);
                chart.listen("click", function(x) {
                    index = x.pointIndex;
                    display_timeliner(evidence_id, data[index][0]);
                });
                var xAxis = chart.xAxis();
                xAxis.title("Time");
                var yAxis = chart.yAxis();
                yAxis.title("Events");
                chart.background().fill("#FFF");
                series.stroke({color: "#000", thickness: 2});
                var animationSettings = chart.animation();
                animationSettings.duration(1000);
                animationSettings.enabled(true);
                chart.container("timeline");
                chart.draw();
            }
            catch{
                toastr.error("The timline data could not be displayed.");
            }
        },
        error: function(xhr, status, error) {
            toastr.error("An error occurred : "  + error);
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
        },
        error: function(xhr, status, error) {
            toastr.error("An error occurred : "  + error);
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
        },
        error: function(xhr, status, error) {
            toastr.error("An error occurred : "  + error);
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
            try{
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
            }
            catch{
                toastr.error("The timline data could not be displayed.");
            }

        },
        error: function(xhr, status, error) {
            toastr.error("An error occurred : "  + error);
        }
    });
}

function display_credentials(evidence_id){
    $.ajax({
        type: "GET",
        url: "/api/windows/"+evidence_id+"/hashdump/",
        dataType: "json",
        success: function(data){
            $.each(data, function(_, value) {$
                build_credential_card('Hashdump',value);
            }); 
        },
        error: function(xhr, status, error) {
            toastr.error("An error occurred : "  + error);
        }
        });

        $.ajax({
            type: "GET",
            url: "/api/windows/"+evidence_id+"/cachedump/",
            dataType: "json",
            success: function(data){
                $.each(data, function(_, value) {$
                    build_credential_card('Cachedump',value);
                }); 
            },
            error: function(xhr, status, error) {
                toastr.error("An error occurred : "  + error);
            }
            });

            $.ajax({
                type: "GET",
                url: "/api/windows/"+evidence_id+"/lsadump/",
                dataType: "json",
                success: function(data){
                    $.each(data, function(_, value) {$
                        build_credential_card('Lsadump',value);
                    }); 
                },
                error: function(xhr, status, error) {
                    toastr.error("An error occurred : "  + error);
                }
                });
        $("#credentials").modal('show');
}


function build_credential_card(plugin, data){
    const card_div = document.createElement('div');
    card_div.setAttribute('class', 'card shadow border-start-primary py-2 mt-2');

    const card_body = document.createElement('div');
    card_body.setAttribute('class', 'card-body');

    const card_row = document.createElement('div');
    card_row.setAttribute('class', 'row align-items-center d-flex no-gutters');

    const card_col1 = document.createElement('div');
    card_col1.setAttribute('class', 'col-auto align-items-center d-flex');

    const card_icon = document.createElement('i');
    card_icon.setAttribute('class', 'fas fa-user fa-2x text-gray-600');

    card_col1.appendChild(card_icon);

    const card_col2 = document.createElement('div');
    card_col2.setAttribute('class', 'col me-2');

    const card_title = document.createElement('span');
    card_title.setAttribute('class', 'text-uppercase fw-bold text-xs mb-1');
    const card_elements = document.createElement('div');
    card_elements.setAttribute('class', 'text-dark list-group-item');

    card_row.appendChild(card_col1);
    card_col1.appendChild(card_title);
    card_col2.appendChild(card_elements);
    card_row.appendChild(card_col2);
    card_body.appendChild(card_row);
    card_div.appendChild(card_body);

    const li_1 = document.createElement('li');
    const li_2 = document.createElement('li');
    const li_3 = document.createElement('li');


    if (plugin == "Hashdump"){
        card_title.textContent = data.User;
        li_1.textContent = "rid : " + data.rid;
        li_2.textContent = "lmhash : " + data.lmhash;
        li_3.textContent = "nthash : " + data.nthash;
        card_elements.appendChild(li_1);
        card_elements.appendChild(li_2);
        card_elements.appendChild(li_3);
        document.getElementById('credentials_cards_1').appendChild(card_div);

    }
    if (plugin == "Cachedump") {
        card_title.textContent = data.UserName;
        li_1.textContent = "Domain : " + data.Domain;
        li_2.textContent = "Domain Name : " + data.Domainname;
        li_3.textContent = "Hash : " + data.Hash;
        card_elements.appendChild(li_1);
        card_elements.appendChild(li_2);
        card_elements.appendChild(li_3);
        document.getElementById('credentials_cards_2').appendChild(card_div);
    }
    
    if (plugin == "Lsadump") {
        card_title.textContent = data.Key;
        li_1.textContent = "Secret (base64) : " + data.Secret;
        li_2.textContent = "Hex : " + data.Hex;
        card_elements.appendChild(li_1);
        card_elements.appendChild(li_2);
        document.getElementById('credentials_card_3').appendChild(card_div);
    }

}