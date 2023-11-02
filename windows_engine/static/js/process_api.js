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
            console.log(data)
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
            console.log(data)
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
            console.log(data)
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

function display_sessions(evidence_id, process_id){
    $.ajax({
        type: "GET",
        url: "/api/windows/"+evidence_id+"/sessions/"+process_id+"/",
        dataType: "json",
        success: function(data){
            console.log(data)
            $(".p_session_username").text("Session Username : " + data[0].UserName)
        }
      });
}
function display_cmdline(evidence_id, process_id){
    $.ajax({
        type: "GET",
        url: "/api/windows/"+evidence_id+"/cmdline/"+process_id+"/",
        dataType: "json",
        success: function(data){
            console.log(data)
            $(".p_cmdline").text("Arguments : " + data[0].Args)
        }
      });
}

