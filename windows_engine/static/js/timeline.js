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
                display_data(evidence_id, data[index][0]);
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

function display_data(evidence_id, timestamp){
    $.ajax({
        type: "GET",
        url: "/api/windows/"+evidence_id+"/timeline_data/"+timestamp+"/",
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
                            return generate_tag(row); 
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