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
                display_timeline(evidence_id, data[index][0]);
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

