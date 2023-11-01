
function generate_visualisation(process_id, evidence_id) {
    console.log(evidence_id)
    console.log(process_id)
    // TODO : Fill the Metadata by requesting pslist.
    var elements = [];
    var links = [];
    var graph = new joint.dia.Graph;
    var paper = new joint.dia.Paper({
         el: document.getElementById("overview_graph"),
         model: graph,
         width: '100%',
         height: '100%',
         gridSize: 1,
         drawGrid: true,
         interactive: { elementMove: false } 
     });
     let startPos = { x: 0, y: 0 };
     let startTranslate = { x: 0, y: 0 };
     const SCALE_FACTOR = 0.7; // Change this to adjust sensitivity

     $.ajax({
        type: "GET",
        url: "/api/windows/"+evidence_id+"/cmdline/"+process_id+"/",
        async: false,
        dataType: "json",
        success: function(data){
            elements.push(MakeRoot(data[0]));
            elements.push(MakeCmdLine(data[0]));
            links.push(makeLink(data[0].PID, data[0].id))
            // Now we get the joblinks
        },
        error: function(xhr, status, error) {
            // Handle error response
            console.log(xhr.responseText);
            alert("An error occurred while submitting the form.");
        }
    });

    $.ajax({
        type: "GET",
        url: "/api/windows/"+evidence_id+"/sids/"+process_id+"/",
        async: false,
        dataType: "json",
        success: function(data){
            console.log(data)
            // elements.push(MakeRoot(data[0]));
            // links.push(makeLink(data[0].PID, data[0].id))
        },
        error: function(xhr, status, error) {
            // Handle error response
            console.log(xhr.responseText);
            alert("An error occurred while submitting the form.");
        }
    });


    var cells = elements.concat(links);
    graph.resetCells(cells);
    joint.layout.DirectedGraph.layout(graph, {
        setLinkVertices: false,
        marginX: 5,
        marginY: 5,
        rankDir: 'LR',
    });


}

function makeLink(parentElementLabel, childElementLabel) {

    return new joint.shapes.standard.Link({
        source: { id: parentElementLabel },
        target: { id: childElementLabel },
        smooth: true,
        attrs: { 
            line: {
                targetMarker: {
                    d: 'M 4 -4 0 0 4 4'
                }
            }
        },
    });
}


function MakeRoot(node) {
    var info = node.Process + "\n\nPID : "+ node.PID + "\n";

    var maxLineLength = _.max(info.split('\n'), function(l) {
        return l.length;
    }).length;
    var letterSize = 10;
    var width = 1.8 * (letterSize * (0.8 * maxLineLength + 1));
    var height = 1 * ((info.split('\n').length + 1) * letterSize);
    return new joint.shapes.standard.EmbeddedImage({
        id: node.PID,
        size: { width: width, height: height },
        attrs: {
            label: {
                text: info,
                fontSize: letterSize,
                fontFamily: 'monospace',
                fill: 'black',
            },
            body: {
                fill: 'white',
                width: width,
                height: height,
                rx: 2,
                ry: 2,
            },
            image : {
                xlinkHref: cpu,
                width: 1, 
                height: 1
            }
        }
    });
}

function MakeCmdLine(node) {
    var info = node.Args;
    var maxLineLength = _.max(info.split('\n'), function(l) {
        return l.length;
    }).length;
    var letterSize = 10;
    var width = 1.8 * (letterSize * (0.8 * maxLineLength + 1));
    var height = 1.2 * ((info.split('\n').length + 1) * letterSize);
    return new joint.shapes.standard.Rectangle({
        id: node.id,
        size: { width: width, height: height },
        attrs: {
            label: {
                text: info,
                fontSize: letterSize,
                fontFamily: 'monospace',
                fill: 'black',
            },
            body: {
                fill: 'white',
            },
        }
    });
}

