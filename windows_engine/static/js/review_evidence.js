
$(document).ready(function() {
    const evidence_id = $('.main').attr('id');    
    display_pstree(evidence_id);
});

function display_pstree(evidence_id){  
    //First get the data via the API.
    $.ajax({
      type: "GET",
      url: "/api/windows/"+evidence_id+"/pstree/",
      dataType: "json",
      success: function(evidence_data){
        var graph = new joint.dia.Graph;
        
       var paper = new joint.dia.Paper({
            el: document.getElementById("pstree"),
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
        
        paper.on({
            'blank:pointerdown': function(evt, x, y) {
                startPos = { x: x, y: y };
                startTranslate = { x: paper.translate().tx, y: paper.translate().ty };
            },
            'blank:pointermove': function(evt, x, y) {
                // Scale the movement by the scale factor
                let newX = startTranslate.x + (x - startPos.x) * SCALE_FACTOR;
                let newY = startTranslate.y + (y - startPos.y) * SCALE_FACTOR;
        
                paper.translate(newX, newY);
            }
        });


        paper.on('blank:mousewheel', (event, x, y, delta) => {
            const scale = paper.scale();
            paper.scale(scale.sx + (delta * 0.02), scale.sy + (delta * 0.02),);
          });
        
        
        try {
            var process_list = JSON.parse(evidence_data[0].graph);
            var cells = adjacencyListToCells(process_list);   
            graph.resetCells(cells);
            joint.layout.DirectedGraph.layout(graph, {
                setLinkVertices: false,
                marginX: 5,
                marginY: 5,
                rankDir: 'LR',
                
            });

            // Adjust z-indices after layout
            graph.getCells().forEach(function(cell) {
                if (cell.isLink()) {
                    // If cell is a link, send it to back
                    cell.toBack();
                } else {
                    // If cell is an element (node), bring it to front
                    cell.toFront();
                }
            });

            // paper.scaleContentToFit({
            //     padding: 10,
            //     // preserveAspectRatio defines whether aspect ratio should be preserved
            //     preserveAspectRatio: true,
            //    // gridSize allows the function to align the new paper size with the grid
            //     minScale: 0.1,
            //     maxScale: 2
            // });
        } catch (error) {
            console.log(error);
        }



        
      },
      error: function(xhr, status, error) {
          // Handle error response
          console.log(xhr.responseText);
          alert("An error occurred while submitting the form.");
      }
    });
}



function adjacencyListToCells(pstree) {
    
    var elements = [];
    var links = [];
    var elementMap = new Map();
    var root = MakeRoot();
    elements.push(root)
    elementMap.set(1,root);
    _.each(pstree, function(node) {
        build_tree(node);
    });
    
    function build_tree(node){
        // create node and add to elements
        var newNode = makeElement(node);
        elements.push(newNode);
        // add the same node into the map
        elementMap.set(node.PID, newNode);
        // now create links
        if (node.children.length){
            _.each(node.children, function(childNode){
                build_tree(childNode);
            });   
        }
        // if the parent exists in the map, create a link
        if (elementMap.has(node.PPID)){
            links.push(makeLink(node.PPID, node.PID));
        }
        else{
            links.push(makeLink(1, node.PID));
        }
    }
    var cells = elements.concat(links);
    return cells;
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

function makeElement(node) {
    var info = node.name + "\n\nPID : "+ node.PID + "\n";


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
                fill: 'black'
            },
            body: {
                fill: 'white',
                width: width,
                height: height,
                rx: 5,
                ry: 5,
            },
            image : {
                xlinkHref: cpu,
                width: 1, 
                height: 1
            }
            
        }
    });
}


function MakeRoot() {
    var name = "Root";
    var PID = 1;
    var maxLineLength = _.max(name.split('\n'), function(l) {
        return l.length;
    }).length;
    var letterSize = 10;
    var width = 2 * (letterSize * (0.6 * maxLineLength + 1));
    var height = 2 * ((name.split('\n').length + 1) * letterSize);
    return new joint.shapes.standard.TextBlock({
        id: PID,
        size: { width: width, height: height },
        attrs: {
            label: {
                text: name,
                fontSize: letterSize,
                fontFamily: 'monospace',
                fill: 'black'
            },
            body: {
                fill: 'white',
                width: width,
                height: height,
                rx: 5,
                ry: 5,
            }
        }
    });
}