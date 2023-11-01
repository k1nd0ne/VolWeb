
function generate_visualisation(process, pstree) {
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

    

     $.each(pstree, function(_,node){
        find_childs(process.PID, node, elements, links)
     });

     function find_childs(pid, node, elements, links){
        // Check if there is not too much elements
        if (node.PID == pid){
            if (node.children){
                $.each(node.children, function(_,childNode){
                    elements.push(MakeNode(childNode));
                    links.push(makeLink(pid, childNode.PID))
                    find_childs(childNode.PID, childNode, elements, links);
                });   
                elements.push(MakeNode(node));
            }
        }
        else{
            if (node.children){
                $.each(node.children, function(_,childNode){
                    find_childs(pid, childNode, elements, links);
                });   
            }
        }
      }

    var cells = elements.concat(links);
    graph.resetCells(cells);
    joint.layout.DirectedGraph.layout(graph, {
        setLinkVertices: false,
        marginX: 5,
        marginY: 5,
        rankDir: 'LR',
    })
    var bbox = graph.getBBox(graph.getElements());
    $('.graph').height(bbox.height + 30);
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

function MakeNode(node) {
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



