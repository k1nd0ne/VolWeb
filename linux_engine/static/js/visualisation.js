const highlightStyles = {
  node: { "border-color": "red", "border-width": 3 },
  edge: { "stroke-width": 3, stroke: "red" },
};

const defaultStyles = {
  node: { "border-color": "black", "border-width": 1 },
  edge: { "stroke-width": 1, stroke: "black" },
};

function applyStyles(cell, styles) {
  if (cell.isLink()) {
    cell.attr({
      line: {
        stroke: styles.edge.stroke,
        "stroke-width": styles.edge["stroke-width"],
      },
    });
  } else {
    cell.attr({
      body: {
        stroke: styles.node["border-color"],
        "stroke-width": styles.node["border-width"],
      },
    });
  }
}

function generate_network_visualisation(data) {
  var namespace = joint.shapes;
  var graph = new joint.dia.Graph({}, { cellNamespace: namespace });

  var paper = new joint.dia.Paper({
    el: document.getElementById("net_graph"),
    model: graph,
    width: "100%",
    height: "100%",
    gridSize: 1,
    drawGrid: true,
    interactive: { vertexAdd: false },
  });
  data.artefacts.nodes.forEach((item) => {
    if (item.id) {
      node = MakeNetNode(item);
      MakeNetNode(item).addTo(graph);
    }
  });
  data.artefacts.edges.forEach((item) => {
    if (item.from && item.to) {
      makeLink(item.from, item.to).addTo(graph);
    }
  });
  joint.layout.DirectedGraph.layout(graph, {
    setLinkVertices: false,
    rankDir: "LR", // Direction: TB (top to bottom), LR (left to right), etc.
    nodeSep: 100, // Horizontal separation between nodes
    edgeSep: 100, // Separation between edges
    rankSep: 100, // Vertical separation between nodes+
    marginX: 5,
    marginY: 5,
  });
  graph.getCells().forEach(function (cell) {
    if (cell.isLink()) {
      // If cell is a link, send it to back
      cell.toBack();
    } else {
      // If cell is an element (node), bring it to front
      cell.toFront();
    }
  });

  graph.on("add", function (cell) {
    // Reset styles whenever a new cell is added
    applyStyles(cell, defaultStyles);
  });

  paper.on("cell:pointerclick", function (cellView, evt, x, y) {
    resetStyles();
    highlightLinked(cellView.model); // Highlight connected nodes and edges
  });
  var bbox = graph.getBBox(graph.getElements());
  $(".netgraph").height(bbox.height + 30);
  function resetStyles() {
    graph.getCells().forEach(function (cell) {
      applyStyles(cell, defaultStyles);
    });
  }

  // Define the function to highlight connected nodes and edges
  function highlightLinked(node) {
    // Helper function to highlight the linked nodes and edges
    var connectedLinks = graph.getConnectedLinks(node);
    var linkedElements = [];

    connectedLinks.forEach(function (link) {
      var sourceElement = link.getSourceElement();
      var targetElement = link.getTargetElement();
      linkedElements.push(sourceElement, targetElement);
      applyStyles(link, highlightStyles);
    });

    linkedElements.forEach(function (element) {
      if (element && element.id !== node.id) {
        applyStyles(element, highlightStyles);
      }
    });

    // Also highlight the clicked node itself
    applyStyles(node, highlightStyles);
  }
}

function MakeNetNode(item) {
  if (item.Process) {
    var info = item.Process + "\n\nLocal Ports:";
    maxLineLength = info.length + 10;

    if (item["LocalPorts"]) {
      item["LocalPorts"].forEach((ports) => {
        if (ports !== null) {
          info += "\n" + ports;
          if (ports.length > maxLineLength) {
            maxLineLength = ports.length;
          }
        }
      });
    }
  } else {
    maxLineLength = item.id.length + 10;
    var info =
      (item.id.length === 0 ? "Unknown" : item.id) + "\nForeign Ports:";

    if (item["ForeignPorts"]) {
      item["ForeignPorts"].forEach((ports) => {
        if (ports !== null) {
          info += "\n" + ports;
          if (ports.length > maxLineLength) {
            maxLineLength = ports.length;
          }
        }
      });
    }
  }

  var letterSize = 10;
  var width = 1.2 * (letterSize * (0.8 * maxLineLength + 1));
  var height = 1 * ((info.split("\n").length + 1) * letterSize);
  rect = new joint.shapes.standard.Rectangle({
    id: item.id,
    size: { width: width, height: height },
  });
  rect.attr({
    label: {
      text: info,
      fontSize: letterSize,
      fontFamily: "monospace",
      fill: "black",
    },
    body: {
      fill: "white",
      stroke: "#084298",
      width: width,
      height: height,
      rx: 2,
      ry: 2,
    },
  });
  return rect;
}

function generate_visualisation(process, pstree) {
  var elements = [];
  var links = [];
  var graph = new joint.dia.Graph();
  var paper = new joint.dia.Paper({
    el: document.getElementById("overview_graph"),
    model: graph,
    width: "100%",
    height: "100%",
    gridSize: 1,
    drawGrid: true,
    interactive: { elementMove: false },
  });

  $.each(pstree, function (_, node) {
    find_childs(process.PID, node, elements, links);
  });

  function find_childs(pid, node, elements, links) {
    if (node.PID == pid) {
      if (node.__children) {
        $.each(node.__children, function (_, childNode) {
          elements.push(MakeNode(childNode));
          links.push(makeLink(pid, childNode.PID));
          find_childs(childNode.PID, childNode, elements, links);
        });
        elements.push(MakeNode(node));
      }
    } else {
      if (node.__children) {
        $.each(node.__children, function (_, childNode) {
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
    rankDir: "LR",
  });
  // Adjust z-indices after layout
  graph.getCells().forEach(function (cell) {
    if (cell.isLink()) {
      // If cell is a link, send it to back
      cell.toBack();
    } else {
      // If cell is an element (node), bring it to front
      cell.toFront();
    }
  });
  var bbox = graph.getBBox(graph.getElements());
  $(".graph").height(bbox.height + 30);
}

function makeLink(parentElementLabel, childElementLabel) {
  return new joint.shapes.standard.Link({
    source: { id: parentElementLabel },
    target: { id: childElementLabel },
    smooth: true,
    attrs: {
      line: {
        targetMarker: {
          d: "M 4 -4 0 0 4 4",
        },
        stroke: "#e082b1",
        strokeWidth: 1.4,
      },
    },
  });
}

function MakeNode(node) {
  var pid_info = `PID : ${node.PID}`;
  var info = `${node.COMM}\n\n${pid_info}\n`;
  var maxLineLength = _.max([pid_info.length, node.COMM.length]);
  var letterSize = 10;
  var width = 1.8 * (letterSize * (0.8 * maxLineLength + 1));
  var height = 1 * ((info.split("\n").length + 1) * letterSize);
  return new joint.shapes.standard.EmbeddedImage({
    id: node.PID,
    size: { width: width, height: height },
    attrs: {
      label: {
        text: info,
        fontSize: letterSize,
        fontFamily: "monospace",
        fill: "black",
      },
      body: {
        fill: "white",
        stroke: "#084298",
        width: width,
        height: height,
        rx: 2,
        ry: 2,
      },
      image: {
        xlinkHref: cpu,
        width: 1,
        height: 1,
      },
    },
  });
}

function build_malfind_process_card(data) {
  /*
    Build a malfind process card: used in api.js
    Also add event listeners to then fill the info about each process.
  */
  const cardDiv = document.createElement("div");
  cardDiv.classList.add(
    "card",
    "shadow",
    "border-start-primary",
    "card_clickable",
    "m-2",
  );
  cardDiv.id = "malfind_process_" + data["Start"];

  const cardBodyDiv = document.createElement("div");
  cardBodyDiv.classList.add("card-body", "p-2");

  cardDiv.appendChild(cardBodyDiv);

  const rowDiv = document.createElement("div");
  rowDiv.classList.add("row", "align-items-center", "no-gutters");

  cardBodyDiv.appendChild(rowDiv);

  const iconColDiv = document.createElement("div");
  iconColDiv.classList.add("col-auto");

  rowDiv.appendChild(iconColDiv);

  const icon = document.createElement("i");
  icon.classList.add("fas", "fa-exclamation", "text-warning");

  iconColDiv.appendChild(icon);

  const textColDiv = document.createElement("div");
  textColDiv.classList.add("col", "me-2");

  rowDiv.appendChild(textColDiv);

  const spanText = document.createElement("span");
  spanText.classList.add("fw-bold", "text-xs");
  spanText.textContent = data.Process + " - " + data.PID;

  textColDiv.appendChild(spanText);
  document.getElementById("malfind_process_list").appendChild(cardDiv);
  $("#" + cardDiv.id).on("click", function () {
    display_malfind_details(data);
  });
}

function display_malfind_details(data) {
  /*
    Display the detailled info when a malfind process card is clicked.
  */
  $("#malfind_start_vpn").text(data["Start"]);
  $("#malfind_end_vpn").text(data["End"]);
  $("#malfind_protection").text(data.Protection);
  $("#malfind_hexdump").text(data.Hexdump);
  $("#malfind_disasm").text(data.Disasm);
  $("#malfind_details").show();
}

function injections_rootkits_hide_all() {
  $("#ir_details").hide();
  $("#malfind_details").hide();
  $("#malfind_process_menu").hide();
}
