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
    // Check if there is not too much elements
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
  var info = node.ImageFileName + "\n\nPID : " + node.PID + "\n";
  var maxLineLength = _.max(info.split("\n"), function (l) {
    return l.length;
  }).length;
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


function build_credential_card(plugin, data) {
  /* 
    Build a credentital card: used in api.js for hashdump, lsadump, cachedump 
  */
  const card_div = document.createElement("div");
  card_div.setAttribute("class", "card shadow border-start-primary py-2 mt-2");

  const card_body = document.createElement("div");
  card_body.setAttribute("class", "card-body");

  const card_row = document.createElement("div");
  card_row.setAttribute("class", "row align-items-center d-flex no-gutters");

  const card_col1 = document.createElement("div");
  card_col1.setAttribute("class", "col-auto align-items-center d-flex");

  const card_icon = document.createElement("i");
  card_icon.setAttribute("class", "fas fa-user fa-2x text-gray-600");

  card_col1.appendChild(card_icon);

  const card_col2 = document.createElement("div");
  card_col2.setAttribute("class", "col me-2");

  const card_title = document.createElement("span");
  card_title.setAttribute("class", "text-uppercase fw-bold text-xs mb-1");
  const card_elements = document.createElement("div");
  card_elements.setAttribute("class", "list-group-item");

  card_row.appendChild(card_col1);
  card_col1.appendChild(card_title);
  card_col2.appendChild(card_elements);
  card_row.appendChild(card_col2);
  card_body.appendChild(card_row);
  card_div.appendChild(card_body);

  const li_1 = document.createElement("li");
  const li_2 = document.createElement("li");
  const li_3 = document.createElement("li");

  if (plugin == "Hashdump") {
    card_title.textContent = data.User;
    li_1.textContent = "rid : " + data.rid;
    li_2.textContent = "lmhash : " + data.lmhash;
    li_3.textContent = "nthash : " + data.nthash;
    card_elements.appendChild(li_1);
    card_elements.appendChild(li_2);
    card_elements.appendChild(li_3);
    document.getElementById("credentials_cards_1").appendChild(card_div);
  }
  if (plugin == "Cachedump") {
    card_title.textContent = data.UserName;
    li_1.textContent = "Domain : " + data.Domain;
    li_2.textContent = "Domain Name : " + data.Domainname;
    li_3.textContent = "Hash : " + data.Hash;
    card_elements.appendChild(li_1);
    card_elements.appendChild(li_2);
    card_elements.appendChild(li_3);
    document.getElementById("credentials_cards_2").appendChild(card_div);
  }

  if (plugin == "Lsadump") {
    card_title.textContent = data.Key;
    li_1.textContent = "Secret (base64) : " + data.Secret;
    li_2.textContent = "Hex : " + data.Hex;
    card_elements.appendChild(li_1);
    card_elements.appendChild(li_2);
    document.getElementById("credentials_card_3").appendChild(card_div);
  }
}


function build_malfind_process_card(data) {
  /* 
    Build a malfind process card: used in api.js
    Also add event listeners to then fill the info about each process.
  */

  console.log(data)
  const cardDiv = document.createElement('div');
  cardDiv.classList.add('card', 'shadow', 'border-start-primary', 'card_clickable', 'm-2');
  cardDiv.id = "malfind_process_" + data["Start VPN"];

  const cardBodyDiv = document.createElement('div');
  cardBodyDiv.classList.add('card-body', 'p-2');

  cardDiv.appendChild(cardBodyDiv);

  const rowDiv = document.createElement('div');
  rowDiv.classList.add('row', 'align-items-center', 'no-gutters');

  cardBodyDiv.appendChild(rowDiv);

  const iconColDiv = document.createElement('div');
  iconColDiv.classList.add('col-auto');

  rowDiv.appendChild(iconColDiv);

  const icon = document.createElement('i');
  icon.classList.add('fas', 'fa-exclamation', 'text-warning');

  iconColDiv.appendChild(icon);

  const textColDiv = document.createElement('div');
  textColDiv.classList.add('col', 'me-2');

  rowDiv.appendChild(textColDiv);

  const spanText = document.createElement('span');
  spanText.classList.add('fw-bold', 'text-xs');
  spanText.textContent = data.Process + " - " + data.PID;

  textColDiv.appendChild(spanText);
  document.getElementById("malfind_process_list").appendChild(cardDiv);
  $('#' + cardDiv.id).on("click", function () {
    display_malfind_details(data);
  });
}

function display_malfind_details(data) {
  /*
    Display the detailled info when a malfind process card is clicked. 
  */
  $("#malfind_start_vpn").text(data['Start VPN']);
  $("#malfind_end_vpn").text(data['End VPN']);
  $("#malfind_tag").text(data.Tag);
  $("#malfind_protection").text(data.Protection);
  $("#malfind_hexdump").text(data.Hexdump);
  $("#malfind_disasm").text(data.Disasm);
  $("#malfind_details").show();
}

function injections_rootkits_hide_all() {
  $("#ldrmodule_details").hide();
  $("#kernel_modules_details").hide();
  $("#ssdt_details").hide();
  $("#malfind_process_menu").hide();
  $("#malfind_details").hide();
}