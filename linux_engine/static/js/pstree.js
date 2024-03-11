function display_pstree(evidence_id) {
  $.ajax({
    type: "GET",
    url: "/api/linux/" + evidence_id + "/pstree/",
    dataType: "json",
    success: function (evidence_data) {
      if (evidence_data !== null) {
        var process_list = evidence_data.artefacts;
        var root = new TreeNode("root");
        $.each(process_list, function (_, node) {
          build_tree(node, root);
        });
        first_process = root.getChildren()[0];
        if (!first_process) {
          // The PSTREE is not available, so all of the plugins based on filtering are disabled
          $(".card_filtering").hide();
          $("#container").html(
            `<i class="text-danger">The PsTree is unavailable, your investigation capablities are downgraded.</i>`,
          );
          return;
        }
        first_process.toggleSelected();
        display_process_info(first_process.getProcessObject(), evidence_id);
        generate_visualisation(first_process.getProcessObject(), process_list);
        var view = new TreeView(root, "#container");
        view.changeOption("leaf_icon", '<i class="fas fa-microchip"></i>');
        view.changeOption("parent_icon", '<i class="fas fa-microchip"></i>');
        TreeConfig.open_icon = '<i class="fas fa-angle-down"></i>';
        TreeConfig.close_icon = '<i class="fas fa-angle-right"></i>';
        root.changeOption("icon", '<i class="fas fa-code-branch"></i>');
        view.reload();

        function build_tree(node, root) {
          // create node and add to elements
          var newNode = new TreeNode(node.PID + " - " + node.COMM, node);
          // now create links
          if (node.__children) {
            $.each(node.__children, function (_, childNode) {
              build_tree(childNode, newNode);
            });
          }
          newNode.on("click", function (e, node) {
            display_process_info(node.getProcessObject(), evidence_id);
            generate_visualisation(node.getProcessObject(), process_list);
          });
          root.addChild(newNode);
        }
      }
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + xhr.responseText);
    },
  });
}

function display_process_info(process, evidence_id) {
  $(".process_id").attr("id", process.PID);
  $(".process_title").text(process.COMM);
  $(".p_pid").text(process.PID);
  $(".p_offset").text(process["OFFSET (V)"]);
  $(".p_threads").text(process.TID);
  display_psaux(evidence_id, process.TID);
}
