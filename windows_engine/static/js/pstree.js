function display_pstree(evidence_id) {
  //First get the data via the API.
  $.ajax({
    type: "GET",
    url: "/api/windows/" + evidence_id + "/pstree/",
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
          var newNode = new TreeNode(
            node.PID + " - " + node.ImageFileName,
            node,
          );
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
  $.ajax({
    type: "GET",
    url: `${tasksURL}/tasks/`,
    dataType: "json",
    success: function (tasks) {
      let handles_found = false;
      let dump_found = false;
      tasks.forEach(({ status, task_name, task_args }) => {
        var args;
        if (status !== "PENDING") {
          args = JSON.parse(task_args).slice(1, -1).split(",");
        } else {
          args = task_args.slice(1, -1).split(",");
        }
        const pid = parseInt(args[1], 10);
        const id = parseInt(args[0], 10);
        if (pid == process.PID && id == evidence_id) {
          if (task_name === "windows_engine.tasks.compute_handles") {
            handles_found = true;
          } else if (
            task_name === "windows_engine.tasks.dump_process_memmap" ||
            task_name === "windows_engine.tasks.dump_process_pslist"
          ) {
            dump_found = true;
          }
        }
      });

      $(".card_process_dump").toggle(!dump_found);
      $(".loading_process_dump").toggle(dump_found);
      $(".card_handles").toggle(!handles_found);
      $(".loading_handles").toggle(handles_found);
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred while getting the tasks : " + error);
    },
  });
  $(".process_id").attr("id", process.PID);
  $(".process_title").text(process.ImageFileName);
  $(".p_pid").text(process.PID);
  $(".p_offset").text(process["Offset(V)"]);
  $(".p_threads").text(process.Threads);
  $(".p_handles").text(process.Handles);
  $(".p_session").text(process.SessionId);
  if (process.Wow64 == true) {
    $(".p_wow64").addClass("text-danger");
  } else {
    $(".p_wow64").removeClass("text-danger");
  }
  $(".p_wow64").text(process.Wow64);
  $(".p_ctime").text(process.CreateTime);
  $(".p_etime").text(process.ExitTime);
  display_sessions(evidence_id, process.PID);
  display_cmdline(evidence_id, process.PID);
}
