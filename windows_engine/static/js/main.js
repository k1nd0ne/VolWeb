$(document).ready(function () {
  const evidence_id = $(".main").attr("id");
  reconnectDelay = 1000; // milliseconds
  connectWebSocket(evidence_id);

  display_pstree(evidence_id);
  display_timeline(evidence_id);

  /* ======================= Overview ======================= */
  $(".card_handles").on("click", function () {
    pid = $(".process_id").attr("id");
    compute_handles(evidence_id, pid);
  });

  $(".card_sids").on("click", function () {
    pid = $(".process_id").attr("id");
    display_sids(evidence_id, pid);
  });

  $(".card_privs").on("click", function () {
    pid = $(".process_id").attr("id");
    display_privs(evidence_id, pid);
  });

  $(".card_envars").on("click", function () {
    pid = $(".process_id").attr("id");
    display_envars(evidence_id, pid);
  });

  $(".card_dlllist").on("click", function () {
    pid = $(".process_id").attr("id");
    display_dlllist(evidence_id, pid);
  });

  $(".card_network").on("click", function () {
    display_network(evidence_id);
  });

  $(".card_sessions").on("click", function () {
    pid = $(".process_id").attr("id");
    display_sessions(evidence_id, pid);
  });

  $(".card_svcscan").on("click", function () {
    display_svcscan(evidence_id);
  });

  $(".card_credentials").on("click", function () {
    display_credentials(evidence_id);
  });

  $(".card_filescan").on("click", function () {
      display_filescan(evidence_id);
  });

  $(".card_process_dump").on("click", function () {
    $("#process_dump_modal").modal("show");
  });

  $("#dump_process_pslist_btn").on("click", function () {
    pid = $(".process_id").attr("id");
    $("#process_dump_modal").modal("hide");
    dump_process_pslist(evidence_id, pid);
  });

  $("#dump_process_memmaps_btn").on("click", function () {
    pid = $(".process_id").attr("id");
    $("#process_dump_modal").modal("hide");
    dump_process_memmap(evidence_id, pid);
  });


  /* ======================= Injections and Rootkits ======================= */

  $(".card_malfind").on("click", function () {
    injections_rootkits_hide_all();
    display_malfind(evidence_id);
  });

  $(".card_ldrmodules").on("click", function () {
    injections_rootkits_hide_all();
    display_ldrmodules(evidence_id);
  });

  $(".card_kernel_modules").on("click", function () {
    injections_rootkits_hide_all();
    display_kernel_modules(evidence_id);
  });

  $(".card_ssdt").on("click", function () {
    injections_rootkits_hide_all();
    display_ssdt(evidence_id);
  });



  toastr.options = {
    closeButton: true,
    debug: false,
    newestOnTop: false,
    progressBar: true,
    positionClass: "toast-top-right",
    preventDuplicates: false,
    onclick: null,
    showDuration: "300",
    hideDuration: "1000",
    timeOut: "5000",
    extendedTimeOut: "1000",
    showEasing: "swing",
    hideEasing: "linear",
    showMethod: "fadeIn",
    hideMethod: "fadeOut",
  };
});


/* ======================= WebSockets Management ======================= */

function reconnectWebSocket(evidence_id) {
  toastr.info("Trying to reconnect in " + reconnectDelay / 1000 + "seconds");
  setTimeout(function () {
    connectWebSocket(evidence_id); // Call the function to connect WebSocket again
    // Increase the reconnect delay exponentially
    reconnectDelay *= 2;
  }, reconnectDelay);
}

function connectWebSocket(evidence_id) {
  const socket_volatility_tasks = new WebSocket(
    "ws://localhost:8000/ws/volatility_tasks/windows/" + evidence_id + "/"
  );

  socket_volatility_tasks.onopen = function () {
    toastr.success("Engine Synchronized.");
    reconnectDelay = 1000;
  };

  socket_volatility_tasks.onmessage = function (e) {
    result = JSON.parse(e.data);
    switch(result.message.name){
      case "handles":
        handles_task_result(result.message);
        break;
      case "pslist_dump":
        pslist_dump_task_result(result.message);
      case "memmap_dump":
        process_dump_task_result(result.message);
        break;
      default:
        break;
    }
  };

  socket_volatility_tasks.onclose = function () {
    toastr.warning("Engine synchronization lost.");
    reconnectWebSocket($(".main").attr("id")); // Call the function to reconnect after connection is closed
  };

  socket_volatility_tasks.onerror = function (error) {
    toastr.warning("Engine synchronization error", error);
    socket_volatility_tasks.close(); // Close the WebSocket connection if an error occurs
  };
}
