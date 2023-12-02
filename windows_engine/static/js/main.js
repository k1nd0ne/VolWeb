$(document).ready(function () {
  const evidence_id = $(".main").attr("id");
  var timeline_data;
  let reconnectDelay = 1000; // milliseconds

  connectWebSocket(evidence_id);

  display_pstree(evidence_id);
  display_timeline(evidence_id);

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

  $(".card_credentials").on("click", function () {
    display_credentials(evidence_id);
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

  // toastr.warning('Your toast message here');
  // toastr.error('Your toast message here');
  // toastr.success('Your Toast message here', 'Title');
});

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
    "ws://192.168.1.25:8000/ws/volatility_tasks/windows/" + evidence_id + "/"
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
    socket_alerte_modified.close(); // Close the WebSocket connection if an error occurs
  };
}
