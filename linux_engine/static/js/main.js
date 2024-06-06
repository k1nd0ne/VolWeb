const baseURL = "/api/linux";
const tasksURL = "/tasks/linux";
$(document).ready(function () {
  evidence_id = $(".main").attr("id");
  reconnectDelay = 1000; // milliseconds
  connectWebSocket(evidence_id);
  display_pstree(evidence_id);
  display_timeline(evidence_id);
  init_stix();

  $(".btn-show-indicators").on("click", function () {
    get_indicators($("#case").attr("value"), evidence_id);
  });
  $("#loading-content").addClass("d-none");
  $("#main-content").removeClass("d-none");
  /* ======================= Overview ======================= */

  $(".card_psscan").on("click", function () {
    display_psscan(evidence_id);
  });

  $(".card_library_list").on("click", function () {
    display_library_list(evidence_id);
  });

  $(".card_bash").on("click", function () {
    display_bash(evidence_id);
  });

  $(".card_kmsg").on("click", function () {
    display_kmsg(evidence_id);
  });

  $(".card_mount_info").on("click", function () {
    display_mount_info(evidence_id);
  });

  $(".card_lsof").on("click", function () {
    pid = $(".process_id").attr("id");
    display_lsof(evidence_id, pid);
  });

  $(".card_elfs").on("click", function () {
    pid = $(".process_id").attr("id");
    display_elfs(evidence_id, pid);
  });

  $(".card_envars").on("click", function () {
    pid = $(".process_id").attr("id");
    display_envars(evidence_id, pid);
  });

  $(".card_capabilities").on("click", function () {
    pid = $(".process_id").attr("id");
    display_capabilities(evidence_id, pid);
  });

  $(".card_network").on("click", function () {
    display_network(evidence_id);
  });

  $(".card_tty_check").on("click", function () {
    display_tty_check(evidence_id);
  });

  /* ======================= Injections and Rootkits ======================= */

  $(".card_malfind").on("click", function () {
    injections_rootkits_hide_all();
    display_malfind(evidence_id);
  });

  $(".card_lsmod").on("click", function () {
    injections_rootkits_hide_all();
    display_lsmod(evidence_id);
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
  $.ajax({
    url: "/websocket-url/", // Adjust this if your URL is different
    type: "GET",
    dataType: "json",
    success: function (data) {
      // Retrieve the WebSocket URL from the response
      var websockurl = `${data.websocket_url}/ws/volatility_tasks/windows/${evidence_id}/`;
      const socket_volatility_tasks = new WebSocket(websockurl);
      socket_volatility_tasks.onopen = function () {
        toastr.success("Engine Synchronized.");
        reconnectDelay = 1000;
      };
      socket_volatility_tasks.onmessage = function (e) {
        result = JSON.parse(e.data);
        switch (result.message.name) {
          case "handles":
            handles_task_result(result.message);
            break;
          case "pslist_dump":
            process_dump_task_result(result.message);
            break;
          case "memmap_dump":
            process_dump_task_result(result.message);
            break;
          case "file_dump":
            filedump_task_result(result.message);
            break;
          default:
            break;
        }
      };

      socket_volatility_tasks.onclose = function () {
        toastr.warning("Engine synchronization lost.");
        reconnectWebSocket(evidence_id); // Call the function to reconnect after connection is closed
      };

      socket_volatility_tasks.onerror = function (error) {
        toastr.warning("Engine synchronization error", error);
        socket_volatility_tasks.close(); // Close the WebSocket connection if an error occurs
      };
    },
    error: function (xhr, status, error) {
      // Handle any errors here
      console.error("Error fetching WebSocket URL:", xhr.responseText);
    },
  });
}
