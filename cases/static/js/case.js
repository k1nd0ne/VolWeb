$(document).ready(function () {
  $("#loading-content").addClass("d-none");
  $("#main-content").removeClass("d-none");
  case_id = $("#case").attr("value");
  connectWebSocket(case_id);
  get_indicators(case_id);
});
