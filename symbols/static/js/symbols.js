var symbols;

function get_symbols() {
  $.ajax({
    url: "/api/symbols/",
    method: "GET",
    contentType: "application/json",
  }).done(function (data) {
    if ($.fn.DataTable.isDataTable("#symbols")) {
      $("#symbols").DataTable().clear().rows.add(data).draw();
    } else {
      symbols = $("#symbols").DataTable({
        rowCallback: function (row, data) {
          $(row).attr("value", data.id).attr("id", data.id);
        },
        aaData: data,
        aoColumns: [
          {
            mData: "name",
            mRender: createNameColumn,
          },
          {
            mData: "os",
            mRender: createOsColumn,
          },
          {
            mData: "description",
            mRender: createDescriptionColumn,
          },
        ],
        aLengthMenu: [
          [25, 50, 75, -1],
          [25, 50, 75, "All"],
        ],
        iDisplayLength: 25,
        searchBuilder: true,
      });
    }
    $(".dataTable").on("click", "tbody tr", function () {
      display_symbol($(this).attr("value"));
    });
    symbols.searchBuilder.container().prependTo(symbols.table().container());
    $("#loading-content").addClass("d-none");
    $("#main-content").removeClass("d-none");
  });
}

function createNameColumn(name) {
  var div = document.createElement("small");
  div.className =
    "px-1 py-1 fw-semibold text-danger-emphasis bg-danger-subtle border border-danger-subtle rounded-2 align-items-center";
  var logo = document.createElement("i");
  var code = document.createElement("code");
  logo.className = "fas fa-file m-2";
  code.textContent = name;
  div.appendChild(logo);
  div.appendChild(code);
  return div.outerHTML;
}

function createOsColumn(os) {
  var div = document.createElement("small");
  var logo = document.createElement("i");
  var span = document.createElement("span");
  if (os === "Windows") {
    div.className =
      "px-1 py-1 fw-semibold text-info-emphasis bg-info-subtle border border-info-subtle rounded-2 align-items-center";
    logo.className = "fab fa-windows m-2";
    span.className = "text-info";
  } else {
    div.className =
      "px-1 py-1 fw-semibold text-success-emphasis bg-success-subtle border border-success-subtle rounded-2 align-items-center";
    logo.className = "fab fa-linux m-2";
    span.className = "text-success";
  }
  span.textContent = os;
  div.appendChild(logo);
  div.appendChild(span);
  return div.outerHTML;
}

function createDescriptionColumn(description) {
  var div = document.createElement("small");
  div.className = "d-flex align-items-center";
  var span = document.createElement("i");
  span.className = "text-muted";
  span.textContent = description;
  div.appendChild(span);
  return div.outerHTML;
}

function display_symbol(id) {
  $.ajax({
    url: `/api/symbols/${id}`,
    type: "GET",
    contentType: "application/json",
    success: populateSymbolModal,
    error: function () {
      toastr.error("An error occurred while getting the symbol.");
    },
  });
}

function populateSymbolModal(data) {
  $("#symbol_name").text(data.name);
  $("#symbol_review_os").text(data.os);
  $("#symbol_review_description").text(data.description);
  $("#symbol_review_file").text(data.symbols_file);
  $("#modal_symbol_review").modal("show").attr("value", data.id);
}

function reconnectWebSocket() {
  toastr.info(`Trying to reconnect in ${reconnectDelay / 1000} seconds`);
  setTimeout(connectWebSocket, reconnectDelay);
  reconnectDelay *= 2;
}

function connectWebSocket() {
  $.ajax({
    url: "/websocket-url/",
    type: "GET",
    dataType: "json",
    success: initializeWebSocket,
    error: function () {
      toastr.error("Websocket error, please try again later.");
    },
  });
}

function initializeWebSocket(data) {
  var websocketUrl = `${data.websocket_url}/ws/symbols/`;
  const socket_symbols = new WebSocket(websocketUrl);
  socket_symbols.onopen = function () {
    reconnectDelay = 1000;
    get_symbols();
  };

  socket_symbols.onmessage = handleSocketMessage;
  socket_symbols.onclose = handleSocketClose;
  socket_symbols.onerror = handleSocketError;
}

function handleSocketMessage(e) {
  var result = JSON.parse(e.data);
  switch (result.status) {
    case "created":
      updateOrCreateSymbolRow(result.message);
      break;
    case "deleted":
      removeSymbolRow(result.message);
      break;
  }
}

function updateOrCreateSymbolRow(message) {
  try {
    symbols
      .row("#" + message.id)
      .data(message)
      .draw(false);
  } catch {
    symbols.row.add(message).draw(false);
  }
}

function removeSymbolRow(message) {
  try {
    symbols
      .row("#" + message.id)
      .remove()
      .draw(false);
  } catch {
    toastr.error("Could not delete the symbol, please try again.");
  }
}

function handleSocketClose() {
  toastr.warning("Synchronization lost.");
  try {
    symbols.clear().draw();
  } catch {}
  reconnectWebSocket();
}

function handleSocketError(error) {
  toastr.error("Can't connect to the server.", error);
  this.close(); // 'this' refers to the WebSocket instance
}

function delete_symbol(id) {
  setAjaxCsrfToken();
  $.ajax({
    type: "DELETE",
    url: `/api/symbols/${id}/`,
    dataType: "json",
    success: function () {
      toastr.success("ISF deleted");
    },
    error: function (xhr, status, error) {
      toastr.error(`An error occurred: ${error}`);
    },
  });
}

function setAjaxCsrfToken() {
  $.ajaxSetup({
    beforeSend: function (xhr) {
      xhr.setRequestHeader(
        "X-CSRFToken",
        document.querySelector("[name=csrfmiddlewaretoken]").value,
      );
    },
  });
}

function clear_form() {
  $("#symbol_form")[0].reset();
}

$(document).ready(function () {
  connectWebSocket();
  $("#symbol_import_loading").hide();
  $(".symbol_import").on("click", function () {
    clear_form();
    $("#symbol_form").show();
    $("#modal_symbol_import").modal("show");
  });

  $(".delete_symbol_confirmed").on("click", function () {
    const id = $("#modal_symbol_review").attr("value");
    delete_symbol(id);
    $("#modal_symbol_review").modal("hide");
  });

  $("#symbol_form").on("submit", function (e) {
    e.preventDefault();
    $("#symbol_form").hide();
    $("#symbol_import_loading").show();
    var formData = new FormData(this);
    setAjaxCsrfToken();
    $.ajax({
      url: "/api/symbols/",
      type: "POST",
      data: formData,
      contentType: false,
      processData: false,
      success: function () {
        clear_form();
        $("#modal_symbol_import").modal("hide");
        $("#symbol_import_loading").hide();
        toastr.success("Symbol uploaded successfully!");
      },
      error: function () {
        clear_form();
        $("#modal_symbol_import").modal("hide");
        toastr.warning("An error occurred while uploading the symbol.");
      },
    });
  });
});
