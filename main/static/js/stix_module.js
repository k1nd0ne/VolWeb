function init_stix() {
  const popoverTriggerList = document.querySelectorAll(
    '[data-bs-toggle="popover"]',
  );
  const popoverList = [...popoverTriggerList].map(
    (popoverTriggerEl) => new bootstrap.Popover(popoverTriggerEl),
  );

  $("#indicator_form").on("submit", function (e) {
    e.preventDefault();
    var formData = new FormData(this);
    setAjaxCsrfToken();
    $.ajax({
      url: "/api/stix/indicators/",
      type: "POST",
      data: formData,
      contentType: false,
      processData: false,
      success: function () {
        clear_form();
        bootstrap.Offcanvas.getInstance($("#stix_creation_canvas")).hide();
        clear_form();
        toastr.success("Indicator created successfully!");
      },
      error: function (xhr, status, error) {
        bootstrap.Offcanvas.getInstance($("#stix_creation_canvas")).hide();
        if (xhr.responseJSON.message) {
          toastr.warning(xhr.responseJSON.message);
        } else {
          toastr.warning(
            `An error occurred while creating the object : ${status}`,
          );
        }
      },
    });
  });
}

function clear_form() {
  $("#indicator_form")[0].reset();
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

function export_stix_bundle(case_id) {
  $.ajax({
    url: `/api/stix/export/${case_id}/`,
    method: "GET",
    xhrFields: {
      responseType: "blob",
    },
    success: function (data) {
      const url = window.URL.createObjectURL(new Blob([data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `stix_bundle_${case_id}.json`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    },
  });
}

function delete_indicator(indicator_id, case_id, evidence_id) {
  $.ajaxSetup({
    beforeSend: function (xhr, settings) {
      xhr.setRequestHeader(
        "X-CSRFToken",
        document.querySelector("[name=csrfmiddlewaretoken]").value,
      );
    },
  });
  $.ajax({
    type: "DELETE",
    url: `/api/stix/indicators/${indicator_id}/`,
    dataType: "json",
    success: function (data) {
      get_indicators(case_id, evidence_id);
      toastr.success("The indicator was deleted");
    },
    error: function (xhr, status, error) {
      toastr.error("Could not delete the indicator: " + error);
    },
  });
}

function get_indicators(case_id, evidence_id) {
  var url = `/api/stix/indicators/case/${case_id}/`;
  if (evidence_id) {
    url = `/api/stix/indicators/evidence/${evidence_id}/`;
  }
  $.ajax({
    url: url,
    method: "GET",
    contentType: "application/json",
  }).done(function (data) {
    $("#indicators").DataTable().destroy();
    evidences = $("#indicators").DataTable({
      rowCallback: function (row, data, index) {
        $(row).attr("value", data.id);
        $(row).attr("id", data.id);
      },
      aaData: data,
      aoColumns: [
        {
          mData: "type",
          mRender: function (value, type, row) {
            return `<div class="p-1 text-uppercase fw-semibold text-warning-emphasis border border-warning-subtle text-center"><small>${value}</small></div>`;
          },
          sClass: "align-middle",
        },
        {
          mData: "name",
          mRender: function (name, type, row) {
            small = document.createElement("span");
            small.setAttribute("class", "text-muted align-middle");
            small.textContent = name;
            return small.outerHTML;
          },
          sClass: "align-middle",
        },
        {
          mData: "description",
          mRender: function (description, type, row) {
            small = document.createElement("div");
            small.setAttribute("class", "text-muted align-middle");
            small.textContent = description;
            return small.outerHTML;
          },
          sClass: "align-middle",
        },
        {
          mData: "value",
          mRender: function (value, type, row) {
            code = document.createElement("div");
            code.setAttribute("class", "text-danger text-break align-middle");
            code.textContent = value;
            return code.outerHTML;
          },
          sClass: "align-middle",
        },
        {
          mData: "dump_linked_dump_name",
          mRender: function (dump_linked_dump_name, type) {
            span = document.createElement("span");
            span.setAttribute("class", "align-middle");
            span.textContent = dump_linked_dump_name;
            return span.outerHTML;
          },
          sClass: "align-middle",
        },
        {
          mData: "id",
          mRender: function (id, type, row) {
            return `<button id=${id} class="btn btn-sm btn-danger align-middle remove-indicator">remove</button>`;
          },
          sClass: "align-middle",
        },
      ],
      aLengthMenu: [
        [25, 50, 75, -1],
        [25, 50, 75, "All"],
      ],
      iDisplayLength: 25,
      searchBuilder: false,
    });
    $(".remove-indicator").on("click", function (e) {
      delete_indicator(this.id, case_id, evidence_id);
    });
  });
}
