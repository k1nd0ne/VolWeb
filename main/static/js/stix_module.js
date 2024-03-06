function init_stix() {
  const popoverTriggerList = document.querySelectorAll(
    '[data-bs-toggle="popover"]',
  );
  const popoverList = [...popoverTriggerList].map(
    (popoverTriggerEl) => new bootstrap.Popover(popoverTriggerEl),
  );

  $(".indicator-form-select").change(function () {
    var selectedType = $(this).val();
    $("#indicator_form").hide();
    $("#observed_data_form").hide();
    if (selectedType === "indicator") {
      $("#indicator_form").show();
    } else if (selectedType === "observed_data") {
      $("#observed_data_form").show();
    }
  });

  $("#indicator_form").on("submit", function (e) {
    e.preventDefault();
    var formData = new FormData(this);
    setAjaxCsrfToken();
    $.ajax({
      url: "/api/stix/indicator/",
      type: "POST",
      data: formData,
      contentType: false,
      processData: false,
      success: function () {
        clear_form();
        $("#stix_modal").modal("hide");
        clear_form();
        toastr.success("Indicator created successfully!");
      },
      error: function () {
        clear_form();
        $("#modal_symbol_import").modal("hide");
        toastr.warning("An error occurred while uploading the symbol.");
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

function get_indicators(case_id) {
  $.ajax({
    url: `/api/stix/indicators/case/${case_id}/`,
    method: "GET",
    contentType: "application/json",
  }).done(function (data) {
    console.log(data);
    $("#indicators").DataTable().destroy();
    evidences = $("#indicators").DataTable({
      rowCallback: function (row, data, index) {
        // $(row).attr("value", data.dump_id);
        // $(row).attr("id", data.dump_id);
      },
      aaData: data,
      aoColumns: [
        {
          mData: "type",
          mRender: function (value, type, row) {
            return `<div class="p-1 text-uppercase fw-semibold text-warning-emphasis border border-warning-subtle text-center"><small>${value}</small></div>`;
          },
        },
        {
          mData: "description",
          mRender: function (dump_etag, type, row) {
            small = document.createElement("div");
            small.setAttribute("class", "text-truncate text-muted");
            small.setAttribute("style", "max-width: 150px");
            small.textContent = dump_etag;
            return small.outerHTML;
          },
        },
        {
          mData: "value",
          mRender: function (value, type, row) {
            code = document.createElement("div");
            code.setAttribute("class", "text-truncate text-danger");
            code.setAttribute("style", "max-width: 300px");
            code.textContent = value;
            return code.outerHTML;
          },
        },
        {
          mData: "tlp",
          mRender: function (tlp, type, row) {
            let tlpDiv = document.createElement("div");
            let tlpSpan = document.createElement("span");
            tlpSpan.textContent = tlp.toUpperCase();
            tlpDiv.appendChild(tlpSpan);

            switch (tlp.toLowerCase()) {
              case "red":
                tlpDiv.className =
                  "px-0 py-0 fw-semibold text-center text-danger-emphasis bg-danger-subtle border border-danger-subtle rounded-2";
                tlpSpan.className = "text-danger ";
                break;
              case "amber":
                tlpDiv.className =
                  "px-0 py-0 fw-semibold text-center text-warning-emphasis bg-warning-subtle border border-warning-subtle rounded-2";
                tlpSpan.className = "text-warning";
                break;
              case "amber+strict":
                tlpDiv.className =
                  "px-0 py-0 fw-semibold text-center text-warning-emphasis bg-warning-subtle border border-warning-subtle rounded-2";
                tlpSpan.className = "text-warning";
                break;
              case "green":
                tlpDiv.className =
                  "px-0 py-0 fw-semibold text-center text-success-emphasis bg-success-subtle border border-success-subtle rounded-2";
                tlpSpan.className = "text-success";
                break;
              case "white":
                tlpDiv.className =
                  "px-0 py-0 fw-semibold text-center text-white-emphasis bg-white-subtle border border-white-subtle rounded-2";
                tlpSpan.className = "text-white";
                break;
              default:
                tlpDiv.className =
                  "px-0 py-0 fw-semibold text-center text-secondary-emphasis bg-secondary-subtle border border-secondary-subtle rounded-2";
                tlpSpan.className = "text-secondary";
                break;
            }
            return tlpDiv.outerHTML;
          },
        },
        {
          mData: "dump_linked_dump_name",
          mRender: function (dump_linked_dump_name, type) {
            span = document.createElement("span");
            span.textContent = dump_linked_dump_name;
            return span.outerHTML;
          },
        },
      ],
      aLengthMenu: [
        [25, 50, 75, -1],
        [25, 50, 75, "All"],
      ],
      iDisplayLength: 25,
      searchBuilder: false,
    });
  });
}
