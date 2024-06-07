$(document).ready(function () {
  $("#loading-content").addClass("d-none");
  $("#main-content").removeClass("d-none");
  const case_id = $("#case").attr("value");
  connectWebSocket(case_id);
  get_indicators(case_id, null);

  $("#upload-button").on("click", function () {
    const evidence_name = $("#id_dump_name").val();
    const evidence_os = $("#id_dump_os").val();
    const linked_case_id = $("#id_dump_linked_case").val();

    if (evidence_name === "") {
      $("#form-error").text("Please enter a name for the evidence.");
      return;
    }

    if (evidence_os === "") {
      $("#form-error").text("Please select an os for this evidence");
      return;
    }

    if (linked_case_id === "") {
      $("#form-error").text("Please select a linked case.");
      return;
    }
    $("#form-error").text("");

    $.ajax({
      type: "GET",
      url: "/api/cases/" + linked_case_id + "/",
      dataType: "json",
      success: function (data) {
        const bucket_name = data.case_bucket_id;
        upload_and_create_evidence(bucket_name);
      },
      error: function (xhr, status, error) {
        toastr.error("An error occurred : " + error);
      },
    });
  });

  $(".evidence_bind").on("click", function () {
    $("#modal_evidence_bind").modal("show");
  });

  $("#bind-button").on("click", function () {
    const evidence_name = $("#id_bind_dump_name").val();
    const evidence_os = $("#id_bind_dump_os").val();
    const dump_source = $("#id_bind_dump_source").val();
    const dump_access_key_id = $("#id_bind_dump_access_key_id").val();
    const dump_access_key = $("#id_bind_dump_access_key").val();
    const dump_region = $("#id_bind_dump_region").val();
    const dump_url = $("#id_bind_dump_url").val();
    const dump_endpoint = $("#id_bind_dump_endpoint").val();

    var formData = {
      dump_name: evidence_name,
      dump_os: evidence_os,
      dump_name: evidence_name,
      dump_access_key_id: dump_access_key_id,
      dump_access_key: dump_access_key,
      dump_endpoint: dump_endpoint,
      dump_source: dump_source,
      dump_linked_case: case_id,
      dump_url: dump_url,
      dump_region: dump_region,
    };

    if (evidence_name === "") {
      $("#form-bind-error").text("Please enter a name for the evidence.");
      return;
    }

    if (evidence_os === "") {
      $("#form-bind-error").text("Please select an os for this evidence");
      return;
    }

    if (dump_source === "") {
      $("#form-bind-error").text("Please select a data source.");
      return;
    }

    if (dump_access_key_id === "") {
      $("#form-bind-error").text("Please enter the access key id");
      return;
    }

    if (dump_access_key === "") {
      $("#form-bind-error").text("Please enter the access key.");
      return;
    }

    if (dump_endpoint === "" && dump_source === "MINIO") {
      $("#form-bind-error").text("Please enter the endpoint of MinIO.");
      return;
    }

    if (dump_region === "" && dump_source === "AWS") {
      $("#form-bind-error").text("Please enter the AWS region.");
      return;
    }

    if (dump_url === "") {
      $("#form-bind-error").text("Please enter the url of your evidence.");
      return;
    }
    $("#form-bind-error").text("");
    bind_and_create_evidence(formData);
  });

  $("#id_bind_dump_source").on("change", function () {
    if (this.value === "AWS") {
      $("#aws-region-form").attr("class", "mb-3");
      $("#minio-endpoint-form").attr("class", "d-none");
    }
    if (this.value === "MINIO") {
      $("#aws-region-form").attr("class", "d-none");
      $("#minio-endpoint-form").attr("class", "mb-3");
    }
  });

  $("#delete_evidence").on("click", function () {
    $(".modal_evidence_review").modal("hide");
    $(".modal_evidence_delete").modal("show");
  });

  $("#restart_analysis").on("click", function () {
    const evidence_id = $(".modal_evidence_review").attr("id");
    start_analysis(evidence_id, case_id);
    $(".modal_evidence_review").modal("hide");
  });

  $("#delete_evidence_confirmed").on("click", function () {
    clear_form();
    const evidence_id = $(".modal_evidence_review").attr("id");
    delete_evidence(evidence_id);
    $(".modal_evidence_delete").modal("hide");
  });

  $("#review_evidence").on("click", function () {
    const evidence_id = $(".modal_evidence_review").attr("id");
    const os = $(".modal_evidence_review").attr("value").toLowerCase();
    window.location.href = `/review/${os}/${evidence_id}/`;
  });

  $(".evidence_create").on("click", function () {
    $("#modal_evidence_create").modal("show");
  });

  $(".stix_bundle_create").on("click", function () {
    export_stix_bundle(case_id);
  });

  $("#modal_evidence_create").on("hide.bs.modal", function () {
    clear_form();
  });

  $("#evidences").on("click", "tbody tr", function () {
    if (!$(this).hasClass("not-completed")) {
      display_evidence($(this).attr("value"));
    }
  });
});
