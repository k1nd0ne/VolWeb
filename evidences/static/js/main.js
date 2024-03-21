$(document).ready(function () {
  connectWebSocket(null);
  $("#upload-button").on("click", function () {
    // First we go an fetch the uuid of the bucket associated with the case selected by the user.
    const evidence_name = $("#id_dump_name").val();
    const evidence_os = $("#id_dump_os").val();
    const linked_case_id = $("#id_dump_linked_case").val();

    //Check if the user selected a case.
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
        //Ok we have the bucket uuid we can try to upload the file to the bucket.
        upload_and_create_evidence(bucket_name);
      },
      error: function (xhr, status, error) {
        toastr.error("An error occurred : " + error);
      },
    });
  });

  $("#delete_evidence").on("click", function () {
    $(".modal_evidence_review").modal("hide");
    $(".modal_evidence_delete").modal("show");
  });

  $("#restart_analysis").on("click", function () {
    const evidence_id = $(".modal_evidence_review").attr("id");
    start_analysis(evidence_id);
    get_evidences();
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

  $("#modal_evidence_create").on("hide.bs.modal", function () {
    clear_form();
  });

  $("#evidences").on("click", "tbody tr", function () {
    if (!$(this).hasClass("not-completed")) {
      display_evidence($(this).attr("value"));
    }
  });
});
