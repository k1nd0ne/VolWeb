function compute_handles(evidence_id, pid) {
  $.ajax({
    type: "GET",
    url: "/tasks/windows/" + evidence_id + "/handles/" + pid + "/",
    dataType: "json",
    beforeSend: function () {},
    success: function (data, status, xhr) {
      if (xhr.status == 201) {
        toastr.info("Computing handles for " + pid);
        $(".card_handles").hide();
        $(".loading_handles").show();
      }
      if (xhr.status == 200) {
        try {
          handles_data.api().destroy();
        } catch {
          //Nothing to do, the datatable will be created.
        }
        try {
          handles_data = $("#handles_datatable").dataTable({
            aaData: data,
            aoColumns: [
              { data: "Process" },
              { data: "Name" },
              { data: "HandleValue" },
              { data: "GrantedAccess" },
              { data: "Type" },
              {
                mData: "id",
                mRender: function (id, type, row) {
                  return generate_tag("handles", row);
                },
              },
            ],
            aLengthMenu: [
              [25, 50, 75, -1],
              [25, 50, 75, "All"],
            ],
            iDisplayLength: 25,
          });
        } catch {
          toastr.warning("An error occured when loading data for 'handles'.");
        }
        $("#handles_datatable").show("fast");
        $(".card_handles").show();
        $(".loading_handles").hide();
        $("#handles").modal("show");
      }
    },
    complete: function (data) {},
    error: function (xhr, status, error) {
      toastr.error("An error occurred while computing the handles : " + error);
    },
  });
}

function handles_task_result(result) {
  if (result.status == "success") {
    toastr.info(result.msg);
  } else {
    toastr.warning(result.msg);
  }
  if (result.pid == $(".process_id").attr("id")) {
    $(".card_handles").show();
    $(".loading_handles").hide();
  }
}
