function compute_handles(evidence_id, pid) {
  $.ajax({
    type: "GET",
    url: "/tasks/windows/" + evidence_id + "/handles/" + pid + "/",
    dataType: "json",
    beforeSend: function () { },
    success: function (data, status, xhr) {
      if (xhr.status === 201) {
        toastr.info("Computing handles for " + pid);
        $(".card_handles").hide();
        $(".loading_handles").show();
      }
      if (xhr.status === 200) {
        try {
          handles_data.destroy();
        } catch {
          //Nothing to do, the datatable will be created.
        }
        try {
          handles_data = $("#handles_datatable").DataTable({
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
            searchBuilder: true,
          });
          handles_data.searchBuilder.container().prependTo(handles_data.table().container());
        } catch {
          toastr.warning("An error occured when loading data for 'handles'.");
        }
        $("#handles_datatable").show("fast");
        $(".card_handles").show();
        $(".loading_handles").hide();
        $("#handles").modal("show");
      }
    },
    complete: function (data) { },
    error: function (xhr, status, error) {
      toastr.error("An error occurred while computing the handles : " + error);
    },
  });
}


function dump_process_pslist(evidence_id, pid) {
  $.ajax({
    type: "GET",
    url: "/tasks/windows/" + evidence_id + "/dump/" + pid + "/pslist/",
    dataType: "json",
    beforeSend: function () { },
    success: function (data, status, xhr) {
      if (xhr.status === 201) {
        toastr.info("Trying to dump process for pid " + pid);
        $(".card_process_dump").hide();
        $(".loading_process_dump").show();
      }
      if (xhr.status === 200) {
        $(".card_process_dump").show();
        $(".loading_process_dump").hide();
        // Launch download now
        alert("Now is the time for download");
      }
    },
    complete: function (data) { },
    error: function (xhr, status, error) {
      toastr.error("An error occurred while dumping the process : " + error);
    },
  });
}


function dump_process_memmap(evidence_id, pid) {
  $.ajax({
    type: "GET",
    url: "/tasks/windows/" + evidence_id + "/dump/" + pid + "/memmap/",
    dataType: "json",
    beforeSend: function () { },
    success: function (data, status, xhr) {
      if (xhr.status == 201) {
        toastr.info("Trying to dump process for pid " + pid);
        $(".card_process_dump").hide();
        $(".loading_process_dump").show();
      }
      if (xhr.status == 200) {
        $(".card_process_dump").show();
        $(".loading_process_dump").hide();
        // Launch download now
        alert("Now is the time for download");
      }
    },
    complete: function (data) { },
    error: function (xhr, status, error) {
      toastr.error("An error occurred while dumping the process : " + error);
    },
  });
}


function dump_file(evidence_id, file_id) {
  console.log(file_id)
  $.ajax({
    type: "GET",
    url: "/tasks/windows/" + evidence_id + "/dump/" + file_id + "/filescan/",
    dataType: "json",
    beforeSend: function () { },
    success: function (data, status, xhr) {
      if (xhr.status === 201) {
        toastr.info("Trying to dump your file");
      }
    },
    complete: function (data) { },
    error: function (xhr, status, error) {
      toastr.error("An error occurred while dumping your file : " + error);
    },
  });
}


function handles_task_result(result) {
  if (result.status === "success") {
    toastr.info(result.msg);
  } else {
    toastr.warning(result.msg);
  }
  if (result.pid === $(".process_id").attr("id")) {
    $(".card_handles").show();
    $(".loading_handles").hide();
  }
}

function filedump_task_result(result) {
  if (result.status === "success" || result.status === "failed") {
    loot = JSON.parse(result.msg);
    if (loot.Status) {
      toastr.success('File ' + loot.FileName + ' is available in the Loot section.');
    }
    else {
      toastr.error(loot.Name);
    }

    try {
      loot_datatable.row("#" + loot.id).data(loot);
    }
    catch {
      loot_datatable.row.add(loot).draw().node();
    }
  } else {
    toastr.warning(result.msg);
  }
}


function process_dump_task_result(result) {
  if (result.status === "success") {
    loot = JSON.parse(result.msg);
    toastr.success('Process dump for pid ' + result.pid + ' is available in the Loot section.');
  }
  else {
    toastr.warning('Process dump for pid ' + result.pid + ' failed.');
  }
  try {
    loot_datatable.row("#" + loot.id).data(loot);
  }
  catch {
    loot_datatable.row.add(loot).draw().node();
  }
  if (result.pid === $(".process_id").attr("id")) {
    $(".card_process_dump").show();
    $(".loading_process_dump").hide();
  }
}
