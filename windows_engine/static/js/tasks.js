function compute_handles(evidence_id, pid) {
  $.ajax({
    type: "GET",
    url: `${tasksURL}/${evidence_id}/handles/${pid}/`,
    dataType: "json",
    beforeSend: function () {},
    success: function (data, status, xhr) {
      if (xhr.status === 201) {
        toastr.info("Computing handles for " + pid);
        $(".card_handles").hide();
        $(".loading_handles").show();
      }
      if (xhr.status === 200) {
        $("#artefacts_datatable").DataTable().destroy();
        $("#artefacts_body").html(
          `<table id="artefacts_datatable" class="table-sm table-responsive table-hover table" cellspacing="0" width="100%"
            >
                    <thead>
                        <tr>
                          <th>Process</th>
                          <th>Name</th>
                          <th>HandleValue</th>
                          <th>GrantedAccess</th>
                          <th>Type</th>
                        </tr>
                    </thead>
                </table>`,
        );
        artefacts_datatable = $("#artefacts_datatable").DataTable({
          aaData: data,
          aoColumns: [
            { data: "Process" },
            { data: "Name" },
            { data: "HandleValue" },
            { data: "GrantedAccess" },
            { data: "Type" },
          ],
          aLengthMenu: [
            [25, 50, 75, -1],
            [25, 50, 75, "All"],
          ],
          iDisplayLength: 25,
          searchBuilder: true,
        });
        artefacts_datatable.searchBuilder
          .container()
          .prependTo(artefacts_datatable.table().container());
        $("#artefacts_modal").modal("show");
      }
    },
    complete: function (data) {},
    error: function (xhr, status, error) {
      if (xhr.status === 408) {
        toastr.error("The worker is unavailable, please try again later.");
      } else {
        toastr.error(`An error occured : ${xhr.status}`);
      }
    },
  });
}

function dump_process_pslist(evidence_id, pid) {
  $.ajax({
    type: "GET",
    url: "/tasks/windows/" + evidence_id + "/dump/" + pid + "/pslist/",
    dataType: "json",
    beforeSend: function () {},
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
    complete: function (data) {},
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
    beforeSend: function () {},
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
    complete: function (data) {},
    error: function (xhr, status, error) {
      toastr.error("An error occurred while dumping the process : " + error);
    },
  });
}

function dump_file(evidence_id, file_id) {
  $.ajax({
    type: "GET",
    url: "/tasks/windows/" + evidence_id + "/dump/" + file_id + "/filescan/",
    dataType: "json",
    beforeSend: function () {},
    success: function (data, status, xhr) {
      if (xhr.status === 201) {
        toastr.info("Trying to dump your file");
      }
    },
    complete: function (data) {},
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
  if (result.pid == $(".process_id").attr("id")) {
    $(".card_handles").show();
    $(".loading_handles").hide();
  }
}

function filedump_task_result(result) {
  if (result.status === "success" || result.status === "failed") {
    loot = JSON.parse(result.msg);
    if (loot.Status) {
      toastr.success(
        "File " + loot.FileName + " is available in the Loot section.",
      );
    } else {
      toastr.error(loot.Name);
    }
    loot_datatable.row.add(loot).draw().node();
  } else {
    toastr.error("The task failed for unknown reason.");
  }
}

function process_dump_task_result(result) {
  if (result) {
    if (result.status === "success") {
      loot = JSON.parse(result.msg);
      toastr.success(
        "Process dump for pid " +
          result.pid +
          " is available in the Loot section.",
      );
    }
    if (result.status === "error") {
      loot = JSON.parse(result.msg);
      toastr.warning("Process dump for pid " + result.pid + " failed.");
    }
    if (result.pid == $(".process_id").attr("id")) {
      $(".card_process_dump").show();
      $(".loading_process_dump").hide();
    }
    loot_datatable.row.add(loot).draw().node();
  }
}
