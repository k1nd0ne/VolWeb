function display_loot(evidence_id) {
  $.ajax({
    type: "GET",
    url: "/api/windows/" + evidence_id + "/loot/",
    dataType: "json",
    success: function (data) {
      try {
        loot_datatable.destroy();
      } catch {
        //Nothing to do, the datatable will be created.
      }
      try {
        loot_datatable = $("#loot_datatable").DataTable({
          aaData: data,
          aoColumns: [
            { data: "Name" },
            {
              mData: "Status",
              mRender: function (status, type, row) {
                return generate_loot_status(status);
              },
            },
            {
              mData: "id",
              mRender: function (id, type, row) {
                return "BTN DOWNLOAD HERE"
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
        loot_datatable.searchBuilder.container().prependTo(loot_datatable.table().container());
      } catch {
        toastr.error("The loot table cannot be displayed");
      }
    },
    error: function (xhr, status, error) {
      toastr.error("An error occurred : " + error);
    },
  });
}

function generate_loot_status(status){
  message = document.createElement('code');
  if(status){
    message.setAttribute('class', 'text-success');
    message.textContent = "The task was completed with success.";
  }
  else{
    message.setAttribute('class', 'text-danger');
    message.textContent = "The task did not complete. The data you are trying to recover are probably freed.";
  }
  return message.outerHTML;
}
