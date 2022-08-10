$("#searchElfs").on("keyup", function() {
  var value = $(this).val().toLowerCase();
  $("#Elfs tr").filter(function() {
    $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
  });
});

$("#searchBash").on("keyup", function() {
  var value = $(this).val().toLowerCase();
  $("#Bash tr").filter(function() {
    $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
  });
});

$("#searchProcessMaps").on("keyup", function() {
  var value = $(this).val().toLowerCase();
  $("#processMaps tr").filter(function() {
    $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
  });
});

$("#searchLsof").on("keyup", function() {
  var value = $(this).val().toLowerCase();
  $("#Lsof tr").filter(function() {
    $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
  });
});

$("#searchTtyCheck").on("keyup", function() {
  var value = $(this).val().toLowerCase();
  $("#TtyCheck tr").filter(function() {
    $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
  });
});
