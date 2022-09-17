function Tag(url, plugin_name, artifact_id, status){
  const csrf = document.getElementsByName('csrfmiddlewaretoken');
  const fd = new FormData();
  fd.append('csrfmiddlewaretoken', csrf[0].value);
  fd.append('plugin_name', plugin_name);
  fd.append('artifact_id', artifact_id);
  fd.append('status', status);
  $.ajax({
    type:'POST',
    url: url,
    enctype: 'multipart/form-data',
    data: fd,
    beforeSend: function(){

    },
    success: function(data){
      if(status == "Evidence"){
          $('.tag_evidence_'+artifact_id+"_"+plugin_name).removeClass("d-none");
          $('.tag_suspicious_'+artifact_id+"_"+plugin_name).addClass("d-none");
      }
      if(status == "Suspicious"){
          $('.tag_suspicious_'+artifact_id+"_"+plugin_name).removeClass("d-none");
          $('.tag_evidence_'+artifact_id+"_"+plugin_name).addClass("d-none");
      }
      if(status == "Clear"){
        $('.tag_suspicious_'+artifact_id+"_"+plugin_name).addClass("d-none");
        $('.tag_evidence_'+artifact_id+"_"+plugin_name).addClass("d-none");
      }
    },
    error: function(error){
      $('#proc-error-message').html("Could not tag the artifact.");
      $('.toast-proc-error').toast('show');
    },
    cache: false,
    contentType : false,
    processData: false
  });
  event.preventDefault();
}

function GetReport(url, case_id){
  const csrf = document.getElementsByName('csrfmiddlewaretoken');
  const fd = new FormData();
  fd.append('csrfmiddlewaretoken', csrf[0].value);
  fd.append('case_id', case_id);
  $.ajax({
    type:'POST',
    url: url,
    enctype: 'multipart/form-data',
    data: fd,
    beforeSend: function(){

    },
    success: function(data){
        $('#report_content_html').html(data['html'])
        $('#report_content_text').html(data['text'])
        //We add style to the table
        $('#report_content_html table').addClass('table table-sm table-dark')
        $('#report_content_text').addClass('d-none')
        $('#report_content_html').removeClass('d-none')
    },
    error: function(error){
      $('#proc-error-message').html("Could not generate report.");
      $('.toast-proc-error').toast('show');
    },
    cache: false,
    contentType : false,
    processData: false
  });
}


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
