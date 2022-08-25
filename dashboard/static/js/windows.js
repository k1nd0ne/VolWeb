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
          $('.tag_evidence_'+artifact_id).removeClass("d-none");
          $('.tag_suspicious_'+artifact_id).addClass("d-none");
      }
      if(status == "Suspicious"){
          $('.tag_suspicious_'+artifact_id).removeClass("d-none");
          $('.tag_evidence_'+artifact_id).addClass("d-none");
      }
      if(status == "Clear"){
        $('.tag_suspicious_'+artifact_id).addClass("d-none");
        $('.tag_evidence_'+artifact_id).addClass("d-none");
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


$(document).ready(function(){
  $('.plugin').hide();
  $('.toast-other').toast('show');

  var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
  var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
    return new bootstrap.Tooltip(tooltipTriggerEl)
  })

  /* ################################ REGISTRY SCRIPTS ################################ */

  $("#search_registry").on("keyup", function() {
    var value = $(this).val().toLowerCase();
    $("#UserAssist tr").filter(function() {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });

  //TimeLine SearchBar
  $("#searchTimeline").on("keyup", function() {
    var value = $(this).val().toLowerCase();
    $("#TimelineTab tr").filter(function() {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) !== -1)
    })
  });

  //FileScan SearchBar
  $("#search_files").on("keyup", function() {
    var value = $(this).val().toLowerCase();
    $("#FileScanTab tr").filter(function() {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });


  //CmdLine SearchBar
  $("#searchCmdLine").on("keyup", function() {
    var value = $(this).val().toLowerCase();
    $("#cmdline tr").filter(function() {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });

  //CmdLine SearchBar
  $("#searchDllList").on("keyup", function() {
    var value = $(this).val().toLowerCase();
    $("#dlllist tr").filter(function() {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });

  //Privileges SearchBar
  $("#searchPriv").on("keyup", function() {
    var value = $(this).val().toLowerCase();
    $("#processPriv tr").filter(function() {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });

  //Process Env SearchBar

  $("#searchEnv").on("keyup", function() {
    var value = $(this).val().toLowerCase();
    $("#processEnv tr").filter(function() {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });


  //Process Handles SearchBar

  $("#searchHandles").on("keyup", function() {
    var value = $(this).val().toLowerCase();
    $("#processHandles tr").filter(function() {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });


  //NetStat Search funtion
  $("#searchNetworkStat").on("keyup", function() {
      var value = $(this).val().toLowerCase();
      $("#netstat tr").filter(function() {
        $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
      });
    });

  //NetStat Search funtion
  $("#searchNetworkScan").on("keyup", function() {
      var value = $(this).val().toLowerCase();
      $("#netscan tr").filter(function() {
        $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
      });
    });

});
