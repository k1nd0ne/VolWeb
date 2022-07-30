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


  function DownloadHive(filename){
      const csrf = document.getElementsByName('csrfmiddlewaretoken');
      const fd = new FormData();
      fd.append('csrfmiddlewaretoken', csrf[0].value);
      fd.append('filename', filename);
      $.ajax({
        type:'POST',
        url: "{% url 'download_hive' %}",
        enctype: 'multipart/form-data',
        data: fd,
        beforeSend: function(){
          $('#proc-message').html("Requesting download...");
          $('.toast-proc').toast('show');
        },
        success: function(data){
          //Convert the Byte Data to BLOB object.
                    var blob = new Blob([data], { type: "application/octetstream" });
                    //Check the Browser type and download the File.
                    var isIE = false || !!document.documentMode;
                    if (isIE) {
                        window.navigator.msSaveBlob(blob, filename);
                    } else {
                        var url = window.URL || window.webkitURL;
                        link = url.createObjectURL(blob);
                        var a = $("<a />");
                        a.attr("download", filename);
                        a.attr("href", link);
                        $("body").append(a);
                        a[0].click();
                        $("body").remove(a);
                    }
        },
        error: function(error){
          $('#proc-error-message').html("Download failed ! :(");
          $('.toast-proc-error').toast('show');
        },
        cache: false,
        contentType : false,
        processData: false
      });
  }


    /* ################################ TIMELINE SCRIPTS ################################ */
  $("#searchTimeline").on("keyup", function() {
    var value = $(this).val().toLowerCase();
    $("#TimelineTab tr").filter(function() {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) !== -1)
    })
  });


    /* ################################ FILES SCRIPTS ################################ */
  //FileScan SearchBar
  $("#search_files").on("keyup", function() {
    var value = $(this).val().toLowerCase();
    $("#FileScanTab tr").filter(function() {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });



});
