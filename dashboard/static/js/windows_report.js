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
