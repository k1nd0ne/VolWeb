function Tag(plugin_name, artifact_id, status){
  var url = $("#tabs").attr("data-url");
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

$("#searchSockstat").on("keyup", function() {
  var value = $(this).val().toLowerCase();
  $("#Sockstat tr").filter(function() {
    $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
  });
});

$("#searchEnvars").on("keyup", function() {
  var value = $(this).val().toLowerCase();
  $("#envars tr").filter(function() {
    $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
  });
});

function DisplayArtifacts(collapse, process, case_id) {
  const span_loading = document.createElement("span"); 
  span_loading.setAttribute('class','spinner-border spinner-border-sm');
  span_loading.setAttribute('role','status');
  $("#procmaps_btn").removeClass("d-none");
  const procmaps_btn = document.getElementById("procmaps_btn"); 
  procmaps_btn.textContent = "Click here to compute ProcMaps for PID " + process;
  procmaps_btn.addEventListener('click', function (e) {
    $("#processHandles").textContent = "";
     procmaps_btn.textContent = "";
     procmaps_btn.appendChild(span_loading);
     ComputeProcMaps(process, case_id);
  });



  if ($('#' + collapse).attr("aria-expanded") == "true") {
    $('.spinner-review').removeClass("d-none");
    var url = $("#" + collapse).attr('data-url');
    $.get(url, { 'case': case_id, 'pid': process }, // url
      function (response, textStatus, jqXHR) {  // success callback
        if (textStatus == "success") {
          if (response['message'] == "success") {
            //FillPsAux(JSON.parse(response['artifacts']['PsAux']));
            FillArtifiacts(JSON.parse(response['artifacts']['PsAux']), 'PsAux');
            FillArtifiacts(JSON.parse(response['artifacts']['Bash']), 'Bash');
            FillArtifiacts(JSON.parse(response['artifacts']['Elfs']), 'Elfs');
            FillArtifiacts(JSON.parse(response['artifacts']['Lsof']), 'Lsof');
            FillArtifiacts(JSON.parse(response['artifacts']['ProcMaps']),'ProcMaps');
            FillArtifiacts(JSON.parse(response['artifacts']['Sockstat']),'Sockstat');
            FillArtifiacts(JSON.parse(response['artifacts']['Envars']),'Envars');
            $('.processes_tab').removeClass('d-none');
            $('.default-td').removeClass('d-none');
            $('.spinner-review').addClass("d-none");
          }
          if (response['message'] == "error") {
            $('#proc-error-message').html("Something went wrong.");
            $('.toast-proc-error').toast('show');
          }
        }
      });
  }
}

function ComputeProcMaps(process, case_id){
   var url = $("#procmaps_btn").attr("data-url");
  $.get(url, { 'case': case_id, 'pid': process }, // url
  function (response, textStatus, jqXHR) {  // success callback
    if (textStatus == "success") {
      if (response['message'] == "success") {
        FillArtifiacts(JSON.parse(response['artifacts']['ProcMaps']),'ProcMaps');
        $("#procmaps_btn").addClass("d-none");
      }
      if (response['message'] == "error") {
        $('#proc-error-message').html("Something went wrong.");
        $('.toast-proc-error').toast('show');
      }
    }
  });

}

function FillArtifiacts(artifacts, plugin_name){
  $('#'+plugin_name).empty();
  $.each(artifacts, function (i, item) {
    var tbody = document.getElementById(plugin_name);
    const tr = document.createElement('tr');
    const td_to_create = Object.keys(item.fields).length;
    const td_tag = document.createElement('td');
    for (var key in item.fields) {
      if (key != "investigation" && key !="PID" && key !="Pid" && key != "Tag"){
        const td = document.createElement('td');
        td.textContent = item.fields[key];
        tr.appendChild(td);
      }
     }

    // Tag conditions and system
    const dropdown = document.createElement('div');
    dropdown.setAttribute('class', 'dropdown no-arrow');

    const button = document.createElement('button');
    button.setAttribute('class', 'btn btn-link btn-sm dropdown-toggle');

    button.setAttribute('aria-expanded', 'true');
    button.setAttribute('data-bs-toggle', 'dropdown');
    button.setAttribute('type', 'button');

    const dots = document.createElement('i');
    dots.setAttribute('class', 'fas fa-ellipsis-v text-gray-400');
    button.appendChild(dots);

    const dropdown_menu = document.createElement('div');
    dropdown_menu.setAttribute('class', 'dropdown-menu shadow dropdown-menu-end animated--fade-in');
    const tagm = document.createElement('p');
    tagm.setAttribute('class', 'text-center dropdown-header');
    tagm.textContent = "Tag as";


    const span_suspicious = document.createElement('span');
    span_suspicious.textContent = " Suspicious";

    const span_evidence = document.createElement('span');
    span_evidence.textContent = " Evidence";

    const badge_suspicious = document.createElement('a');
    badge_suspicious.setAttribute('class', 'dropdown-item');
    badge_suspicious.setAttribute('href', '#');
    badge_suspicious.addEventListener('click', function (e) {
      Tag(plugin_name, item.pk, "Suspicious");
    });

    const pill_orange = document.createElement('strong');
    pill_orange.setAttribute('class', 'badge bg-warning text-wrap text-warning');
    pill_orange.textContent = ' ';
    badge_suspicious.appendChild(pill_orange);
    badge_suspicious.appendChild(span_suspicious);


    const badge_evidence = document.createElement('a');
    badge_evidence.setAttribute('class', 'dropdown-item');
    badge_evidence.setAttribute('href', '#');
    badge_evidence.addEventListener('click', function (e) {
      Tag(plugin_name, item.pk, "Evidence");
    });

    const pill_red = document.createElement('strong');
    pill_red.setAttribute('class', 'badge bg-danger text-wrap text-danger');
    pill_red.textContent = ' '

    badge_evidence.appendChild(pill_red);
    badge_evidence.appendChild(span_evidence);


    const divider = document.createElement('div');
    divider.setAttribute('class', 'dropdown-divider');

    const badge_clear = document.createElement('a');
    badge_clear.setAttribute('class', 'dropdown-item');
    badge_clear.setAttribute('href', '#');
    badge_clear.addEventListener('click', function (e) {
      Tag(plugin_name, item.pk, "Clear");
    });
    badge_clear.textContent = " Clear tag";


    const tag_evidence = document.createElement('strong');
    const tag_suspicious = document.createElement('strong');

    if (item.fields.Tag == "Evidence") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap tag_evidence_' + item.pk + '_' + plugin_name);
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_' + plugin_name);
    }

    else if (item.fields.Tag == "Suspicious") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_' + plugin_name);
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap tag_suspicious_' + item.pk + '_' + plugin_name);
    }

    else {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_' + plugin_name);
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_' + plugin_name);
    }

    tag_evidence.textContent = "Evidence";
    tag_suspicious.textContent = "Suspicious";

    dropdown_menu.appendChild(tagm);
    dropdown_menu.appendChild(badge_suspicious);
    dropdown_menu.appendChild(badge_evidence);
    dropdown_menu.appendChild(divider);
    dropdown_menu.appendChild(badge_clear);

    button.appendChild(dots);
    dropdown.appendChild(button);
    dropdown.appendChild(tag_evidence);
    dropdown.appendChild(tag_suspicious);
    dropdown.appendChild(dropdown_menu);
    td_tag.appendChild(dropdown);
    tr.appendChild(td_tag);
    tbody.appendChild(tr);
  });
  $('#'+plugin_name).removeClass('d-none'); 
}


