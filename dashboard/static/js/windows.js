function Tag(plugin_name, artifact_id, status) {
  var url = $("#tabs").attr("data-url");
  const csrf = document.getElementsByName('csrfmiddlewaretoken');
  const fd = new FormData();
  fd.append('csrfmiddlewaretoken', csrf[0].value);
  fd.append('plugin_name', plugin_name);
  fd.append('artifact_id', artifact_id);
  fd.append('status', status);
  $.ajax({
    type: 'POST',
    url: url,
    enctype: 'multipart/form-data',
    data: fd,
    success: function (data) {
      if (status == "Evidence") {
        $('.tag_evidence_' + artifact_id + "_" + plugin_name).removeClass("d-none");
        $('.tag_suspicious_' + artifact_id + "_" + plugin_name).addClass("d-none");
      }
      if (status == "Suspicious") {
        $('.tag_suspicious_' + artifact_id + "_" + plugin_name).removeClass("d-none");
        $('.tag_evidence_' + artifact_id + "_" + plugin_name).addClass("d-none");
      }
      if (status == "Clear") {
        $('.tag_suspicious_' + artifact_id + "_" + plugin_name).addClass("d-none");
        $('.tag_evidence_' + artifact_id + "_" + plugin_name).addClass("d-none");
      }
    },
    error: function (error) {
      $('#proc-error-message').html("Could not tag the artifact.");
      $('.toast-proc-error').toast('show');
    },
    cache: false,
    contentType: false,
    processData: false
  });
  event.preventDefault();
}

function GetReport(url, case_id) {
  const csrf = document.getElementsByName('csrfmiddlewaretoken');
  const fd = new FormData();
  fd.append('csrfmiddlewaretoken', csrf[0].value);
  fd.append('case_id', case_id);
  $.ajax({
    type: 'POST',
    url: url,
    enctype: 'multipart/form-data',
    data: fd,
    beforeSend: function () {

    },
    success: function (data) {
      $('#report_content_html').html(data['html'])
      $('#report_content_text').html(data['text'])
      //We add style to the table
      $('#report_content_html table').addClass('table table-sm table-dark')
      $('#report_content_text').addClass('d-none')
      $('#report_content_html').removeClass('d-none')
    },
    error: function (error) {
      $('#proc-error-message').html("Could not generate report.");
      $('.toast-proc-error').toast('show');
    },
    cache: false,
    contentType: false,
    processData: false
  });
}

function DisplayArtifacts(collapse, process, case_id) {
  const span_loading = document.createElement("span"); 
  span_loading.setAttribute('class','spinner-border spinner-border-sm');
  span_loading.setAttribute('role','status');
  $("#handles_btn").removeClass("d-none");
  const handles_btn = document.getElementById("handles_btn"); 
  handles_btn.textContent = "Click here to compute Handles for PID " + process;
  handles_btn.addEventListener('click', function (e) {
    $("#processHandles").textContent = "";
    $('#Handles tr').remove();
    $('#Handles').addClass('d-none');
     handles_btn.textContent = "";
     handles_btn.appendChild(span_loading);
     ComputeHandles(process, case_id);
  });
  if ($('#' + collapse).attr("aria-expanded") == "true") {
    $('.spinner-review').removeClass("d-none");
    var url = $("#" + collapse).attr('data-url');
    $.get(url, { 'case': case_id, 'pid': process }, // url
      function (response, textStatus, jqXHR) {  // success callback
        if (textStatus == "success") {
          if (response['message'] == "success") {
            FillArtifiacts(JSON.parse(response['artifacts']['CmdLine']),'CmdLine');
            FillArtifiacts(JSON.parse(response['artifacts']['Privs']),'Privs');
            FillArtifiacts(JSON.parse(response['artifacts']['Envars']),'Envars');
            FillArtifiacts(JSON.parse(response['artifacts']['DllList']),'DllList');
            FillArtifiacts(JSON.parse(response['artifacts']['LdrModules']),'LdrModules');
            FillArtifiacts(JSON.parse(response['artifacts']['NetStat']),'NetStat');
            FillArtifiacts(JSON.parse(response['artifacts']['NetScan']),'NetScan');
            FillArtifiacts(JSON.parse(response['artifacts']['Sessions']),'Sessions');
            FillArtifiacts(JSON.parse(response['artifacts']['Handles']),'Handles');
            FillArtifiacts(JSON.parse(response['artifacts']['VadWalk']),'VadWalk');

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

function DisplayTimeline(case_id, date) {
  $('.spinner-review').removeClass("d-none");
  $('#TimelineTab').addClass('d-none');
  var url = $("#TimelineTab").attr('data-url');
  var date = date.toString();
  $.get(url, { 'case': case_id, 'date': date }, // url
  function (response, textStatus, jqXHR) {  // success callback
    if (textStatus == "success") {
      if (response['message'] == "success") {
        FillTimeline(JSON.parse(response['artifacts']['Timeliner']));
        $('#TimelineTab').removeClass('d-none');
        $('.spinner-review').addClass("d-none");
      }
      if (response['message'] == "error") {
        $('#proc-error-message').html("Something went wrong.");
        $('.toast-proc-error').toast('show');
      }
    }
    else{
      console.log(textStatus)
    }
  });
}

function ComputeHandles(process, case_id){
  var url = $("#handles_btn").attr("data-url");
  $.get(url, { 'case': case_id, 'pid': process }, // url
  function (response, textStatus, jqXHR) {  // success callback
    if (textStatus == "success") {
      if (response['message'] == "success") {
        FillArtifiacts(JSON.parse(response['artifacts']['Handles']),'Handles');
        $("#handles_btn").addClass("d-none");
        $('#Handles').removeClass('d-none');
      }
      if (response['message'] == "error") {
        $('#proc-error-message').html("Something went wrong.");
        $('.toast-proc-error').toast('show');
      }
    }
  });
}

function FillTimeline(artifacts) {
  // Create the html elements for each line
  $('#TimelineTab').empty();
  $.each(artifacts, function (i, item) {
    
    var tbody = document.getElementById('TimelineTab');
    const tr = document.createElement('tr');
    const td_1 = document.createElement('td');
    const td_2 = document.createElement('td');
    const td_3 = document.createElement('td');
    const td_4 = document.createElement('td');
    const td_5 = document.createElement('td');
    const td_6 = document.createElement('td');
    const td_7 = document.createElement('td');
    td_7.setAttribute('class', 'w-10');

    td_1.textContent = item.fields.CreatedDate;
    td_2.textContent = item.fields.ChangedDate;
    td_3.textContent = item.fields.AccessedDate;
    td_4.textContent = item.fields.Description;
    td_5.textContent = item.fields.ModifiedDate;
    td_6.textContent = item.fields.Plugin;


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
      Tag('Timeliner', item.pk, "Suspicious");
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
      Tag('Timeliner', item.pk, "Evidence");
    });


    const pill_red = document.createElement('strong');
    pill_red.setAttribute('class', 'badge bg-danger text-wrap text-danger');
    pill_red.textContent = ' ';

    badge_evidence.appendChild(pill_red);
    badge_evidence.appendChild(span_evidence);


    const divider = document.createElement('div');
    divider.setAttribute('class', 'dropdown-divider');

    const badge_clear = document.createElement('a');
    badge_clear.setAttribute('class', 'dropdown-item');
    badge_clear.setAttribute('href', '#');
    badge_clear.addEventListener('click', function (e) {
      Tag('Timeliner', item.pk, "Clear");
    });
    badge_clear.textContent = " Clear tag";


    const tag_evidence = document.createElement('strong');
    const tag_suspicious = document.createElement('strong');

    if (item.fields.Tag == "Evidence") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap tag_evidence_' + item.pk + '_Timeliner');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_Timeliner');
    }

    else if (item.fields.Tag == "Suspicious") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_Timeliner');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap tag_suspicious_' + item.pk + '_Timeliner');
    }

    else {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_Timeliner');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_Timeliner');
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
    td_7.appendChild(dropdown);

    tr.appendChild(td_1);
    tr.appendChild(td_2);
    tr.appendChild(td_3);
    tr.appendChild(td_4);
    tr.appendChild(td_5);
    tr.appendChild(td_6);
    tr.appendChild(td_7);
    tbody.appendChild(tr);
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


$(document).ready(function () {
  $('.plugin').hide();
  $('.toast-other').toast('show');

  var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
  var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
    return new bootstrap.Tooltip(tooltipTriggerEl)
  })

  /* ################################ REGISTRY SCRIPTS ################################ */

  $("#search_proc").on("keyup", function () {
    var value = $(this).val().toLowerCase();
    $("#process-ac #process_info").filter(function () {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });


  $("#search_registry").on("keyup", function () {
    var value = $(this).val().toLowerCase();
    $("#UserAssist tr").filter(function () {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });

  //TimeLine SearchBar
  $("#searchTimeline").on("keyup", function () {
    var value = $(this).val().toLowerCase();
    $("#TimelineTab tr").filter(function () {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) !== -1)
    })
  });

  //FileScan SearchBar
  $("#search_files").on("keyup", function () {
    var value = $(this).val().toLowerCase();
    $("#FileScanTab tr").filter(function () {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });


  //CmdLine SearchBar
  $("#searchCmdLine").on("keyup", function () {
    var value = $(this).val().toLowerCase();
    $("#CmdLine tr").filter(function () {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });

  //Dlllist SearchBar
  $("#searchDllList").on("keyup", function () {
    var value = $(this).val().toLowerCase();
    $("#DllList tr").filter(function () {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });

  //Privileges SearchBar
  $("#searchPriv").on("keyup", function () {
    var value = $(this).val().toLowerCase();
    $("#Privs tr").filter(function () {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });

  //Process Env SearchBar

  $("#searchEnv").on("keyup", function () {
    var value = $(this).val().toLowerCase();
    $("#Envars tr").filter(function () {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });


  //Process Handles SearchBar

  $("#searchHandles").on("keyup", function () {
    var value = $(this).val().toLowerCase();
    $("#processHandles tr").filter(function () {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });


  //NetStat Search funtion
  $("#searchNetworkStat").on("keyup", function () {
    var value = $(this).val().toLowerCase();
    $("#NetStat tr").filter(function () {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });

  //NetStat Search funtion
  $("#searchNetworkScan").on("keyup", function () {
    var value = $(this).val().toLowerCase();
    $("#NetScan tr").filter(function () {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });

});
