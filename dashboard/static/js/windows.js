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
     handles_btn.textContent = "";
     handles_btn.appendChild(span_loading);
     ComputeHandles(process, case_id);
  });
  if ($('#' + collapse).attr("aria-expanded") == "true") {
    $('#cmdline').addClass('d-none');
    $('#processPriv').addClass('d-none');
    $('#processEnv').addClass('d-none');
    $('#dlllist').addClass('d-none');
    $('#ldrmodules').addClass('d-none');

    $('#netstat').addClass('d-none');
    $('#netscan').addClass('d-none');
    $('#sessions').addClass('d-none');
    $('#processHandles').addClass('d-none');
    $('.spinner-review').removeClass("d-none");
    var url = $("#" + collapse).attr('data-url');
    $.get(url, { 'case': case_id, 'pid': process }, // url
      function (response, textStatus, jqXHR) {  // success callback
        if (textStatus == "success") {
          if (response['message'] == "success") {
            FillCmdLine(JSON.parse(response['artifacts']['CmdLine']));
            FillPrivileges(JSON.parse(response['artifacts']['Privs']));
            FillEnvars(JSON.parse(response['artifacts']['Envars']));
            FillDlls(JSON.parse(response['artifacts']['DllList']));
            FillLdr(JSON.parse(response['artifacts']['LdrModules']));
            FillNetStat(JSON.parse(response['artifacts']['NetStat']));
            FillNetScan(JSON.parse(response['artifacts']['NetScan']));
            FillSessions(JSON.parse(response['artifacts']['Sessions']));

            $('#cmdline').removeClass('d-none');
            $('#processPriv').removeClass('d-none');
            $('#processEnv').removeClass('d-none');
            $('#dlllist').removeClass('d-none');
            $('#ldrmodules').removeClass('d-none');
            $('#netstat').removeClass('d-none');
            $('#netscan').removeClass('d-none');
            $('#sessions').removeClass('d-none');
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
  });
}

function ComputeHandles(process, case_id){
  
  $('#processHandles').addClass('d-none');
  var url = $("#handles_btn").attr("data-url");
  $.get(url, { 'case': case_id, 'pid': process }, // url
  function (response, textStatus, jqXHR) {  // success callback
    if (textStatus == "success") {
      if (response['message'] == "success") {
        FillHandles(JSON.parse(response['artifacts']['Handles']));
        $("#handles_btn").addClass("d-none");
      }
      if (response['message'] == "error") {
        $('#proc-error-message').html("Something went wrong.");
        $('.toast-proc-error').toast('show');
      }
    }
  });

}

function FillCmdLine(artifacts) {
  // Create the html elements for each line
  $('#cmdline').empty();
  $.each(artifacts, function (i, item) {
    var tbody = document.getElementById('cmdline');
    const tr = document.createElement('tr');
    const td_1 = document.createElement('td');
    const td_2 = document.createElement('td');
    const td_3 = document.createElement('td');
    const td_4 = document.createElement('td');
    td_1.textContent = item.fields.PID;
    td_2.textContent = item.fields.Process;
    td_3.textContent = item.fields.Args;
    td_3.setAttribute('class', 'w-50');

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
      Tag('CmdLine', item.pk, "Suspicious");
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
      Tag('CmdLine', item.pk, "Evidence");
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
      Tag('CmdLine', item.pk, "Clear");
    });
    badge_clear.textContent = " Clear tag";


    const tag_evidence = document.createElement('strong');
    const tag_suspicious = document.createElement('strong');

    if (item.fields.Tag == "Evidence") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap tag_evidence_' + item.pk + '_CmdLine');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_CmdLine');
    }

    else if (item.fields.Tag == "Suspicious") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_CmdLine');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap tag_suspicious_' + item.pk + '_CmdLine');
    }

    else {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_CmdLine');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_CmdLine');
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
    td_4.appendChild(dropdown);

    tr.appendChild(td_1);
    tr.appendChild(td_2);
    tr.appendChild(td_3);
    tr.appendChild(td_4);

    tbody.appendChild(tr);
  });
}

function FillPrivileges(artifacts) {
  // Create the html elements for each line
  $('#processPriv').empty();
  $.each(artifacts, function (i, item) {
    var tbody = document.getElementById('processPriv');
    const tr = document.createElement('tr');
    const td_1 = document.createElement('td');
    const td_2 = document.createElement('td');
    const td_3 = document.createElement('td');
    const td_4 = document.createElement('td');
    const td_5 = document.createElement('td');
    const td_6 = document.createElement('td');
    const td_7 = document.createElement('td');
    td_1.textContent = item.fields.PID;
    td_2.textContent = item.fields.Process;
    td_3.textContent = item.fields.Privilege;
    td_4.textContent = item.fields.Attributes;
    td_5.textContent = item.fields.Description;
    td_6.textContent = item.fields.Value;

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
      Tag('Privs', item.pk, "Suspicious");
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
      Tag('Privs', item.pk, "Evidence");
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
      Tag('Privs', item.pk, "Clear");
    });
    badge_clear.textContent = " Clear tag";


    const tag_evidence = document.createElement('strong');
    const tag_suspicious = document.createElement('strong');

    if (item.fields.Tag == "Evidence") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap tag_evidence_' + item.pk + '_Privs');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_Privs');
    }

    else if (item.fields.Tag == "Suspicious") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_Privs');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap tag_suspicious_' + item.pk + '_Privs');
    }

    else {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_Privs');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_Privs');
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

function FillEnvars(artifacts) {
  // Create the html elements for each line
  $('#processEnv').empty();
  $.each(artifacts, function (i, item) {
    var tbody = document.getElementById('processEnv');
    const tr = document.createElement('tr');
    const td_1 = document.createElement('td');
    const td_2 = document.createElement('td');
    const td_3 = document.createElement('td');
    const td_4 = document.createElement('td');
    const td_5 = document.createElement('td');
    td_5.setAttribute('class', 'w-50 text-break');
    const td_6 = document.createElement('td');
    td_6.setAttribute('class', 'w-10');

    td_1.textContent = item.fields.Block;
    td_2.textContent = item.fields.PID;
    td_3.textContent = item.fields.Process;
    td_4.textContent = item.fields.Variable;
    td_5.textContent = item.fields.Value;

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
      Tag('Envars', item.pk, "Suspicious");
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
      Tag('Envars', item.pk, "Evidence");
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
      Tag('Envars', item.pk, "Clear");
    });
    badge_clear.textContent = " Clear tag";


    const tag_evidence = document.createElement('strong');
    const tag_suspicious = document.createElement('strong');

    if (item.fields.Tag == "Evidence") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap tag_evidence_' + item.pk + '_Envars');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_Envars');
    }

    else if (item.fields.Tag == "Suspicious") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_Envars');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap tag_suspicious_' + item.pk + '_Envars');
    }

    else {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_Envars');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_Envars');
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
    td_6.appendChild(dropdown);

    tr.appendChild(td_1);
    tr.appendChild(td_2);
    tr.appendChild(td_3);
    tr.appendChild(td_4);
    tr.appendChild(td_5);
    tr.appendChild(td_6);
    tbody.appendChild(tr);
  });
}

function FillDlls(artifacts) {
  // Create the html elements for each line
  $('#dlllist').empty();
  $.each(artifacts, function (i, item) {
    var tbody = document.getElementById('dlllist');
    const tr = document.createElement('tr');
    const td_1 = document.createElement('td');
    const td_2 = document.createElement('td');
    const td_3 = document.createElement('td');
    const td_4 = document.createElement('td');
    const td_5 = document.createElement('td');
    td_5.setAttribute('class', 'w-25 text-break');
    const td_6 = document.createElement('td');
    const td_7 = document.createElement('td');
    const td_8 = document.createElement('td');
    const td_9 = document.createElement('td');
    td_9.setAttribute('class', 'w-10');

    td_1.textContent = item.fields.Process;
    td_2.textContent = item.fields.PID;
    td_3.textContent = item.fields.Base;
    td_4.textContent = item.fields.Name;
    td_5.textContent = item.fields.Path;
    td_6.textContent = item.fields.Size;
    td_7.textContent = item.fields.LoadTime;
    td_8.textContent = item.fields.Fileouput;

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
      Tag('DllList', item.pk, "Suspicious");
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
      Tag('DllList', item.pk, "Evidence");
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
      Tag('DllList', item.pk, "Clear");
    });
    badge_clear.textContent = " Clear tag";


    const tag_evidence = document.createElement('strong');
    const tag_suspicious = document.createElement('strong');

    if (item.fields.Tag == "Evidence") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap tag_evidence_' + item.pk + '_DllList');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_DllList');
    }

    else if (item.fields.Tag == "Suspicious") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_DllList');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap tag_suspicious_' + item.pk + '_DllList');
    }

    else {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_DllList');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_DllList');
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
    td_9.appendChild(dropdown);

    tr.appendChild(td_1);
    tr.appendChild(td_2);
    tr.appendChild(td_3);
    tr.appendChild(td_4);
    tr.appendChild(td_5);
    tr.appendChild(td_6);
    tr.appendChild(td_7);
    tr.appendChild(td_8);
    tr.appendChild(td_9);
    tbody.appendChild(tr);
  });
}

function FillLdr(artifacts) {
  // Create the html elements for each line
  $('#ldrmodules').empty();
  $.each(artifacts, function (i, item) {
    var tbody = document.getElementById('ldrmodules');
    const tr = document.createElement('tr');
    const td_1 = document.createElement('td');
    const td_2 = document.createElement('td');
    const td_3 = document.createElement('td');
    const td_4 = document.createElement('td');
    const td_5 = document.createElement('td');
    const td_6 = document.createElement('td');
    const td_7 = document.createElement('td');
    td_7.setAttribute('class', 'w-25 text-break');

    const td_8 = document.createElement('td');

    td_1.textContent = item.fields.Pid;
    td_2.textContent = item.fields.Process;
    td_3.textContent = item.fields.Base;
    td_4.textContent = item.fields.InInit;
    td_5.textContent = item.fields.InLoad;
    td_6.textContent = item.fields.InMem;
    td_7.textContent = item.fields.MappedPath;

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
      Tag('Ldrmodules', item.pk, "Suspicious");
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
      Tag('Ldrmodules', item.pk, "Evidence");
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
      Tag('Ldrmodules', item.pk, "Clear");
    });
    badge_clear.textContent = " Clear tag";


    const tag_evidence = document.createElement('strong');
    const tag_suspicious = document.createElement('strong');

    if (item.fields.Tag == "Evidence") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap tag_evidence_' + item.pk + '_Ldrmodules');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_Ldrmodules');
    }

    else if (item.fields.Tag == "Suspicious") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_Ldrmodules');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap tag_suspicious_' + item.pk + '_Ldrmodules');
    }

    else {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_Ldrmodules');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_Ldrmodules');
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
    td_8.appendChild(dropdown);

    tr.appendChild(td_1);
    tr.appendChild(td_2);
    tr.appendChild(td_3);
    tr.appendChild(td_4);
    tr.appendChild(td_5);
    tr.appendChild(td_6);
    tr.appendChild(td_7);
    tr.appendChild(td_8);
    tbody.appendChild(tr);
  });
}

function FillSessions(artifacts) {
  // Create the html elements for each line
  $('#sessions').empty();
  $.each(artifacts, function (i, item) {
    var tbody = document.getElementById('sessions');
    const tr = document.createElement('tr');
    const td_1 = document.createElement('td');
    const td_2 = document.createElement('td');
    const td_3 = document.createElement('td');
    const td_4 = document.createElement('td');
    const td_5 = document.createElement('td');
    const td_6 = document.createElement('td');
    const td_7 = document.createElement('td');

    td_1.textContent = item.fields.ProcessID;
    td_2.textContent = item.fields.Process;
    td_3.textContent = item.fields.SessionID;
    td_4.textContent = item.fields.SessionType;
    td_5.textContent = item.fields.UserName;
    td_6.textContent = item.fields.CreateTime;
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
      Tag('Sessions', item.pk, "Suspicious");
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
      Tag('Sessions', item.pk, "Evidence");
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
      Tag('Sessions', item.pk, "Clear");
    });
    badge_clear.textContent = " Clear tag";


    const tag_evidence = document.createElement('strong');
    const tag_suspicious = document.createElement('strong');

    if (item.fields.Tag == "Evidence") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap tag_evidence_' + item.pk + '_Sessions');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_Sessions');
    }

    else if (item.fields.Tag == "Suspicious") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_Sessions');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap tag_suspicious_' + item.pk + '_Sessions');
    }

    else {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_Sessions');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_Sessions');
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

function FillNetStat(artifacts) {
  // Create the html elements for each line
  $('#netstat').empty();
  $.each(artifacts, function (i, item) {
    var tbody = document.getElementById('netstat');
    const tr = document.createElement('tr');
    const td_1 = document.createElement('td');
    const td_2 = document.createElement('td');
    const td_3 = document.createElement('td');
    const td_4 = document.createElement('td');
    const td_5 = document.createElement('td');
    const td_6 = document.createElement('td');
    const td_7 = document.createElement('td');
    const td_8 = document.createElement('td');
    const td_9 = document.createElement('td');
    const td_10 = document.createElement('td');
    const td_11 = document.createElement('td');
    td_11.setAttribute('class', 'w-10');

    td_1.textContent = item.fields.Created;
    td_2.textContent = item.fields.Offset;
    td_3.textContent = item.fields.Owner;
    td_4.textContent = item.fields.Proto;
    td_5.textContent = item.fields.LocalAddr;
    td_6.textContent = item.fields.LocalPort;
    td_7.textContent = item.fields.ForeignAddr;
    td_8.textContent = item.fields.ForeignPort;
    td_9.textContent = item.fields.State;
    td_10.textContent = item.fields.PID;


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
      Tag('NetStat', item.pk, "Suspicious");
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
      Tag('NetStat', item.pk, "Evidence");
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
      Tag('NetStat', item.pk, "Clear");
    });
    badge_clear.textContent = " Clear tag";


    const tag_evidence = document.createElement('strong');
    const tag_suspicious = document.createElement('strong');

    if (item.fields.Tag == "Evidence") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap tag_evidence_' + item.pk + '_NetStat');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_NetStat');
    }

    else if (item.fields.Tag == "Suspicious") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_NetStat');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap tag_suspicious_' + item.pk + '_NetStat');
    }

    else {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_NetStat');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_NetStat');
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
    td_11.appendChild(dropdown);

    tr.appendChild(td_1);
    tr.appendChild(td_2);
    tr.appendChild(td_3);
    tr.appendChild(td_4);
    tr.appendChild(td_5);
    tr.appendChild(td_6);
    tr.appendChild(td_7);
    tr.appendChild(td_8);
    tr.appendChild(td_9);
    tr.appendChild(td_10);
    tr.appendChild(td_11);
    tbody.appendChild(tr);
  });
}

function FillNetScan(artifacts) {
  // Create the html elements for each line
  $('#netscan').empty();
  $.each(artifacts, function (i, item) {
    var tbody = document.getElementById('netscan');
    const tr = document.createElement('tr');
    const td_1 = document.createElement('td');
    const td_2 = document.createElement('td');
    const td_3 = document.createElement('td');
    const td_4 = document.createElement('td');
    const td_5 = document.createElement('td');
    const td_6 = document.createElement('td');
    const td_7 = document.createElement('td');
    const td_8 = document.createElement('td');
    const td_9 = document.createElement('td');
    const td_10 = document.createElement('td');
    const td_11 = document.createElement('td');
    td_11.setAttribute('class', 'w-10');

    td_1.textContent = item.fields.Created;
    td_2.textContent = item.fields.Offset;
    td_3.textContent = item.fields.Owner;
    td_4.textContent = item.fields.Proto;
    td_5.textContent = item.fields.LocalAddr;
    td_6.textContent = item.fields.LocalPort;
    td_7.textContent = item.fields.ForeignAddr;
    td_8.textContent = item.fields.ForeignPort;
    td_9.textContent = item.fields.State;
    td_10.textContent = item.fields.PID;


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
      Tag('NetScan', item.pk, "Suspicious");
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
      Tag('NetScan', item.pk, "Evidence");
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
      Tag('NetScan', item.pk, "Clear");
    });
    badge_clear.textContent = " Clear tag";


    const tag_evidence = document.createElement('strong');
    const tag_suspicious = document.createElement('strong');

    if (item.fields.Tag == "Evidence") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap tag_evidence_' + item.pk + '_NetScan');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_NetScan');
    }

    else if (item.fields.Tag == "Suspicious") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_NetScan');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap tag_suspicious_' + item.pk + '_NetScan');
    }

    else {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_NetScan');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_NetScan');
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
    td_11.appendChild(dropdown);

    tr.appendChild(td_1);
    tr.appendChild(td_2);
    tr.appendChild(td_3);
    tr.appendChild(td_4);
    tr.appendChild(td_5);
    tr.appendChild(td_6);
    tr.appendChild(td_7);
    tr.appendChild(td_8);
    tr.appendChild(td_9);
    tr.appendChild(td_10);
    tr.appendChild(td_11);
    tbody.appendChild(tr);
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

function FillHandles(artifacts) {
  // Create the html elements for each line
  $('#processHandles').empty();
  $.each(artifacts, function (i, item) {
    
    var tbody = document.getElementById('processHandles');
    const tr = document.createElement('tr');
    const td_1 = document.createElement('td');
    const td_2 = document.createElement('td');
    const td_3 = document.createElement('td');
    const td_4 = document.createElement('td');
    td_4.setAttribute('class', 'w-25 text-break');
    const td_5 = document.createElement('td');
    const td_6 = document.createElement('td');
    const td_7 = document.createElement('td');
    const td_8 = document.createElement('td');
    td_8.setAttribute('class', 'w-10');

    td_1.textContent = item.fields.Process;
    td_2.textContent = item.fields.PID;
    td_3.textContent = item.fields.Offset;
    td_4.textContent = item.fields.Name;
    td_5.textContent = item.fields.HandleValue;
    td_6.textContent = item.fields.GrantedAccess;
    td_7.textContent = item.fields.Type;

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
      Tag('Handles', item.pk, "Suspicious");
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
      Tag('Handles', item.pk, "Evidence");
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
      Tag('Handles', item.pk, "Clear");
    });
    badge_clear.textContent = " Clear tag";


    const tag_evidence = document.createElement('strong');
    const tag_suspicious = document.createElement('strong');

    if (item.fields.Tag == "Evidence") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap tag_evidence_' + item.pk + '_Handles');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_Handles');
    }

    else if (item.fields.Tag == "Suspicious") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_Handles');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap tag_suspicious_' + item.pk + '_Handles');
    }

    else {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_Handles');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_Handles');
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
    td_8.appendChild(dropdown);

    tr.appendChild(td_1);
    tr.appendChild(td_2);
    tr.appendChild(td_3);
    tr.appendChild(td_4);
    tr.appendChild(td_5);
    tr.appendChild(td_6);
    tr.appendChild(td_7);
    tr.appendChild(td_8);
    tbody.appendChild(tr);
    $('#processHandles').removeClass('d-none');
  });
}

$(document).ready(function () {
  $('.plugin').hide();
  $('.toast-other').toast('show');

  var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
  var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
    return new bootstrap.Tooltip(tooltipTriggerEl)
  })

  /* ################################ REGISTRY SCRIPTS ################################ */

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
    $("#cmdline tr").filter(function () {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });

  //CmdLine SearchBar
  $("#searchDllList").on("keyup", function () {
    var value = $(this).val().toLowerCase();
    $("#dlllist tr").filter(function () {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });

  //Privileges SearchBar
  $("#searchPriv").on("keyup", function () {
    var value = $(this).val().toLowerCase();
    $("#processPriv tr").filter(function () {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });

  //Process Env SearchBar

  $("#searchEnv").on("keyup", function () {
    var value = $(this).val().toLowerCase();
    $("#processEnv tr").filter(function () {
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
    $("#netstat tr").filter(function () {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });

  //NetStat Search funtion
  $("#searchNetworkScan").on("keyup", function () {
    var value = $(this).val().toLowerCase();
    $("#netscan tr").filter(function () {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });

});
