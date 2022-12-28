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


function DisplayArtifacts(collapse, process, case_id) {
  if ($('#' + collapse).attr("aria-expanded") == "true") {
    $('#Bash').addClass('d-none');
    $('#Elfs').addClass('d-none');
    $('#Lsof').addClass('d-none');
    $('#PsAux').addClass('d-none');
    $('#processMaps').addClass('d-none');

    $('.spinner-review').removeClass("d-none");
    var url = $("#" + collapse).attr('data-url');
    $.get(url, { 'case': case_id, 'pid': process }, // url
      function (response, textStatus, jqXHR) {  // success callback
        if (textStatus == "success") {
          if (response['message'] == "success") {
            FillPsAux(JSON.parse(response['artifacts']['PsAux']));
            FillBash(JSON.parse(response['artifacts']['Bash']));
            FillElfs(JSON.parse(response['artifacts']['Elfs']));
            FillLsof(JSON.parse(response['artifacts']['Lsof']));
            FillProcMaps(JSON.parse(response['artifacts']['ProcMaps']));

            $('#Bash').removeClass('d-none');
            $('#Elfs').removeClass('d-none');
            $('#Lsof').removeClass('d-none');
            $('#PsAux').removeClass('d-none');
            $('#processMaps').removeClass('d-none');
            
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


function FillPsAux(artifacts) {
  // Create the html elements for each line
  $('#PsAux').empty();
  $.each(artifacts, function (i, item) {
    var tbody = document.getElementById('PsAux');
    const tr = document.createElement('tr');
    const td_1 = document.createElement('td');
    const td_2 = document.createElement('td');
    const td_3 = document.createElement('td');
    const td_4 = document.createElement('td');
    const td_5 = document.createElement('td');

    td_1.textContent = item.fields.PID;
    td_2.textContent = item.fields.PPID;
    td_3.textContent = item.fields.COMM;
    td_4.textContent = item.fields.ARGS;

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
      Tag('PsAux', item.pk, "Suspicious");
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
      Tag('PsAux', item.pk, "Evidence");
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
      Tag('PsAux', item.pk, "Clear");
    });
    badge_clear.textContent = " Clear tag";


    const tag_evidence = document.createElement('strong');
    const tag_suspicious = document.createElement('strong');

    if (item.fields.Tag == "Evidence") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap tag_evidence_' + item.pk + '_PsAux');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_PsAux');
    }

    else if (item.fields.Tag == "Suspicious") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_PsAux');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap tag_suspicious_' + item.pk + '_PsAux');
    }

    else {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_PsAux');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_PsAux');
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
    td_5.appendChild(dropdown);

    tr.appendChild(td_1);
    tr.appendChild(td_2);
    tr.appendChild(td_3);
    tr.appendChild(td_4);
    tr.appendChild(td_5);

    tbody.appendChild(tr);
  });
}

function FillBash(artifacts) {
  // Create the html elements for each line
  $('#Bash').empty();
  $.each(artifacts, function (i, item) {
    var tbody = document.getElementById('Bash');
    const tr = document.createElement('tr');
    const td_1 = document.createElement('td');
    const td_2 = document.createElement('td');
    const td_3 = document.createElement('td');
    const td_4 = document.createElement('td');
    const td_5 = document.createElement('td');

    td_1.textContent = item.fields.PID;
    td_2.textContent = item.fields.Process;
    td_3.textContent = item.fields.CommandTime;
    td_4.textContent = item.fields.Command;

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
      Tag('Bash', item.pk, "Suspicious");
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
      Tag('Bash', item.pk, "Evidence");
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
      Tag('Bash', item.pk, "Clear");
    });
    badge_clear.textContent = " Clear tag";


    const tag_evidence = document.createElement('strong');
    const tag_suspicious = document.createElement('strong');

    if (item.fields.Tag == "Evidence") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap tag_evidence_' + item.pk + '_Bash');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_Bash');
    }

    else if (item.fields.Tag == "Suspicious") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_Bash');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap tag_suspicious_' + item.pk + '_Bash');
    }

    else {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_Bash');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_Bash');
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
    td_5.appendChild(dropdown);

    tr.appendChild(td_1);
    tr.appendChild(td_2);
    tr.appendChild(td_3);
    tr.appendChild(td_4);
    tr.appendChild(td_5);

    tbody.appendChild(tr);
  });
}

function FillElfs(artifacts) {
  // Create the html elements for each line
  $('#Elfs').empty();
  $.each(artifacts, function (i, item) {
    var tbody = document.getElementById('Elfs');
    const tr = document.createElement('tr');
    const td_1 = document.createElement('td');
    const td_2 = document.createElement('td');
    const td_3 = document.createElement('td');
    const td_4 = document.createElement('td');
    const td_5 = document.createElement('td');
    const td_6 = document.createElement('td');

    td_1.textContent = item.fields.Start;
    td_2.textContent = item.fields.End;
    td_3.textContent = item.fields.FilePath;
    td_4.textContent = item.fields.Process;
    td_5.textContent = item.fields.PID;
    

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
      Tag('Elfs', item.pk, "Suspicious");
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
      Tag('Elfs', item.pk, "Evidence");
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
      Tag('Elfs', item.pk, "Clear");
    });
    badge_clear.textContent = " Clear tag";


    const tag_evidence = document.createElement('strong');
    const tag_suspicious = document.createElement('strong');

    if (item.fields.Tag == "Evidence") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap tag_evidence_' + item.pk + '_Elfs');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_Elfs');
    }

    else if (item.fields.Tag == "Suspicious") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_Elfs');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap tag_suspicious_' + item.pk + '_Elfs');
    }

    else {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_Elfs');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_Elfs');
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

function FillLsof(artifacts) {
  // Create the html elements for each line
  $('#Lsof').empty();
  $.each(artifacts, function (i, item) {
    var tbody = document.getElementById('Lsof');
    const tr = document.createElement('tr');
    const td_1 = document.createElement('td');
    const td_2 = document.createElement('td');
    const td_3 = document.createElement('td');
    const td_4 = document.createElement('td');
    const td_5 = document.createElement('td');

    td_1.textContent = item.fields.FD;
    td_2.textContent = item.fields.PID;
    td_3.textContent = item.fields.Path;
    td_4.textContent = item.fields.Process;
    

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
      Tag('Lsof', item.pk, "Suspicious");
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
      Tag('Lsof', item.pk, "Evidence");
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
      Tag('Lsof', item.pk, "Clear");
    });
    badge_clear.textContent = " Clear tag";


    const tag_evidence = document.createElement('strong');
    const tag_suspicious = document.createElement('strong');

    if (item.fields.Tag == "Evidence") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap tag_evidence_' + item.pk + '_Lsof');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_Lsof');
    }

    else if (item.fields.Tag == "Suspicious") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_Lsof');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap tag_suspicious_' + item.pk + '_Lsof');
    }

    else {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_Lsof');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_Lsof');
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
    td_5.appendChild(dropdown);

    tr.appendChild(td_1);
    tr.appendChild(td_2);
    tr.appendChild(td_3);
    tr.appendChild(td_4);
    tr.appendChild(td_5);

    tbody.appendChild(tr);
  });
}

function FillProcMaps(artifacts) {
  // Create the html elements for each line
  $('#processMaps').empty();
  $.each(artifacts, function (i, item) {
    var tbody = document.getElementById('processMaps');
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

    td_1.textContent = item.fields.Start;
    td_2.textContent = item.fields.End;
    td_3.textContent = item.fields.FilePath;
    td_4.textContent = item.fields.Flags;
    td_5.textContent = item.fields.Inode;
    td_6.textContent = item.fields.Major;
    td_7.textContent = item.fields.Minor;
    td_8.textContent = item.fields.PID;
    td_9.textContent = item.fields.PgOff;
    td_10.textContent = item.fields.Process;

    

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
      Tag('ProcMaps', item.pk, "Suspicious");
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
      Tag('ProcMaps', item.pk, "Evidence");
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
      Tag('ProcMaps', item.pk, "Clear");
    });
    badge_clear.textContent = " Clear tag";


    const tag_evidence = document.createElement('strong');
    const tag_suspicious = document.createElement('strong');

    if (item.fields.Tag == "Evidence") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap tag_evidence_' + item.pk + '_ProcMaps');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_ProcMaps');
    }

    else if (item.fields.Tag == "Suspicious") {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_ProcMaps');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap tag_suspicious_' + item.pk + '_ProcMaps');
    }

    else {
      tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.pk + '_ProcMaps');
      tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.pk + '_ProcMaps');
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