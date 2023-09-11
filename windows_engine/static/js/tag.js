function generate_tag(item){
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
          tag('Timeliner', item.pk, "Suspicious");
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
          tag('Timeliner', item.pk, "Evidence");
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
          tag('Timeliner', item.id, "Clear");
        });
        badge_clear.textContent = " Clear tag";
    
    
        const tag_evidence = document.createElement('strong');
        const tag_suspicious = document.createElement('strong');
    
        if (item.Tag == "Evidence") {
          tag_evidence.setAttribute('class', 'badge bg-danger text-wrap tag_evidence_' + item.id + '_Timeliner');
          tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.id + '_Timeliner');
        }
    
        else if (item.Tag == "Suspicious") {
          tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.id + '_Timeliner');
          tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap tag_suspicious_' + item.id + '_Timeliner');
        }
    
        else {
          tag_evidence.setAttribute('class', 'badge bg-danger text-wrap d-none tag_evidence_' + item.id + '_Timeliner');
          tag_suspicious.setAttribute('class', 'badge bg-warning text-wrap d-none tag_suspicious_' + item.id + '_Timeliner');
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
        return dropdown.innerHTML;
}

function Tag(plugin_name, artifact_id, status) {
    // TODO : Actually TAG
    // var url = $("#tabs").attr("data-url");
    // const csrf = document.getElementsByName('csrfmiddlewaretoken');
    // const fd = new FormData();
    // fd.append('csrfmiddlewaretoken', csrf[0].value);
    // fd.append('plugin_name', plugin_name);
    // fd.append('artifact_id', artifact_id);
    // fd.append('status', status);
    // $.ajax({
    //   type: 'POST',
    //   url: url,
    //   enctype: 'multipart/form-data',
    //   data: fd,
    //   success: function (data) {
    //     if (status == "Evidence") {
    //       $('.tag_evidence_' + artifact_id + "_" + plugin_name).removeClass("d-none");
    //       $('.tag_suspicious_' + artifact_id + "_" + plugin_name).addClass("d-none");
    //     }
    //     if (status == "Suspicious") {
    //       $('.tag_suspicious_' + artifact_id + "_" + plugin_name).removeClass("d-none");
    //       $('.tag_evidence_' + artifact_id + "_" + plugin_name).addClass("d-none");
    //     }
    //     if (status == "Clear") {
    //       $('.tag_suspicious_' + artifact_id + "_" + plugin_name).addClass("d-none");
    //       $('.tag_evidence_' + artifact_id + "_" + plugin_name).addClass("d-none");
    //     }
    //   },
    //   error: function (error) {
    //     $('#proc-error-message').html("Could not tag the artifact.");
    //     $('.toast-proc-error').toast('show');
    //   },
    //   cache: false,
    //   contentType: false,
    //   processData: false
    // });
    // event.preventDefault();
  }