function DownloadDump(dump_id) {
    $("#action-form").append("<input class='d-none' name='id' value=" + dump_id + ">");
    $("#action-form").submit();
}

function DemandProcDump(pid, case_id) {
    const csrf = document.getElementsByName('csrfmiddlewaretoken');
    const fd = new FormData();
    var url = $('.procdump-try-' + pid).attr('data-url');
    fd.append('csrfmiddlewaretoken', csrf[0].value);
    fd.append('case_id', case_id);
    fd.append('pid', pid);
    $.ajax({
        type: 'POST',
        url: url,
        enctype: 'multipart/form-data',
        data: fd,
        beforeSend: function () {
            $('.procdump-try-' + pid).addClass("d-none");
            $('.procdump-load-' + pid).removeClass("d-none");
            $('#proc-message-info').html("Trying to dump the process...");
            $('.toast-proc-info').toast('show');
        },
        success: function (response) {
            if (response['message'] == "success") {
                $('#proc-success-message').html("Your file was successfully dumped.");
                $('.toast-proc-success').toast('show');
                $('.procdump-load-' + pid).addClass("d-none");
                dump_id = response['id']
                DownloadDump(dump_id)

            }
            if (response['message'] == "error") {
                $('#proc-failed-message').html("The PID provided is not valid");
                $('.toast-proc-failed').toast('show');
                $('.procdump-load-' + pid).addClass("d-none");
                $('.procdump-try-' + pid).removeClass("d-none");
            }

            if (response['message'] == "failed") {
                $('.procdump-load-' + pid).addClass("d-none");
                $('.procdump-ko-' + pid).removeClass("d-none");
                $('#proc-failed-message').html("The requested file could not be dumped");
                $('.toast-proc-failed').toast('show');
            }

            if (response['message'] == "exist") {
                $('#proc-success-message').html("Your file was successfully dumped");
                $('.toast-proc-success').toast('show');
                $('.procdump-load-' + pid).addClass("d-none");
                dump_id = response['id']
                DownloadDump(dump_id)
            }

        },
        error: function (error) {
            $('#proc-failed-message').html("Could not dump the file requested.");
            $('.toast-proc-failed').toast('show');
        },
        cache: false,
        contentType: false,
        processData: false
    });
}

function DisplayArtifacts(collapse, process) {

    if ($('#' + collapse).attr("aria-expanded") == "true") {
        $('.pid').addClass('d-none');
        $('.default-td').addClass('d-none');
        $('.spinner-review').removeClass("d-none");
        setTimeout(function () {
            $('.processes_tab').removeClass('d-none');
            $('.' + process).removeClass('d-none');
            $('.default-td').removeClass('d-none');
            $('.spinner-review').addClass("d-none");
        }, 2000);
    }
}

function DisplayAll() {

    if ($('#collapse_default').attr("aria-expanded") == "true") {
        $('.pid').addClass('d-none');
        $('.spinner-review').removeClass("d-none");
        setTimeout(function () {
            $('.processes_tab').removeClass('d-none');
            $('.pid').removeClass('d-none');
            $('.spinner-review').addClass("d-none");


        }, 2000);
    }
}

function copy(text, target) {
    $(target).attr("title", "Copied!");
    $(target).tooltip('dispose')
    $(target).tooltip('enable')
    $(target).tooltip('show')
    var input = document.createElement('input');
    input.setAttribute('value', text);
    document.body.appendChild(input);
    input.select();
    var result = document.execCommand('copy');
    document.body.removeChild(input)
    return result;
}