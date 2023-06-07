// Refresh only part of the page.
function refresh() {
    //Delete the table first and show spinner
    sidebar.classList.remove('active');
    overlay.classList.remove('active');
    $('#all-investigations').html("")
    $('.spinner-main').show();
    var url = $("#main").attr("data-url");
    $.ajax({
        url: url,
        success: function (data) {
            var parser = new DOMParser();
            var wrapper = parser.parseFromString(data, "text/html");
            invests = wrapper.getElementById('all-investigations');
            $('.spinner-main').hide();
            $('#all-investigations').html(invests);
        }
    });
}

function ReviewInvest(case_id) {
    var url = $(".a-review").attr("data-url");
    $("#actionform").attr('action', url);
    $("#actionform").append("<input class='d-none' name='sa_case_id' value=" + case_id + ">");
    $("#actionform").submit();
}

function EditInvest(case_id) {
    var url = $("#"+case_id).attr("data-url");
    console.log(url);
    $("#actionform").attr('action', url);
    $("#actionform").submit();
}


/* The user decided to click on the "Start analysis" btn */
function StartAnalysis(case_id) {
    const csrftoken = document.querySelector('[name=csrfmiddlewaretoken]').value;
    const fd = new FormData();
    var url = $(".a-start").attr("data-url");
    fd.append('csrfmiddlewaretoken', csrftoken);
    fd.append('sa_case_id', case_id);
    $.ajax({
        type: 'POST',
        url: url,
        enctype: 'multipart/form-data',
        data: fd,
        beforeSend: function () {
            sidebar.classList.remove('active');
            overlay.classList.remove('active');
            $('#proc-message-info').html("Starting...");
            $('.toast-proc-info').toast('show');
        },
        success: function (response) {
            if (response['message'] == "success") {
                $('#proc-success-message').html("Analysis started.");
                $('.toast-proc-success').toast('show');
                refresh();
            }
            if (response['message'] == "error") {
                $('#proc-error-message').html("Invalid request");
                $('.toast-proc-error').toast('show');
            }

        },
        error: function (error) {
            $('#proc-error-message').html("Something went wrong (500) ");
            $('.toast-proc-error').toast('show');
        },
        cache: false,
        contentType: false,
        processData: false
    });
}

/* Cancel Analysis function */
function CancelAnalysis(case_id) {
    const csrftoken = document.querySelector('[name=csrfmiddlewaretoken]').value;
    const fd = new FormData();
    fd.append('csrfmiddlewaretoken', csrftoken);
    fd.append('sa_case_id', case_id);
    var url = $(".a-cancel").attr("data-url");
    $.ajax({
        type: 'POST',
        url: url,
        enctype: 'multipart/form-data',
        data: fd,
        beforeSend: function () {
            sidebar.classList.remove('active');
            overlay.classList.remove('active');
            $('#proc-message-info').html("Canceling...");
            $('.toast-proc-info').toast('show');
        },
        success: function (response) {
            if (response['message'] == "success") {
                $('#proc-success-message').html("Analysis canceled.");
                $('.toast-proc-success').toast('show');
                refresh();
            }
            if (response['message'] == "error") {
                $('#proc-error-message').html("Invalid request");
                $('.toast-proc-error').toast('show');
            }
        },
        error: function (error) {
            $('#proc-error-message').html("Something went wrong (500) ");
            $('.toast-proc-error').toast('show');
        },
        cache: false,
        contentType: false,
        processData: false
    });
}

/* Delete investigation script */
function DeleteAnalysis(case_id) {
    const csrftoken = document.querySelector('[name=csrfmiddlewaretoken]').value;
    const fd = new FormData();
    fd.append('csrfmiddlewaretoken', csrftoken);
    fd.append('sa_case_id', case_id);
    var url = $(".a-delete").attr("data-url");
    $.ajax({
        type: 'POST',
        url: url,
        enctype: 'multipart/form-data',
        data: fd,
        beforeSend: function () {
            sidebar.classList.remove('active');
            overlay.classList.remove('active');
            $('#proc-message-info').html("Deleting...");
            $('.toast-proc-info').toast('show');
        },
        success: function (response) {
            if (response['message'] == "success") {
                $('#actions').hide();
                $('#proc-success-message').html("Analysis removed.");
                $('.toast-proc-success').toast('show');
                refresh();
            }
            if (response['message'] == "error") {
                $('#proc-error-message').html("Invalid request");
                $('.toast-proc-error').toast('show');
            }
        },
        error: function (error) {
            $('#proc-error-message').html("Something went wrong (500) ");
            $('.toast-proc-error').toast('show');
        },
        cache: false,
        contentType: false,
        processData: false
    });
}

$(document).ready(function () {
    window.setInterval('refresh()', 60000);
    $('.delete').on('click', function () {
        $(this).closest('tr').remove();
    });
    $('.spinner-main').hide();
    $('.container').show();
    $('.container-fluid').show();
});

const sidebar = document.querySelector(".sidebar2");
const overlay = document.querySelector(".overlay");

if (sidebar) {
    overlay.addEventListener('click', () => { sidebar.classList.remove('active'), overlay.classList.remove('active') });
    function GetInvest(case_id) {
        $(".spinnerside").removeClass("d-none");
        $(".sidecontent").addClass("d-none");
        var url = $("#all-investigations").attr("data-url");
        $.get(url, { sa_case_id: case_id }, // url
            function (response, textStatus, jqXHR) {  // success callback
                if (textStatus == "success") {
                    if (response['message'] == "success") {
                        if (response['result'][0].fields.os_version == "Linux") {
                            $(".sidebar-invest-logo").html("<i class='fa-brands fa-linux fa-3x' ></i>");
                        }
                        if (response['result'][0].fields.os_version == "Windows") {
                            $(".sidebar-invest-logo").html("<i class='fa-brands fa-windows fa-3x' ></i>");
                        }

                        if (response['result'][0].fields.os_version == "MacOs") {
                            $(".sidebar-invest-logo").html("<i class='fa-brands fa-apple fa-3x' ></i>");
                        }

                        $(".sidebar-invest-name").html(response['result'][0].fields.title);
                        $(".sidebar-invest-desc").html(response['result'][0].fields.description);
                        $(".sidebar-invest-team").html(response['result'][0].fields.investigators);


                        if (response['result'][0].fields.status == "0") {
                            $(".invest-card-link").addClass("d-none");
                            $(".card-start").removeClass("d-none");
                            $(".a-start").attr("onclick", "StartAnalysis(" + case_id + ");")
                        }

                        if (response['result'][0].fields.status == "1") {
                            $(".invest-card-link").addClass("d-none");
                            $(".card-cancel").removeClass("d-none");
                            $(".a-cancel").attr("onclick", "CancelAnalysis(" + case_id + ");")
                        }

                        if (response['result'][0].fields.status == "2") {
                            $(".invest-card-link").addClass("d-none");
                            $(".card-start").removeClass("d-none");
                            $(".card-review").removeClass("d-none");
                            $(".a-review").attr("onclick", "ReviewInvest(" + case_id + ");")
                            $(".a-start").attr("onclick", "StartAnalysis(" + case_id + ");")
                        }
                        if (response['result'][0].fields.status == "4") {
                            $(".invest-card-link").addClass("d-none");
                            $(".card-review").removeClass("d-none");
                            $(".card-start").removeClass("d-none");
                            $(".a-review").attr("onclick", "ReviewInvest(" + case_id + ");")
                            $(".a-start").attr("onclick", "StartAnalysis(" + case_id + ");")
                        }

                        $(".card-delete").removeClass("d-none");
                        $(".card-custom").removeClass("d-none");
                        $(".a-delete").attr("onclick", "DeleteAnalysis(" + case_id + ");")
                        $(".a-custom").attr("onclick", "EditInvest(" + case_id + ");")
                        $(".spinnerside").addClass("d-none");
                        $(".sidecontent").removeClass("d-none");
                    }
                    if (response['message'] == "error") {
                        $('#proc-error-message').html("Something went wrong getting the case.");
                        $('.toast-proc-error').toast('show');
                    }
                    $('.invest-details').show();
                    $('.spinner-invest').hide();
                }
            });
        sidebar.classList.add('active');
        overlay.classList.add('active');
    }
}

$("#searchbar").on("keyup", function () {
    var value = $(this).val().toLowerCase();
    $('div[data-role="investigations"]').filter(function () {
        $(this).toggle($(this).find('span').text().toLowerCase().indexOf(value) > -1)
    });
});



