var cases;
var reconnectDelay = 10000;
function get_cases() {
    $.ajax({
        'url': "/api/cases/",
        'method': "GET",
        'contentType': 'application/json'
    }).done(function (data) {
        try{
            cases.destroy();
        }
        catch{
            // Nothing to do.
        }
        cases = $('#cases').DataTable({
            rowCallback: function (row, data, index) {
                $(row).attr('value', data.case_id);
                $(row).attr('id', data.case_id);
            },
            "aaData": data,
            "aoColumns": [
                {  
                    mData: "case_id",
                    mRender: function (case_id, type) {
                        div = document.createElement('div');
                        div.setAttribute('class','align-items-center');
                        logo = document.createElement('i');
                        code = document.createElement('code');
                        logo.setAttribute('class','fas fa-hashtag m-2');
                        code.textContent = case_id;
                        div.appendChild(logo);
                        div.appendChild(code);
                        return div.outerHTML;
                    }
                },
                {  
                    mData: "case_name",
                    mRender: function (case_name, type) {
                        div = document.createElement('div');
                        div.setAttribute('class','align-items-center');
                        logo = document.createElement('i');
                        span = document.createElement('span');
                        span.setAttribute('class','text-info');
                        logo.setAttribute('class','fas fa-suitcase m-2');
                        span.textContent = case_name;
                        div.appendChild(logo);
                        div.appendChild(span);
                        return div.outerHTML;
                    }
                },
                {  
                    mData: "case_description",
                    mRender: function (case_description, type) {
                        div = document.createElement('div');
                        div.setAttribute('class','align-items-center');
                        logo = document.createElement('i');
                        span = document.createElement('span');
                        span.setAttribute('class','text-muted');
                        logo.setAttribute('class','fas fa-circle-info m-2');
                        span.textContent = case_description;
                        div.appendChild(logo);
                        div.appendChild(span);
                        return div.outerHTML;
                    }
                },
                {  
                    mData: "case_last_update",
                    mRender: function (case_last_update, type) {
                        div = document.createElement('div');
                        div.setAttribute('class','align-items-center');
                        logo = document.createElement('i');
                        span = document.createElement('span');
                        span.setAttribute('class','text-muted');
                        logo.setAttribute('class','fas fa-calendar m-2');
                        span.textContent = case_last_update;
                        div.appendChild(logo);
                        div.appendChild(span);
                        return div.outerHTML;
                    }
                },
            ],
            "aLengthMenu": [[25, 50, 75, -1], [25, 50, 75, "All"]],
            "iDisplayLength": 25
        });
        $('.dataTable').on('click', 'tbody tr', function () {
            display_case($(this).attr('value'));
        });
    });
}

function create_new_case() {
    var formData = {
        case_name: $('#id_case_name').val(),
        case_description: $('#id_case_description').val(),
        linked_users: $('#id_linked_users').val(),
    };
    $.ajaxSetup({
        beforeSend: function (xhr, settings) {
            xhr.setRequestHeader("X-CSRFToken", document.querySelector('[name=csrfmiddlewaretoken]').value);
        }
    });
    $.ajax({
        type: "POST",
        url: "/api/cases/",
        data: formData,
        dataType: "json",
        success: function (response) {
            toastr.success("Case created.")
            $('#modal_case_create').modal('toggle');
            clear_form()
        },
        error: function (xhr, status, error) {
            toastr.error("Error while creating the case, make sure all the fields are completed."); 
        }
    });
}


function save_case(case_id) {
    var formData = {
        case_name: $('#id_case_name').val(),
        case_description: $('#id_case_description').val(),
        linked_users: $('#id_linked_users').val(),
    };
    $.ajaxSetup({
        beforeSend: function (xhr, settings) {
            xhr.setRequestHeader("X-CSRFToken", document.querySelector('[name=csrfmiddlewaretoken]').value);
        }
    });
    $.ajax({
        type: "PUT",
        url: "/api/cases/" + case_id + "/",
        data: formData,
        dataType: "json",
        success: function (response) {
            toastr.success("Case updated.")
            $('#modal_case_create').modal('toggle');
            $(':input', '#case_form')
                .not(':button, :submit, :reset, :hidden')
                .val('')
                .prop('checked', false)
                .prop('selected', false);
        },
        error: function (xhr, status, error) {
            toastr.error("Could not edit the case: " + error);
        }
    });
}

function display_case(case_id) {
    $('.modal_case_review').modal('show');
    $.ajax({
        type: "GET",
        url: "/api/cases/" + case_id + "/",
        dataType: "json",
        success: function (case_data) {
            $.ajax({
                type: "GET",
                url: "/api/evidences/case/" + case_id + "/",
                dataType: "json",
                success: function (evidence_data) {
                    var usernames = case_data.linked_users.map(function (user) {
                        return user.username;
                    }).join(", ");
                    case_data.linked_users = usernames;
                    $('.modal_case_review').attr("id", case_data.case_id);
                    $('.case_number').text("Case #" + case_data.case_id + " : " + case_data.case_name);
                    $('.case_description').text(case_data.case_description);
                    $('.case_users').text(case_data.linked_users);
                    $('.case_info').removeClass('placeholder');
                    $("#linked_evidences").empty();
                    for (var i = 0; i < evidence_data.length; i++) {
                        const tr = document.createElement('tr');
                        const td_name = document.createElement('td');
                        const td_os = document.createElement('td');
                        const td_status = document.createElement('td');
                        td_name.textContent = evidence_data[i].dump_name;
                        td_os.textContent = evidence_data[i].dump_os;
                        td_status.textContent = evidence_data[i].dump_status + "%";
                        tr.appendChild(td_name)
                        tr.appendChild(td_os)
                        tr.appendChild(td_status)
                        $("#linked_evidences").append(tr);
                    }
                    $('.case_info').removeClass('placeholder');
                },
                error: function (xhr, status, error) {
                    toastr.error("Error when fetching your case: "+ error);
                }
            });
        },
        error: function (xhr, status, error) {
            toastr.error("Error when fetching your case: " + error);
        }
    });
}

function delete_case(case_id) {
    $.ajaxSetup({
        beforeSend: function (xhr, settings) {
            xhr.setRequestHeader("X-CSRFToken", document.querySelector('[name=csrfmiddlewaretoken]').value);
        }
    });
    $.ajax({
        type: "DELETE",
        url: "/api/cases/" + case_id + "/",
        dataType: "json",
        success: function (data) {
            $('.modal_case_review').attr("id", NaN);
        },
        error: function (xhr, status, error) {
            toastr.error("Could not delete the case: " + error);
        }
    });
}

function edit_case(case_id) {
    // Make an AJAX GET request to retrieve the case details
    $.ajax({
        url: "/api/cases/" + case_id + "/",
        type: "GET",
        success: function (data) {
            // Populating the form fields with the received case details
            $("#id_case_name").val(data.case_name);
            $("#id_case_description").val(data.case_description);
            $("#id_linked_users").val(data.linked_users);
            // Handle linked_users field which is a multiple select
            var linkedUsersSelect = $("#id_linked_users");
            // Select the values received for linked_users
            var selectedValues = data.linked_users;
            selectedValues.forEach(function (value) {
                linkedUsersSelect.find("option[value='" + value.id + "']").prop("selected", true);
            });
            // Hide the current modal 
            $('.modal_case_review').modal('toggle');
            // Show the form
            $('#modal_case_create').modal('show');
        },
        error: function (xhr, textStatus, errorThrown) {
            alert("Failed to retrieve case details: " + textStatus);
        }
    });
}

function clear_form() {
    $(':input', '#case_form')
        .not(':button, :submit, :reset, :hidden')
        .val('')
        .prop('checked', false)
        .prop('selected', false);
}

function reconnectWebSocket() {
    toastr.info("Trying to reconnect in " + reconnectDelay / 1000 + "seconds");
    setTimeout(function () {
        connectWebSocket(); // Call the function to connect WebSocket again
        // Increase the reconnect delay exponentially
        reconnectDelay *= 2;
    }, reconnectDelay);
}

function connectWebSocket() {
    const socket_cases = new WebSocket(
        "ws://localhost:8001/ws/cases/"
    );

    socket_cases.onopen = function () {
        reconnectDelay = 1000;
        get_cases();
    };

    socket_cases.onmessage = function (e) {
        result = JSON.parse(e.data);
        if (result.status == "created"){
            try {
                cases.row("#" + result.message.case_id).data(result.message);
            }
            catch {
                cases.row.add(result.message).draw().node();
            }
        }
        
        if (result.status == "deleted"){
            try {
                cases.row("#" + result.message.case_id).remove().draw();   
            }
            catch {
                toastr.error('Could not delete the case, please try again.');
            }
        }

    };

    socket_cases.onclose = function () {
        toastr.warning("Synchronization lost.");
        try{
            cases.rows().remove().draw();
        }
        catch{

        }
        reconnectWebSocket(); // Call the function to reconnect after connection is closed
    };

    socket_cases.onerror = function (error) {
        toastr.error("Can't connect to the server.", error);
        socket_cases.close(); // Close the WebSocket connection if an error occurs
    };
}

$(document).ready(function () {
    connectWebSocket();
    $('.save_case').hide();
    $('#new_case').hide();
    $('.case_create').on('click', function () {
        $('#modal_case_create').modal('show');
        $('.save_case').hide();
        $('#new_case').show();
    });

    $('#modal_case_create').on('hide.bs.modal', function () {
        clear_form();
    });

    $('#new_case').on('click', function () {
        create_new_case();
    });

    $('.save_case').on('click', function () {
        const case_id = $('.save_case').attr('id');
        save_case(case_id);
        clear_form();
    });


    $('#delete_case').on('click', function () {
        $('.modal_case_review').modal('hide');
        $('.modal_case_delete').modal('show');
    });

    $('#delete_case_confirm').on('click', function () {
        const case_id = $('.modal_case_review').attr('id');
        clear_form();
        delete_case(case_id);
        $('.modal_case_delete').modal('hide');
    });

    $('#edit_case').on('click', function () {
        $('.save_case').show();
        $('#new_case').hide();
        const case_id = $('.modal_case_review').attr('id');
        $('.save_case').attr('id', case_id);
        edit_case(case_id);
    });
});

