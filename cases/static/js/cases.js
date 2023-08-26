var cases;
function refresh_cases(){
    cases.api().destroy();
    get_cases();
}

function get_cases(){
    $.ajax({
        'url': "/api/cases/",
        'method': "GET",
        'contentType': 'application/json'
    }).done( function(data) {
        $.each(data, function(index, item) {
            var usernames = item.linked_users.map(function(user) {
                return user.username;
            }).join(", ");
            item.linked_users = usernames;
        });
        cases = $('#cases').dataTable({      
            rowCallback: function(row, data, index) {
                $(row).attr('value', data.case_id); // Add id to the tr element
              },
            "aaData" : data,
            "aoColumns": [
                { "data": "case_id" },
                { "data": "case_name" },
                { "data": "case_description" },
                { "data": "linked_users" },
                { "data": "case_last_update"}           
            ],
            "aLengthMenu": [[25, 50, 75, -1], [25, 50, 75, "All"]],
            "iDisplayLength": 25
        });
        $('.dataTable').on('click', 'tbody tr', function() {
           display_case($(this).attr('value')); 
        });
    });
}

function create_new_case(){
    var formData = {
        case_name: $('#id_case_name').val(),
        case_description: $('#id_case_description').val(),
        linked_users:  $('#id_linked_users').val(),
    };
    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            xhr.setRequestHeader("X-CSRFToken", document.querySelector('[name=csrfmiddlewaretoken]').value);
        }
    });
    $.ajax({
        type: "POST",
        url: "/api/cases/",
        data: formData,
        dataType: "json",
        success: function(response) {
            // Handle successful response
            $('#modal_case_create').modal('toggle');
            clear_form()
            refresh_cases()

        },
        error: function(xhr, status, error) {
            // Handle error response
            console.log(xhr.responseText);
            alert("An error occurred while submitting the form : " + xhr.responseText);
        }
    });
}


function save_case(case_id){
    var formData = {
        case_name: $('#id_case_name').val(),
        case_description: $('#id_case_description').val(),
        linked_users:  $('#id_linked_users').val(),
    };
    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            xhr.setRequestHeader("X-CSRFToken", document.querySelector('[name=csrfmiddlewaretoken]').value);
        }
    });
    $.ajax({
        type: "PUT",
        url: "/api/cases/"+case_id+"/",
        data: formData,
        dataType: "json",
        success: function(response) {
            // Handle successful response
            console.log(response);
            $('#modal_case_create').modal('toggle');
            $(':input','#case_form')
            .not(':button, :submit, :reset, :hidden')
            .val('')
            .prop('checked', false)
            .prop('selected', false);
            refresh_cases()

        },
        error: function(xhr, status, error) {
            // Handle error response
            console.log(xhr.responseText);
            alert("An error occurred while submitting the form.");
        }
    });
}

// TODO : ERROR HANDLING
function display_case(case_id){
    $('.modal_case_review').modal('show');
    $.ajax({
            type: "GET",
            url: "/api/cases/"+case_id+"/",
            dataType: "json",
            success: function(case_data) {
                $.ajax({
                    type: "GET",
                    url: "/api/evidences/case/"+case_id+"/",
                    dataType: "json",
                    success: function(evidence_data) {
                        var usernames = case_data.linked_users.map(function(user) {
                            return user.username;
                        }).join(", ");
                        case_data.linked_users = usernames;
                        $('.modal_case_review').attr("id",case_data.case_id);
                        $('.case_number').text("Case #"+case_data.case_id + " : " + case_data.case_name);
                        $('.case_description').text(case_data.case_description);
                        $('.case_users').text(case_data.linked_users);
                        $('.case_info').removeClass('placeholder');
                        $("#linked_evidences").empty();
                        for (var i = 0; i < evidence_data.length; i++)
                        {
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
                    error: function(xhr, status, error) {
                        // Handle error response
                        console.log(xhr.responseText);
                        alert("An error occurred while submitting the form.");
                    }
                });
            },
            error: function(xhr, status, error) {
                // Handle error response
                console.log(xhr.responseText);
                alert("An error occurred while submitting the form.");
            }
        });
    }


// TODO : ERROR HANDLING
function delete_case(case_id){
    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            xhr.setRequestHeader("X-CSRFToken", document.querySelector('[name=csrfmiddlewaretoken]').value);
        }
    });
    $.ajax({
        type: "DELETE",
        url: "/api/cases/"+case_id+"/",
        dataType: "json",
        success: function(data) {
            $('.modal_case_review').attr("id",NaN);
            $('.modal_case_review').modal('toggle');
            refresh_cases();
        },
        error: function(xhr, status, error) {
            // Handle error response
            console.log(xhr.responseText);
            alert("An error occurred while submitting the form.");
        }
        });
    }

function edit_case(case_id) {
    // Make an AJAX GET request to retrieve the case details
    $.ajax({
        url: "/api/cases/" + case_id + "/",
        type: "GET",
        success: function(data) {
        // Populating the form fields with the received case details
        $("#id_case_name").val(data.case_name);
        $("#id_case_description").val(data.case_description);
        $("#id_linked_users").val(data.linked_users);
        // Handle linked_users field which is a multiple select
        var linkedUsersSelect = $("#id_linked_users");
        // Select the values received for linked_users
        var selectedValues = data.linked_users;
        selectedValues.forEach(function(value) {
          linkedUsersSelect.find("option[value='" + value.id + "']").prop("selected",true);
        });
        // Hide the current modal 
        $('.modal_case_review').modal('toggle');
        // Show the form
        $('#modal_case_create').modal('show');
        },
        error: function(xhr, textStatus, errorThrown) {
        alert("Failed to retrieve case details: " + textStatus);
        }
    });
}

function clear_form(){
    $(':input','#case_form')
    .not(':button, :submit, :reset, :hidden')
    .val('')
    .prop('checked', false)
    .prop('selected', false);
}



$(document).ready(function() {
    $('.save_case').hide();
    $('#new_case').hide();
    $('.case_create').on('click', function() {
        $('#modal_case_create').modal('show');
        $('.save_case').hide();
        $('#new_case').show();
    });


    
    $('#modal_case_create').on('hide.bs.modal', function() {
        clear_form();
    });


    $('#new_case').on('click', function() {
        create_new_case();
    });

    $('.save_case').on('click', function() {
        const case_id = $('.save_case').attr('id');
        save_case(case_id);
        clear_form();
    });


    $('#delete_case').on('click', function() {
        const case_id = $('.modal_case_review').attr('id');
        clear_form();
        delete_case(case_id);
    });


    $('#edit_case').on('click', function() {
        $('.save_case').show();
        $('#new_case').hide();
        const case_id = $('.modal_case_review').attr('id');
        $('.save_case').attr('id',case_id);
        edit_case(case_id);
    });
    get_cases(); 
});

