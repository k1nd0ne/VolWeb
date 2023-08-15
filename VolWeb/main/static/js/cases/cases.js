$(document).ready(function() {
    $('.case_create').on('click', function() {
        $('#modal_case_create').modal('show');
     });

    $('#new_case').on('click', function() {
        create_new_case();
    });
    var cases;
    get_cases();

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
            csrfmiddlewaretoken : document.querySelector('[name=csrfmiddlewaretoken]').value
        };
    
        $.ajax({
        type: "POST",
        url: "/api/cases/",
        data: formData,
        dataType: "json",
        success: function(response) {
            // Handle successful response
            console.log(response);
            $(':input','#case_form')
            .not(':button, :submit, :reset, :hidden')
            .val('')
            .prop('checked', false)
            .prop('selected', false);
            $('#modal_case_create').modal('toggle');
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
        $('#modal_case_review').modal('show');
        $.ajax({
            'url': "/api/cases/"+case_id+"/",
            'method': "GET",
            'contentType': 'application/json'
        }).done(function(data) {
            var usernames = data.linked_users.map(function(user) {
                return user.username;
            }).join(", ");
            data.linked_users = usernames;
            $('.case_number').text("Case #"+data.case_id);
            $('.case_name').text(data.case_name);
            $('.case_description').text(data.case_description);
            $('.case_users').text(data.linked_users);
            $('.case_info').removeClass('placeholder');

        });
    }
});



