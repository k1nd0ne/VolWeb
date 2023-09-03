var evidences;

function upload_and_create_evidence(bucket_id){
    // configuration for Minio/AWS
    AWS.config.update({
        accessKeyId: 'user',
        secretAccessKey: 'password',
        region: 'us-west-2' // (We don't care with Minio)
    });

    // create an S3 instance
    const s3 = new AWS.S3({
        endpoint: 'http://127.0.0.1:9000', // Minio server
        s3ForcePathStyle: true,
        signatureVersion: 'v4'
    });

    const fileChooser = document.getElementById('file-chooser');
    const file = fileChooser.files[0];
    
    if (file) {
        const uploader = s3.upload({
        Bucket: bucket_id,
        Key: file.name,
        Body: file,
        ACL: 'public-read'
        });

        uploader.on('httpUploadProgress', function(evt) {
        $('.upload-progress').removeClass("d-none");
        $('#evidence_form').hide();
        $('#upload-button').hide();
        
        console.log("Uploaded :: " + parseInt((evt.loaded * 100) / evt.total)+'%');
        document.getElementById('upload-progress').innerHTML = "Uploaded :: " + parseInt((evt.loaded * 100) / evt.total)+'%';
        });

        uploader.send(function(err, data) {
        fileChooser.value = '';
        document.getElementById('upload-progress').innerHTML = '';
        if (err) {
            console.log("Error", err);
        }
        if (data) {
            console.log("Upload Success", data);
            create_evidence(file.name,data.ETag);
            $('#modal_evidence_create').modal('toggle');
            $('.upload-progress').addClass("d-none");
            $('#evidence_form').show();
            $('#upload-button').show();
            clear_form();
            refresh_evidences();
        }
        });
    } else {
        console.log('Nothing to upload.');
    }
}

function refresh_evidences(){
    evidences.api().destroy();
    get_evidences();
}


function get_evidences(){
    $.ajax({
        'url': "/api/evidences/",
        'method': "GET",
        'contentType': 'application/json'
    }).done(function(data) {
        evidences = $('#evidences').dataTable({      
            rowCallback: function(row, data, index) {
                $(row).attr('value', data.dump_id); // Add id to the tr element
              },
            "aaData" : data,
            "aoColumns": [
                { "data": "dump_name" },
                { "data": "dump_os" },
                { "data": "dump_linked_case" },
                { "data": "dump_etag" },
            ],
            "aLengthMenu": [[25, 50, 75, -1], [25, 50, 75, "All"]],
            "iDisplayLength": 25
        });
        $('.dataTable').on('click', 'tbody tr', function() {
            display_evidence($(this).attr('value')); 
         });
    });
}

// TODO : ERROR HANDLING
function display_evidence(evidence_id){
    $('.modal_evidence_review').modal('show');
    $.ajax({
            type: "GET",
            url: "/api/evidences/"+evidence_id+"/",
            dataType: "json",
            success: function(evidence_data){
                $('.modal_evidence_review').attr("id",evidence_data.dump_id);
                $('.evidence_etag').text(evidence_data.dump_etag);
                $('.evidence_name').text(evidence_data.dump_name);
                $('.evidence_os').text(evidence_data.dump_os);
                $('.evidence_status').text(evidence_data.dump_status);
                $('.evidence_info').removeClass('placeholder');
            },
            error: function(xhr, status, error) {
                // Handle error response
                console.log(xhr.responseText);
                alert("An error occurred while submitting the form.");
            }
        });
}

//TODO : ERROR HANDLING
function create_evidence(filename, etag){
    console.log(filename)
    var formData = {
        dump_name: filename,
        dump_etag: etag,
        dump_os: $('#id_dump_os').val(),
        dump_linked_case:  $('#id_dump_linked_case').val(),
    };
    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            xhr.setRequestHeader("X-CSRFToken", document.querySelector('[name=csrfmiddlewaretoken]').value);
        }
    });
    $.ajax({
        type: "POST",
        url: "/api/evidences/",
        data: formData,
        dataType: "json",
        success: function(response) {
            // Handle successful response
            console.log(response)
        },
        error: function(xhr, status, error) {
            // Handle error response
            console.log(xhr.responseText);
            alert("An error occurred while submitting the form : " + xhr.responseText);
        }
    });
}

// TODO : ERROR HANDLING
function delete_evidence(dump_id){
    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            xhr.setRequestHeader("X-CSRFToken", document.querySelector('[name=csrfmiddlewaretoken]').value);
        }
    });
    $.ajax({
        type: "DELETE",
        url: "/api/evidences/"+dump_id+"/",
        dataType: "json",
        success: function(data) {
            $('.modal_evidence_review').attr("id",NaN);
            $('.modal_evidence_review').modal('toggle');
            refresh_evidences();
        },
        error: function(xhr, status, error) {
            // Handle error response
            console.log(xhr.responseText);
            alert("An error occurred while submitting the form.");
        }
        });
    }

function clear_form(){
    $(':input','#evidence_form')
    .not(':button, :submit, :reset, :hidden')
    .val('')
    .prop('checked', false)
    .prop('selected', false);
}

$(document).ready(function() {    
    get_evidences();
    document.getElementById('upload-button').addEventListener('click', () => {
        
        // First we go an fetch the uuid of the bucket associated with the case selected by the user.
        const evidence_name = $('#id_dump_name').val()
        const evidence_os = $('#id_dump_os').val()
        const linked_case_id = $('#id_dump_linked_case').val()
        

        
        //Check if the user selected a case.
        if (evidence_name === '') {
            $('#form-error').text("Please enter a name for the evidence.");
            return
        }

        if (evidence_os === '') {
            $('#form-error').text("Please select an os for this evidence");
            return
        }

        if (linked_case_id === '') {
            $('#form-error').text("Please select a linked case.");
            return
        }
        $('#form-error').text("");
        
        $.ajax({
            type: "GET",
            url: "/api/cases/"+linked_case_id+"/",
            dataType: "json",
            success: function(data) {
                const bucket_name = data.case_bucket_id;
                //Ok we have the bucket uuid we can try to upload the file to the bucket.
                upload_and_create_evidence(bucket_name);
            },
            error: function(xhr, status, error) {
                // Handle error response
                console.log(xhr.responseText);
                alert("An error occurred while submitting the form.");
            }
        });
    });


    $('#delete_evidence').on('click', function() {
        const evidence_id = $('.modal_evidence_review').attr('id');
        clear_form();
        delete_evidence(evidence_id);
    });

    $('.evidence_create').on('click', function() {
        $('#modal_evidence_create').modal('show');
    });

    $('#modal_evidence_create').on('hide.bs.modal', function() {
        clear_form();
    });

});