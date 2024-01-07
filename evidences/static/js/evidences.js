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
            toastr.error("Error : " + err);
        }
        if (data) {
            toastr.success("Upload Success");
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
        toastr.warrning("Nothing to upload");
    }
}

function refresh_evidences(){
    evidences.destroy();
    get_evidences();
}


function get_evidences(){
    $.ajax({
        'url': "/api/evidences/",
        'method': "GET",
        'contentType': 'application/json'
    }).done(function(data) {
        evidences = $('#evidences').DataTable({      
            rowCallback: function(row, data, index) {
                $(row).attr('value', data.dump_id); // Add id to the tr element
              },
            "aaData" : data,
            "aoColumns": [
                {  
                    mData: "dump_name",
                    mRender: function (dump_name, type) {
                        div = document.createElement('div');
                        div.setAttribute('class','align-items-center');
                        logo = document.createElement('i');
                        code = document.createElement('code');
                        logo.setAttribute('class','fas fa-memory m-2');
                        code.textContent = dump_name;
                        div.appendChild(logo);
                        div.appendChild(code);
                        return div.outerHTML;
                    }
                },
                {  
                    mData: "dump_os",
                    mRender: function (dump_os, type) {
                        div = document.createElement('div');
                        div.setAttribute('class','align-items-center');
                        logo = document.createElement('i');
                        span = document.createElement('span');
                        if(dump_os == "Windows"){
                            logo.setAttribute('class','fab fa-windows m-2');
                            span.setAttribute('class','text-primary');
                        }
                        else{
                            logo.setAttribute('class','fab fa-linux m-2');
                            span.setAttribute('class','text-info');
                        }
                        span.textContent = dump_os;
                        div.appendChild(logo);
                        div.appendChild(span);
                        return div.outerHTML;
                    }
                },
                {  
                    mData: "dump_linked_case",
                    mRender: function (dump_linked_case, type) {
                        div = document.createElement('div');
                        div.setAttribute('class','align-items-center');
                        logo = document.createElement('i');
                        span = document.createElement('span');
                        logo.setAttribute('class','fas fa-suitcase m-2');
                        span.textContent = dump_linked_case;
                        div.appendChild(logo);
                        div.appendChild(span);
                        return div.outerHTML;
                    }
                },
                {  
                    mData: "dump_etag",
                    mRender: function (dump_etag, type) {
                        div = document.createElement('div');
                        div.setAttribute('class','align-items-center');
                        logo = document.createElement('i');
                        span = document.createElement('span');
                        logo.setAttribute('class','fas fa-bucket m-2');
                        span.textContent = dump_etag;
                        div.appendChild(logo);
                        div.appendChild(span);
                        return div.outerHTML;
                    }
                },
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
                toastr.error("An error occurred : "  + error);
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
            toastr.error("An error occurred : "  + error);
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
            toastr.error("An error occurred : "  + error);
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

function reconnectWebSocket() {
    toastr.info("Trying to reconnect in " + reconnectDelay / 1000 + "seconds");
    setTimeout(function () {
        connectWebSocket(); // Call the function to connect WebSocket again
        // Increase the reconnect delay exponentially
        reconnectDelay *= 2;
    }, reconnectDelay);
}

function connectWebSocket() {
    const socket_evidences = new WebSocket(
        "ws://localhost:8000/ws/evidences/"
    );

    socket_evidences.onopen = function () {
        reconnectDelay = 1000;
        get_evidences();
    };

    socket_evidences.onmessage = function (e) {
        result = JSON.parse(e.data);
        if(result.status == "created"){
            try {
                evidences.row("#" + result.message.evidence_id).data(result.message);
            }
            catch {
                evidences.row.add(result.message).draw().node();
            }
        }

        if(result.status == "deleted"){
            try {
                evidences.row("#" + result.message.evidence_id).remove().draw();   
            }
            catch {
                toastr.error('Could not delete the case, please try again.');
            }           
        }

    };

    socket_evidences.onclose = function () {
        toastr.warning("Synchronization lost.");
        evidences.rows().remove().draw();
        reconnectWebSocket(); // Call the function to reconnect after connection is closed
    };

    socket_evidences.onerror = function (error) {
        toastr.error("Can't connect to the server.", error);
        socket_evidences.close(); // Close the WebSocket connection if an error occurs
    };
}


$(document).ready(function() {   
    connectWebSocket();

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
                toastr.error("An error occurred : "  + error);
            }
        });
    });


    $('#delete_evidence').on('click', function() {
        const evidence_id = $('.modal_evidence_review').attr('id');
        clear_form();
        delete_evidence(evidence_id);
    });

    $('#review_evidence').on("click", function(){
        const evidence_id = $('.modal_evidence_review').attr('id');
        var url = "/review/windows/" + evidence_id + '/';
        window.location.href = url; // This line will redirect the user to the constructed url
      });

    $('.evidence_create').on('click', function() {
        $('#modal_evidence_create').modal('show');
    });

    $('#modal_evidence_create').on('hide.bs.modal', function() {
        clear_form();
    });

});