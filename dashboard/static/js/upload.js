/*
The FileUpload Javascript function:
  - Manage the form errors
  - Upload file chunk by chunk
/!\ This function needs a rework along with the linked investigations views /!\
*/

class FileUpload {

    constructor(input) {
        this.input = input
        this.max_length = 1024 * 1024 * 10;
    }

    create_progress_bar() {
        var progress = `<div class="file-icon">
                            <i class="fa fa-file-o" aria-hidden="true"></i>
                        </div>
                        <div class="file-details">
                            <p class="filename"></p>
                            <small class="textbox"></small>
                            <div class="progress" style="margin-top: 5px;">
                                <div class="progress-bar" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100" style="width: 0%">
                                </div>
                            </div>
                        </div>`
        document.getElementById('uploaded_files').innerHTML = progress
    }

    upload() {
        this.initFileUpload();
    }

    initFileUpload() {
        const alertBox = document.getElementById('alert-box');
        const cancelBtn = document.getElementById('cancel-btn');
        const csrf = document.getElementsByName('csrfmiddlewaretoken');
        const title = document.getElementById('id_title');
        const description = document.getElementById('id_description');
        const investigators = document.getElementById('id_investigators');
        const os_version = document.getElementById('id_os_version');
        const investName = document.getElementById('id_title');
        const investDesc = document.getElementById('id_description');
        const filefield = document.getElementById('fileupload');
        alertBox.innerHTML = "";
        if(title.value == ""){
                    alertBox.innerHTML = "<p class='text-danger'>Please fill out the hostname field.</p>";
                    return;

        }
        if(filefield.value == ""){
                    alertBox.innerHTML = "<p class='text-danger'>Please choose a file.</p>";
                    return;

        }
        if(description.value == ""){
                    alertBox.innerHTML = "<p class='text-danger'>Please fill out the description field.</p>";
                    return;

        }
        if(investigators.value == ''){
                    alertBox.innerHTML = "<p class='text-danger'>Please select at least one Forensics analyst on the investigation.</p>";
                    return;

        }
        if(os_version.value == ''){
                    alertBox.innerHTML = "<p class='text-danger'>Please fill the os version field.</p>";
                    return;

        }
        this.create_progress_bar();
        this.file = this.input.files[0];
        this.upload_file(0, null);
    }

    //upload file
    upload_file(start, model_id) {
        const alertBox = document.getElementById('alert-box');
        const cancelBtn = document.getElementById('cancel-btn');
        const csrf = document.getElementsByName('csrfmiddlewaretoken');
        const title = document.getElementById('id_title');
        const description = document.getElementById('id_description');
        const investigators = document.getElementById('id_investigators');
        const os_version = document.getElementById('id_os_version');
        const investName = document.getElementById('id_title');
        const investDesc = document.getElementById('id_description');
        const filefield = document.getElementById('fileupload');
        const uploadForm = document.getElementById('upload-form');
        uploadForm.classList.add('d-none');
        investName.innerHTML = "Investigation : " + title.value;
        investDesc.innerHTML = " OS Version : " + os_version.value;
        investDesc.innerHTML += "</br> Context : " + description.value;
        investDesc.innerHTML += "</br> Investigators : " + investigators.value;
        var end;
        var self = this;
        var existingPath = model_id;
        var formData = new FormData();
        var nextChunk = start + this.max_length + 1;
        var currentChunk = this.file.slice(start, nextChunk);
        var uploadedChunk = start + currentChunk.size
        if (uploadedChunk >= this.file.size) {
            end = 1;
        } else {
            end = 0;
        }
        formData.append('file', currentChunk)
        formData.append('name', this.file.name)
        $('.filename').text(this.file.name)
        $('.textbox').text("Uploading file")
        formData.append('eof', end)
        formData.append('existingPath', existingPath);
        formData.append('nextSlice', nextChunk);
        formData.append('title', title.value);
        formData.append('description', description.value);
        formData.append('status', '0');
        formData.append('os_version', os_version.value);
        formData.append('investigators', investigators.value);
        formData.append('uid', 'null');
        $.ajaxSetup({
            headers: {
                "X-CSRFToken": document.querySelector('[name=csrfmiddlewaretoken]').value,
            }
        });
        $.ajax({
            xhr: function () {
                var xhr = new XMLHttpRequest();
                xhr.upload.addEventListener('progress', function (e) {
                    if (e.lengthComputable) {
                        if (self.file.size < self.max_length) {
                            var percent = Math.round((e.loaded / e.total) * 100);
                        } else {
                            var percent = Math.round((uploadedChunk / self.file.size) * 100);
                        }
                        $('.progress-bar').css('width', percent + '%')
                        $('.progress-bar').text(percent + '%')
                    }
                });
                return xhr;
            },

            url: '',
            type: 'POST',
            cache: false,
            processData: false,
            contentType: false,
            data: formData,
            error: function (xhr) {
                alertBox.innerHTML = "<p class='text-danger'>Something went wrong : "+ xhr +"</p>";
                console.log(xhr);
            },
            success: function (res) {
                if (nextChunk < self.file.size) {
                    console.log(res)
                    // upload file in chunks
                    existingPath = res.existingPath
                    self.upload_file(nextChunk, existingPath);
                } else {
                    alertBox.innerHTML = "<p class='text-white'>Upload completed you can now start the analysis from <a href=\"../\">here</a></p>";
                }
            }
        });
    };
}

(function ($) {
    $('#submit').on('click', (event) => {
        event.preventDefault();
        var uploader = new FileUpload(document.querySelector('#fileupload'))
        uploader.upload();
    });
})(jQuery);
