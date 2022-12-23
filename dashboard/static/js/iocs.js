$("#searchbar").on("keyup", function () {
    var value = $(this).val().toLowerCase();
    $('div[data-role="iocs"]').filter(function () {
        $(this).toggle($(this).find('span').text().toLowerCase().indexOf(value) > -1)
    });
});
//Ask for IOC deletion
function DeleteIOC(id) {
    const csrf = document.getElementsByName('csrfmiddlewaretoken');
    const fd = new FormData();
    var url = $('div[data-role="iocs"]').attr('data-url');
    fd.append('csrfmiddlewaretoken', csrf[0].value);
    fd.append('ioc_id', id);
    $.ajax({
        type: 'POST',
        url: url,
        enctype: 'multipart/form-data',
        data: fd,
        beforeSend: function () {
        },
        success: function (response) {
            location.reload();
        },
        error: function (error) {

        },
        cache: false,
        contentType: false,
        processData: false
    });
}

