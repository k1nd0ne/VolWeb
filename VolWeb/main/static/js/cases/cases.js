$(document).ready(function() {  
    $.ajax({
        'url': "/get_cases/",
        'method': "GET",
        'contentType': 'application/json'
    }).done( function(data) {
        console.log(data)
        $('#cases tbody').empty();
        $.each(data, function(index, item) {
            var usernames = item.linked_users.map(function(user) {
                return user.username;
              }).join(", ");
            $('#cases tbody').append('<tr><td>' + item.case_name + '</td><td>' + item.case_description + '</td><td>' + usernames + '</td><td>'+ item.case_last_update +'</td></tr>' );
        });
        $('#cases').DataTable();
    })
  
    $('.dataTable').on('click', 'tbody td', function() {
        //get textContent of the TD
        console.log('TD cell textContent : ', this.textContent)
        //get the value of the TD using the API 
        console.log('value by API : ', table.cell({ row: this.parentNode.rowIndex, column : this.cellIndex }).data());
      })
  
});
