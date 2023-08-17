$(document).ready(function() {
  get_recent_cases();
});

function get_recent_cases(){
  $.ajax({
    url: '/api/cases/',
    dataType: 'JSON',
    success: function(data){
      $("#cases_placeholder").hide();
      for (var i = 0; i < data.length; i++)
      {
        const li_item = document.createElement('li');
        li_item.setAttribute('class','list-group-item');
        li_item.textContent = data[i].case_name;
        $("#recent_cases").append(li_item);
        if (i==4)
          break;
      }
      
    }
  });
}