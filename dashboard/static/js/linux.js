    $('#processListTable').on('click', 'tbody tr', function(event) {
      var table = $(this);
      if (table.hasClass("highlight")){
        table.removeClass("highlight");
      }
      else{
        table.addClass("highlight");
      }
    });
      //ProcessScan SearchBar

      $("#searchProcessList").on("keyup", function() {
        var value = $(this).val().toLowerCase();
        $("#processList tr").filter(function() {
          $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
        });
      });
      //Process Scan Search function
      $(document).ready(function(){
        $('.container').show();
        $('.container-fluid').show();
        $('.plugin').hide();
        $('.Case').show();
        $('.spinner-main').hide();
        $('.toast-other').toast('show');

        $('#main').show();
        $('#loading').hide();

      $("#PsListLink").on("click", function(){
        $('.plugin').hide();
        $('.PsList').show();
      });

      $("#CaseLink").on("click", function(){
        $('.plugin').hide();
        $('.Case').show();
      });
    });
