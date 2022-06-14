    $('#processListTable').on('click', 'tbody tr', function(event) {
      var table = $(this);
      if (table.hasClass("highlight")){
        table.removeClass("highlight");
      }
      else{
        table.addClass("highlight");
      }
    });

    $('#processMapsTable').on('click', 'tbody tr', function(event) {
      var table = $(this);
      if (table.hasClass("highlight")){
        table.removeClass("highlight");
      }
      else{
        table.addClass("highlight");
      }
    });

    $('#TtyCheckTable').on('click', 'tbody tr', function(event) {
      var table = $(this);
      if (table.hasClass("highlight")){
        table.removeClass("highlight");
      }
      else{
        table.addClass("highlight");
      }
    });

    $('#BashTable').on('click', 'tbody tr', function(event) {
      var table = $(this);
      if (table.hasClass("highlight")){
        table.removeClass("highlight");
      }
      else{
        table.addClass("highlight");
      }
    });

    $('#ElfsTable').on('click', 'tbody tr', function(event) {
      var table = $(this);
      if (table.hasClass("highlight")){
        table.removeClass("highlight");
      }
      else{
        table.addClass("highlight");
      }
    });

    $('#LsofTable').on('click', 'tbody tr', function(event) {
      var table = $(this);
      if (table.hasClass("highlight")){
        table.removeClass("highlight");
      }
      else{
        table.addClass("highlight");
      }
    });

    $('#TtyCheck').on('click', 'tbody tr', function(event) {
      var table = $(this);
      if (table.hasClass("highlight")){
        table.removeClass("highlight");
      }
      else{
        table.addClass("highlight");
      }
    });

      $("#searchProcessList").on("keyup", function() {
        var value = $(this).val().toLowerCase();
        $("#processList tr").filter(function() {
          $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
        });
      });

      $("#searchBash").on("keyup", function() {
        var value = $(this).val().toLowerCase();
        $("#Bash tr").filter(function() {
          $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
        });
      });

      $("#searchProcessMaps").on("keyup", function() {
        var value = $(this).val().toLowerCase();
        $("#processMaps tr").filter(function() {
          $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
        });
      });

      $("#searchLsof").on("keyup", function() {
        var value = $(this).val().toLowerCase();
        $("#Lsof tr").filter(function() {
          $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
        });
      });

      $("#searchTtyCheck").on("keyup", function() {
        var value = $(this).val().toLowerCase();
        $("#TtyCheck tr").filter(function() {
          $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
        });
      });

      $("#searchElfs").on("keyup", function() {
        var value = $(this).val().toLowerCase();
        $("#Elfs tr").filter(function() {
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

      $("#PsTreeLink").on("click", function(){
        $('.plugin').hide();
        $('.PsTree').show();
      });

      $("#CaseLink").on("click", function(){
        $('.plugin').hide();
        $('.Case').show();
      });

      $("#BashLink").on("click", function(){
        $('.plugin').hide();
        $('.Bash').show();
      });

      $("#ProcMapsLink").on("click", function(){
        $('.plugin').hide();
        $('.ProcMaps').show();
      });

      $("#LsofLink").on("click", function(){
        $('.plugin').hide();
        $('.Lsof').show();
      });

      $("#TtyCheckLink").on("click", function(){
        $('.plugin').hide();
        $('.TtyCheck').show();
      });

      $("#ElfsLink").on("click", function(){
        $('.plugin').hide();
        $('.Elfs').show();
      });

    });
