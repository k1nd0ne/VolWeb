function compute_handles(evidence_id,pid){
    $.ajax({
        type: "GET",
        url: "/tasks/windows/"+evidence_id+"/handles/"+pid+"/",
        dataType: "json",
        beforeSend: function(){
            $(".card_handles").hide();
            $(".loading_handles").show();
          },
        success: function(data){
        },
        complete:function(data){
            $(".card_handles").show();
            $(".loading_handles").hide();
          },
        error: function(xhr, status, error) {
            toastr.error("An error occurred while computing the handles : "  + error);
        }
      });
}