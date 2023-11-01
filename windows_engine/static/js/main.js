$(document).ready(function() {
    const evidence_id = $('.main').attr('id');    
    var timeline_data;
    display_pstree(evidence_id);
    display_timeline(evidence_id);
    $('.card_sids').on('click', function(){
        pid = $('.process_id').attr('id');
        display_sids(pid);
    });
    
});