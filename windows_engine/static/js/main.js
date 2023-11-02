$(document).ready(function() {
    const evidence_id = $('.main').attr('id');
    $('#sids_datatable').hide();
    $('#privs_datatable').hide();
    $('#envars_datatable').hide();
    $('#dlllist_datatable').hide();
    $('#sessions_datatable').hide();
    var timeline_data;
    display_pstree(evidence_id);
    display_timeline(evidence_id);

    $('.card_sids').on('click', function(){
        pid = $('.process_id').attr('id');
        display_sids(evidence_id,pid);
    });

    $('.card_privs').on('click', function(){
        pid = $('.process_id').attr('id');
        display_privs(evidence_id,pid);
    });
    
    $('.card_envars').on('click', function(){
        pid = $('.process_id').attr('id');
        display_envars(evidence_id,pid);
    });

    $('.card_dlllist').on('click', function(){
        pid = $('.process_id').attr('id');
        display_dlllist(evidence_id,pid);
    });

    $('.card_sessions').on('click', function(){
        pid = $('.process_id').attr('id');
        display_sessions(evidence_id,pid);
    });
    
});