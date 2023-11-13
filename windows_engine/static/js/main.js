$(document).ready(function() {
    const evidence_id = $('.main').attr('id');
    var timeline_data;
    display_pstree(evidence_id);
    display_timeline(evidence_id);

    $('.card_handles').on('click', function(){
        pid = $('.process_id').attr('id');
        compute_handles(evidence_id,pid);
    });

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

    $('.card_network').on('click', function(){
        display_network(evidence_id);
    });

    $('.card_sessions').on('click', function(){
        pid = $('.process_id').attr('id');
        display_sessions(evidence_id,pid);
    });
    
    $('.card_credentials').on('click', function(){
        display_credentials(evidence_id);
    });

    toastr.options = {
        "closeButton": true,
        "debug": false,
        "newestOnTop": false,
        "progressBar": true,
        "positionClass": "toast-top-right",
        "preventDuplicates": false,
        "onclick": null,
        "showDuration": "300",
        "hideDuration": "1000",
        "timeOut": "5000",
        "extendedTimeOut": "1000",
        "showEasing": "swing",
        "hideEasing": "linear",
        "showMethod": "fadeIn",
        "hideMethod": "fadeOut"
    }

    // toastr.warning('Your toast message here');
    // toastr.error('Your toast message here');
    // toastr.success('Your Toast message here', 'Title');

});