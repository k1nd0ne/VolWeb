from django.urls import path
from . import views

urlpatterns = [
    
    #path('get_mac_bash/', views.get_bash, name='get_mac_bash'),
    #path('check_mac_syscall/', views.check_syscall, name='check_mac_syscall'),
    #path('check_mac_trap_table/', views.check_trap_table, name='check_mac_trap_table'),
    #path('check_mac_sysctl/', views.check_sysctl, name='check_mac_sysctl'),
    #path('get_mac_ifconfig/', views.get_ifconfig, name='get_mac_ifconfig'),
    #path('get_mac_kauth_listeners/', views.get_kauth_listeners, name='get_mac_kauth_listeners'),
    #path('get_mac_kauth_scopes', views.get_kauth_scopes, name='get_mac_kauth_scopes'),
    #path('get_mac_kevents', views.get_kevents, name='get_mac_kevents'),
    #path('get_mac_list_files', views.get_list_files, name='get_mac_list_files'),
    #path('get_mac_lsmod', views.get_lsmod, name='get_mac_lsmod'),
    #path('get_mac_lsof', views.get_lsof, name='get_mac_lsof'),
    #path('get_mac_malfind', views.get_malfind, name='get_mac_malfind'),
    #path('get_mac_mount', views.get_handles, name='get_mac_mount'),
    #path('get_mac_netstat', views.get_netstat, name='get_mac_netstat'),
    #path('get_mac_proc_maps', views.proc_maps, name='get_mac_proc_maps'),
    #path('get_mac_psaux', views.get_psaux, name='get_mac_psaux'),
    #path('get_mac_pslist', views.get_pslist, name='get_mac_pslist'),
    #path('get_mac_pstree', views.get_pstree, name='get_mac_pstree'),
    #path('get_mac_socket_filters', views.get_socket_filters, name='get_mac_socket_filters'),
    #path('check_mac_timers', views.check_timers, name='check_mac_timers'),
    #path('get_mac_trustedbsd', views.get_trustedbsd, name='get_mac_trustedbsd'),
    #path('get_mac_vfsevents', views.get_vfsevents, name='get_mac_vfsevents'),
    
    path('mac_tag', views.mac_tag, name='mac_tag'),
    path('mac_report', views.mac_report, name='mac_report'),
    path('get_mac_artifacts', views.get_mac_artifacts, name='get_mac_artifacts'),
]