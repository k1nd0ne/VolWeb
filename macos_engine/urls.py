from django.urls import path
from . import views

urlpatterns = [
    path('get_bash/', views.get_bash, name='get_bash'),
    path('check_syscall/', views.check_syscall, name='check_syscall'),
    path('check_trap_table/', views.check_trap_table, name='check_trap_table'),
    path('check_sysctl/', views.check_sysctl, name='check_sysctl'),
    path('get_ifconfig/', views.get_ifconfig, name='get_ifconfig'),
    path('get_kauth_listeners/', views.get_kauth_listeners, name='get_kauth_listeners'),
    path('get_kauth_scopes', views.get_kauth_scopes, name='get_kauth_scopes'),
    path('get_kevents', views.get_kevents, name='get_kevents'),
    path('get_list_files', views.get_list_files, name='get_list_files'),
    path('get_lsmod', views.get_lsmod, name='get_lsmod'),
    path('get_lsof', views.get_lsof, name='get_lsof'),
    path('get_malfind', views.get_malfind, name='get_malfind'),
    path('get_mount', views.get_handles, name='get_mount'),
    path('get_netstat', views.get_netstat, name='get_netstat'),
    path('get_proc_maps', views.proc_maps, name='get_proc_maps'),
    path('get_psaux', views.get_psaux, name='get_psaux'),
    path('get_pslist', views.get_pslist, name='get_pslist'),
    path('get_pstree', views.get_pstree, name='get_pstree'),
    path('get_socket_filters', views.get_socket_filters, name='get_socket_filters'),
    path('check_timers', views.check_timers, name='check_timers'),
    path('get_trustedbsd', views.get_trustedbsd, name='get_trustedbsd'),
    path('get_vfsevents', views.get_vfsevents, name='get_vfsevents')
]