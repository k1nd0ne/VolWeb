from django.urls import path
from windows_engine import views

urlpatterns = [
    path('review/windows/<int:dump_id>/', views.review, name='review'),
    path('api/windows/<int:dump_id>/pstree/', views.PsTreeApiView.as_view()),
    path('api/windows/<int:dump_id>/timeline/', views.TimelineChartApiView.as_view()),
    path('api/windows/<int:dump_id>/timeliner/<str:timestamp>/', views.TimelineDataApiView.as_view()),
    path('api/windows/<int:dump_id>/timeliner/<int:artifact_id>/<str:tag>/', views.TimelineDataApiView.as_view()),
    path('api/windows/<int:dump_id>/cmdline/<int:pid>/', views.CmdLineApiView.as_view()),
    path('api/windows/<int:dump_id>/sids/<int:pid>/', views.GetSIDsApiView.as_view()),
    path('api/windows/<int:dump_id>/privileges/<int:pid>/', views.PrivsApiView.as_view()),
    path('api/windows/<int:dump_id>/envars/<int:pid>/', views.EnvarsApiView.as_view()),
    path('api/windows/<int:dump_id>/dlllist/<int:pid>/', views.DllListApiView.as_view()),
    path('api/windows/<int:dump_id>/sessions/<int:pid>/', views.SessionsApiView.as_view()),
    path('api/windows/<int:dump_id>/netstat/', views.NetStatApiView.as_view()),
    path('api/windows/<int:dump_id>/netscan/', views.NetScanApiView.as_view()),
    path('api/windows/<int:dump_id>/netgraph/', views.NetGraphApiView.as_view()),
] 