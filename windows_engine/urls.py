from django.urls import path
from windows_engine import views

urlpatterns = [
    # Basic
    path('review/windows/<int:dump_id>/', views.review, name='review'),

    # API
    path('api/windows/<int:dump_id>/pstree/', views.PsTreeApiView.as_view()),
    path('api/windows/<int:dump_id>/timeline/', views.TimelineChartApiView.as_view()),
    path('api/windows/<int:dump_id>/timeliner/<str:timestamp>/', views.TimelineDataApiView.as_view()),
    path('api/windows/<int:dump_id>/timeliner/<int:artifact_id>/<str:tag>/', views.TimelineDataApiView.as_view()),
    path('api/windows/<int:dump_id>/cmdline/<int:pid>/', views.CmdLineApiView.as_view()),
    path('api/windows/<int:dump_id>/sids/<int:pid>/', views.GetSIDsApiView.as_view()),
    path('api/windows/<int:dump_id>/sids/<int:artifact_id>/<str:tag>/', views.GetSIDsApiView.as_view()),
    path('api/windows/<int:dump_id>/privileges/<int:pid>/', views.PrivsApiView.as_view()),
    path('api/windows/<int:dump_id>/privileges/<int:artifact_id>/<str:tag>/', views.PrivsApiView.as_view()),
    path('api/windows/<int:dump_id>/envars/<int:pid>/', views.EnvarsApiView.as_view()),
    path('api/windows/<int:dump_id>/envars/<int:artifact_id>/<str:tag>/', views.EnvarsApiView.as_view()),
    path('api/windows/<int:dump_id>/dlllist/<int:pid>/', views.DllListApiView.as_view()),
    path('api/windows/<int:dump_id>/dlllist/<int:artifact_id>/<str:tag>/', views.DllListApiView.as_view()),
    path('api/windows/<int:dump_id>/sessions/<int:pid>/', views.SessionsApiView.as_view()),
    path('api/windows/<int:dump_id>/sessions/<int:artifact_id>/<str:tag>/', views.SessionsApiView.as_view()),
    path('api/windows/<int:dump_id>/netstat/', views.NetStatApiView.as_view()),
    path('api/windows/<int:dump_id>/netstat/<int:artifact_id>/<str:tag>/', views.NetStatApiView.as_view()),
    path('api/windows/<int:dump_id>/netscan/', views.NetScanApiView.as_view()),
    path('api/windows/<int:dump_id>/netscan/<int:artifact_id>/<str:tag>/', views.NetScanApiView.as_view()),
    path('api/windows/<int:dump_id>/netgraph/', views.NetGraphApiView.as_view()),
    path('api/windows/<int:dump_id>/cachedump/', views.CachedumpApiView.as_view()),
    path('api/windows/<int:dump_id>/hashdump/', views.HashdumpApiView.as_view()),
    path('api/windows/<int:dump_id>/lsadump/', views.LsadumpApiView.as_view()),
    
    # Tasks
    path('tasks/windows/<int:dump_id>/handles/<int:pid>/', views.GetHandlesApiView.as_view()),
]