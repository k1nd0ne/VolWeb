from django.urls import path
from linux_engine import views
from django.shortcuts import render
from django.contrib.auth.decorators import login_required

urlpatterns = [
    path("review/linux/<int:dump_id>/", views.review, name="review"),
    path("api/linux/<int:dump_id>/pstree/", views.PsTreeApiView.as_view()),
    path("api/linux/<int:dump_id>/psscan/", views.PsScanApiView.as_view()),
    path("api/linux/<int:dump_id>/library_list/", views.LibraryListApiView.as_view()),

    path("api/linux/<int:dump_id>/kmsg/", views.KmsgApiView.as_view()),
    path("api/linux/<int:dump_id>/bash/", views.BashApiView.as_view()),
    path("api/linux/<int:dump_id>/mountinfo/", views.MountInfoApiView.as_view()),
    path("api/linux/<int:dump_id>/sockstat/", views.SockstatApiView.as_view()),
    path("api/linux/<int:dump_id>/netgraph/", views.NetGraphApiView.as_view()),
    path("api/linux/<int:dump_id>/timeline/", views.TimelineChartApiView.as_view()),
    path("api/linux/<int:dump_id>/timeliner/", views.TimelineDataApiView.as_view()),
    path("api/linux/<int:dump_id>/malfind/", views.MalfindApiView.as_view()),
    path("api/linux/<int:dump_id>/lsmod/", views.LsmodApiView.as_view()),
    path("api/linux/<int:dump_id>/tty_check/", views.tty_checkApiView.as_view()),
    path("api/linux/<int:dump_id>/psaux/<int:pid>/", views.PsAuxApiView.as_view()),
    path("api/linux/<int:dump_id>/envars/<int:pid>/", views.EnvarsApiView.as_view()),
    path("api/linux/<int:dump_id>/lsof/<int:pid>/", views.LsofApiView.as_view()),
    path("api/linux/<int:dump_id>/elfs/<int:pid>/", views.ElfsApiView.as_view()),
    path(
        "api/linux/<int:dump_id>/capabilities/<int:pid>/",
        views.CapabilitiesApiView.as_view(),
    ),
]
