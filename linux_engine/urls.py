from django.urls import path
from linux_engine import views
from django.shortcuts import render
from django.contrib.auth.decorators import login_required

urlpatterns = [
path("review/linux/<int:dump_id>/", views.review, name="review"),
path("api/linux/<int:dump_id>/pstree/", views.PsTreeApiView.as_view()),
path("api/linux/<int:dump_id>/psscan/", views.PsScanApiView.as_view()),
path("api/linux/<int:dump_id>/bash/", views.BashApiView.as_view()),
path("api/linux/<int:dump_id>/sockstat/", views.SockstatApiView.as_view()),
path("api/linux/<int:dump_id>/netgraph/", views.NetGraphApiView.as_view()),
path("api/linux/<int:dump_id>/timeline/", views.TimelineChartApiView.as_view()),
path('api/linux/<int:dump_id>/timeliner/', views.TimelineDataApiView.as_view()),
path(
    "api/linux/<int:dump_id>/psaux/<int:pid>/", views.PsAuxApiView.as_view()
),
path(
    "api/linux/<int:dump_id>/lsof/<int:pid>/", views.LsofApiView.as_view()
),
path(
    "api/linux/<int:dump_id>/elfs/<int:pid>/", views.ElfsApiView.as_view()
),
]
