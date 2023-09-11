from django.urls import path
from windows_engine import views

urlpatterns = [
    path('review/windows/<int:dump_id>/', views.review, name='review'),
    path('review/windows/<int:dump_id>/<int:process_id>/', views.process, name='process'),
    path('api/windows/<int:dump_id>/pstree/', views.PsTreeApiView.as_view()),
    path('api/windows/<int:dump_id>/timeline/', views.TimelineChartApiView.as_view()),
    path('api/windows/<int:dump_id>/timeline_data/<str:timestamp>/', views.TimelineDataApiView.as_view()),


] 