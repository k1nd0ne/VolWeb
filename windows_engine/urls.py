from django.urls import path
from windows_engine import views

urlpatterns = [
    path('review/windows/<int:dump_id>/', views.review, name='review'),
    path('api/windows/<int:dump_id>/pstree/', views.PsTreeApiView.as_view()),
] 