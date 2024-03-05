from django.urls import path
from main import views

urlpatterns = [
    path("", views.home, name="home"),
    path('websocket-url/', views.websocket_url, name='websocket_url'),
    path('statistics/', views.statistics, name='statistics'),
    path('minio_secrets/',views.minio_secrets,name='minio_secrets'),
]
