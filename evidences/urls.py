from django.urls import path
from evidences import views

urlpatterns = [
    path('evidences/', views.evidences, name='evidences'),
] 