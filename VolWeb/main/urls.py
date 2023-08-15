from django.urls import path
from main import views

urlpatterns = [
    path('', views.home, name='home'),
    path('cases/', views.cases, name='cases'),
    path('get_cases/', views.CaseApiView.as_view()),
] 