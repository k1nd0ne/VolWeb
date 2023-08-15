from django.urls import path
from main import views

urlpatterns = [
    path('', views.home, name='home'),
    path('cases/', views.cases, name='cases'),
    path('api/cases/', views.CaseApiView.as_view()),
    path('api/cases/<int:case_id>/', views.CaseDetailApiView.as_view()),
] 