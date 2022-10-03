from django.urls import path
from . import views

urlpatterns = [
    path('', views.iocs, name='iocs'),
    path('new_ioc', views.new_ioc, name='new_ioc'),
    path('custom_ioc/<int:pk>/', views.custom_ioc, name='custom_ioc'),
    path('delete_ioc', views.delete_ioc, name='delete_ioc'),
]
