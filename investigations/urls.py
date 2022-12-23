from django.urls import path
from . import views

urlpatterns = [
    path('', views.investigations, name='investigations'),
    path('new_invest/', views.new_invest, name='new_invest'),
    path('custom_invest/<int:pk>/', views.custom_invest, name='custom_invest'),
    path('review_invest/', views.review_invest, name='review_invest'),
    path('start_analysis/', views.start_analysis, name='start_analysis'),
    path('get_invest/', views.get_invest, name='get_invest'),
    path('remove_analysis/', views.remove_analysis, name='remove_analysis'),
    path('cancel_analysis/', views.cancel_analysis, name='cancel_analysis'),
]
