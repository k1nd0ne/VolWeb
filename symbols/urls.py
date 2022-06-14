from django.urls import path
from . import views
urlpatterns = [
    path('',views.symbols,name='symbols'),
    path('add_symbols',views.add_symbols,name='add_symbols'),
    path('custom_symbols',views.custom_symbols,name='custom_symbols'),
    path('delete_symbols',views.delete_symbols,name='delete_symbols'),
    path('bind_symbols',views.bind_symbols,name='bind_symbols'),
    path('unbind_symbols',views.unbind_symbols,name='unbind_symbols'),

    ]
