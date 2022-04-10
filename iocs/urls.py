from django.urls import path
from . import views
urlpatterns = [
    path('',views.iocs,name='iocs'),
    path('newioc',views.newioc,name='newioc'),
    path('customioc',views.customioc,name='customioc'),
    path('deleteioc',views.deleteioc,name='deleteioc'),
    ]
