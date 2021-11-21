from django.urls import path
from . import views
urlpatterns = [
    path('',views.investigations, name='investigations'),
    path('newinvest/',views.newinvest, name='newinvest'),
    path('reviewinvest/',views.reviewinvest, name='reviewinvest'),
 ]
