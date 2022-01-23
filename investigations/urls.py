from django.urls import path
from . import views
urlpatterns = [
    path('',views.investigations, name='investigations'),
    path('newinvest/',views.newinvest, name='newinvest'),
    path('reviewinvest/',views.reviewinvest, name='reviewinvest'),
    path('dump_process/',views.dump_process, name='dump_process'),
    path('download_dump/',views.download_dump, name='download_dump'),
    path('dump_file/',views.dump_file, name='dump_file'),
    path('download_file/',views.download_file, name='download_file')
 ]
