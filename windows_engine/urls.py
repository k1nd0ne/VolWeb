from django.urls import path
from . import views
urlpatterns = [
    path('dump_process/',views.dump_process, name='dump_process'),
    path('download_dump/',views.download_dump, name='download_dump'),
    path('dump_file/',views.dump_file, name='dump_file'),
    path('download_file/',views.download_file, name='download_file'),
    path('download_hive/',views.download_hive, name='download_hive'),
    path('tag',views.tag, name='tag'),
 ]
