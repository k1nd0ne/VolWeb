from django.urls import path
from . import views
urlpatterns = [
    path('dump_process/',views.dump_process, name='dump_process'),
    path('download_dump/',views.download_dump, name='download_dump'),
    path('dump_file/',views.dump_file, name='dump_file'),
    path('vt_hash_check/',views.vt_hash_check, name='vt_hash_check'),
    path('download_file/',views.download_file, name='download_file'),
    path('download_hive/',views.download_hive, name='download_hive'),
    path('win_tag',views.win_tag, name='win_tag'),
    path('win_report', views.win_report,name='win_report'),
 ]
