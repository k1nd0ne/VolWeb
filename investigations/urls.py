from django.urls import path
from . import views
urlpatterns = [
    path('',views.investigations, name='investigations'),
    path('newinvest/',views.newinvest, name='newinvest'),
    path('reviewinvest/',views.reviewinvest, name='reviewinvest'),
    path('start_analysis/',views.start_analysis, name='start_analysis'),
    path('get_invest/',views.get_invest, name='get_invest'),
    path('get_status/',views.get_status, name='get_status'),
    path('remove_analysis/',views.remove_analysis, name='remove_analysis'),
    path('cancel_analysis/',views.cancel_analysis, name='cancel_analysis'),
    path('dump_process/',views.dump_process, name='dump_process'),
    path('download_dump/',views.download_dump, name='download_dump'),
    path('dump_file/',views.dump_file, name='dump_file'),
    path('download_file/',views.download_file, name='download_file'),
    path('download_hive/',views.download_hive, name='download_hive'),
    path('dlllist/',views.dlllist, name='dlllist'),

 ]
