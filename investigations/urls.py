from django.urls import path
from . import views
urlpatterns = [
    path('',views.investigations, name='investigations'),
    path('newinvest/',views.newinvest, name='newinvest'),
    path('reviewinvest/',views.reviewinvest, name='reviewinvest'),
    path('start_analysis/',views.start_analysis, name='start_analysis'),
    path('get_invest/',views.get_invest, name='get_invest'),
    path('remove_analysis/',views.remove_analysis, name='remove_analysis'),
    path('cancel_analysis/',views.cancel_analysis, name='cancel_analysis'),
 ]
