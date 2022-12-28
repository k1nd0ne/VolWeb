from django.urls import path
from . import views

urlpatterns = [
    path('lin_tag', views.lin_tag, name='lin_tag'),
    path('lin_report', views.lin_report, name='lin_report'),
    path('get_l_artifacts', views.get_l_artifacts, name='get_l_artifacts'),
]
