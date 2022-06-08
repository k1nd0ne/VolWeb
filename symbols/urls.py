from django.urls import path
from . import views
urlpatterns = [
    path('',views.symbols,name='symbols'),
    path('addsymbols',views.addsymbols,name='addsymbols'),
    path('customsymbols',views.customsymbols,name='customsymbols'),
    path('deletesymbols',views.deletesymbols,name='deletesymbols'),
    ]
