from django.urls import path
from symbols import views

urlpatterns = [
    path("symbols/", views.symbols, name="symbols"),
    path("api/symbols/", views.SymbolsApiView.as_view()),
    path("api/symbols/<int:id>/", views.SymbolApiView.as_view()),
]
