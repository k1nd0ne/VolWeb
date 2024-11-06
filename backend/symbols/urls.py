from django.urls import path, include
from rest_framework import routers
from .views import SymbolViewSet, SymbolUploadView

router = routers.DefaultRouter()
router.register(r"symbols", SymbolViewSet, basename="symbol")

urlpatterns = [
    path(
        "upload_symbols/",
        SymbolUploadView.as_view(),
        name="upload-symbols",
    ),
    path("", include(router.urls)),

]
