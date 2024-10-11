from django.urls import path, include
from rest_framework import routers
from .views import EvidenceViewSet

router = routers.DefaultRouter()
router.register(r"evidences", EvidenceViewSet, basename="evidence")

urlpatterns = [
    path("", include(router.urls)),
]
