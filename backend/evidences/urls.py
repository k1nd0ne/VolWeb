from django.urls import path, include
from rest_framework import routers
from .views import EvidenceViewSet, EvidenceStatisticsApiView

router = routers.DefaultRouter()
router.register(r"evidences", EvidenceViewSet, basename="evidence")

urlpatterns = [
    path("evidence-statistics/<int:id>/", EvidenceStatisticsApiView.as_view(), name="statistics"),
    path("", include(router.urls)),
]
