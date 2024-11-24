from django.urls import path, include
from rest_framework import routers
from .views import EvidenceViewSet, EvidenceStatisticsApiView, BindEvidenceViewSet

router = routers.DefaultRouter()
router.register(r"evidences", EvidenceViewSet, basename="evidence")

urlpatterns = [
    path(
        "evidence-statistics/<int:id>/",
        EvidenceStatisticsApiView.as_view(),
        name="statistics",
    ),
    path("evidences/bind/", BindEvidenceViewSet.as_view(), name="bind"),
    path("", include(router.urls)),
]
