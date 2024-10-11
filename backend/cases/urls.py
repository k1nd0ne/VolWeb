from django.urls import path, include
from rest_framework.routers import DefaultRouter
from cases.views import CaseViewSet, GeneratePresignedUrlView

router = DefaultRouter()
router.register(r"cases", CaseViewSet)

urlpatterns = [
    path(
        "cases/<int:case_id>/generate-presigned-url/",
        GeneratePresignedUrlView.as_view(),
        name="generate-presigned-url",
    ),
    path("", include(router.urls)),
]
