from django.urls import path, include
from rest_framework.routers import DefaultRouter
from cases.views import CaseViewSet, InitiateUploadView, UploadChunkView, CompleteUploadView

router = DefaultRouter()
router.register(r"cases", CaseViewSet)

urlpatterns = [
    path('cases/upload/initiate/', InitiateUploadView.as_view(), name='initiate_upload'),
    path('cases/upload/chunk/', UploadChunkView.as_view(), name='upload_chunk'),
    path('cases/upload/complete/', CompleteUploadView.as_view(), name='complete_upload'),
    path("", include(router.urls)),
]
