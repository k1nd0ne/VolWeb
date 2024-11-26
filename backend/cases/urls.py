from django.urls import path, include
from rest_framework.routers import DefaultRouter
from cases.views import CaseViewSet, GeneratePresignedUrlView, InitiateMultipartUploadView, GeneratePresignedUrlForPartView, CompleteMultipartUploadView

router = DefaultRouter()
router.register(r"cases", CaseViewSet)

urlpatterns = [
    # path(
    #     "cases/<int:case_id>/generate-presigned-url/",
    #     GeneratePresignedUrlView.as_view(),
    #     name="generate-presigned-url",
    # ),
    path('cases/<int:case_id>/generate-presigned-url/', GeneratePresignedUrlView.as_view()),
    path('cases/<int:case_id>/initiate-multipart-upload/', InitiateMultipartUploadView.as_view()),
    path('cases/<int:case_id>/generate-presigned-url-for-part/', GeneratePresignedUrlForPartView.as_view()),
    path('cases/<int:case_id>/complete-multipart-upload/', CompleteMultipartUploadView.as_view()),
    path("", include(router.urls)),
]
