from django.urls import path
from main import views

urlpatterns = [
    path("", views.home, name="home"),
    path("websocket-url/", views.websocket_url, name="websocket_url"),
    path("statistics/", views.statistics, name="statistics"),
    path("minio_secrets/", views.minio_secrets, name="minio_secrets"),
    path("api/stix/indicators/", views.IndicatorApiView.as_view()),
    path("api/stix/indicators/<int:indicator_id>/", views.IndicatorApiView.as_view()),
    path(
        "api/stix/indicators/case/<int:case_id>/", views.IndicatorCaseApiView.as_view()
    ),
    path(
        "api/stix/indicators/evidence/<int:dump_id>/",
        views.IndicatorEvidenceApiView.as_view(),
    ),
    path("api/stix/export/<int:case_id>/", views.IndicatorExportApiView.as_view()),
]
