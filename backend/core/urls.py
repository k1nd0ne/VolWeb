from django.urls import path
from rest_framework_simplejwt import views as jwt_views
from core.views import LogoutView, UserList, IndicatorApiView, IndicatorCaseApiView, IndicatorExportApiView, IndicatorEvidenceApiView

urlpatterns = [
    path("logout/", LogoutView.as_view(), name="logout"),
    path("token/", jwt_views.TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", jwt_views.TokenRefreshView.as_view(), name="token_refresh"),
    path("users/", UserList.as_view(), name="users"),
    path("api/stix/indicators/", IndicatorApiView.as_view()),
    path("api/stix/indicators/<int:indicator_id>/", IndicatorApiView.as_view()),
    path(
        "api/stix/indicators/case/<int:case_id>/", IndicatorCaseApiView.as_view()
    ),
    path(
        "api/stix/indicators/evidence/<int:dump_id>/",
        IndicatorEvidenceApiView.as_view(),
    ),
    path("api/stix/export/<int:case_id>/", IndicatorExportApiView.as_view()),
]
