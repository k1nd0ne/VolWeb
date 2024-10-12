from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("cases.urls")),
    path("api/", include("evidences.urls")),
    path("api/", include("volatility_engine.urls")),
    path("core/", include("core.urls")),
]
