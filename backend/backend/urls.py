from django.contrib import admin
from django.urls import path, include
from django.conf.urls.static import static
from django.conf import settings

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("cases.urls")),
    path("api/", include("evidences.urls")),
    path("api/", include("symbols.urls")),
    path("api/", include("volatility_engine.urls")),
    path("core/", include("core.urls")),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
