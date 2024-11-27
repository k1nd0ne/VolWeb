from django.contrib import admin
from django.urls import path, include
from django.conf.urls.static import static
from django.conf import settings
from django.urls import re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
   openapi.Info(
      title="VolWeb API",
      default_version='v1',
      description="Documentation",
      terms_of_service="https://github.com/k1nd0ne/VolWeb/",
      contact=openapi.Contact(email="k1nd0ne@mail.com"),
      license=openapi.License(name="GPL v3 License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,)
   ,)


urlpatterns = [
    path("admin/", admin.site.urls),
    path('swagger<format>/', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path("api/", include("cases.urls")),
    path("api/", include("evidences.urls")),
    path("api/", include("symbols.urls")),
    path("api/", include("volatility_engine.urls")),
    path("core/", include("core.urls")),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
