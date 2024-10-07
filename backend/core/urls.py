from django.urls import path
from rest_framework_simplejwt import views as jwt_views
from core.views import LogoutView, UserList

urlpatterns = [
    path("logout/", LogoutView.as_view(), name="logout"),
    path("token/", jwt_views.TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", jwt_views.TokenRefreshView.as_view(), name="token_refresh"),
    path("users/", UserList.as_view(), name="users"),
]
