from django.urls import path
from .consumers import VolatilityTaskConsumer

websockets_urlpatterns = [
    path("ws/volatility_tasks/windows/<int:dump_id>/", VolatilityTaskConsumer.as_asgi())
]
