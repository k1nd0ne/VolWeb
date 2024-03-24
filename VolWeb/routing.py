from django.urls import path
from .consumers import VolatilityTaskConsumer, CasesTaskConsumer, EvidencesTaskConsumer, SymbolsTaskConsumer

websockets_urlpatterns = [
    path(
        "ws/volatility_tasks/windows/<int:dump_id>/", VolatilityTaskConsumer.as_asgi()
    ),
    path("ws/cases/", CasesTaskConsumer.as_asgi()),
    path("ws/evidences/", EvidencesTaskConsumer.as_asgi()),
    path("ws/symbols/", SymbolsTaskConsumer.as_asgi()),

]
