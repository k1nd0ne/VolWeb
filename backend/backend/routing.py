from django.urls import path
from .consumers import (
    VolatilityTaskConsumer,
    CasesTaskConsumer,
    EvidencesTaskConsumer,
    SymbolsTaskConsumer,
)

websockets_urlpatterns = [
    path("ws/cases/", CasesTaskConsumer.as_asgi()),
    path("ws/evidences/", EvidencesTaskConsumer.as_asgi()),
    path("ws/evidences/<int:case_id>/", EvidencesTaskConsumer.as_asgi()),
    path("ws/symbols/", SymbolsTaskConsumer.as_asgi()),
    path("ws/engine/<int:evidence_id>/", VolatilityTaskConsumer.as_asgi()),
]
