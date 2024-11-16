from django.apps import AppConfig


class VolatilityEngineConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "volatility_engine"

    def ready(self):
        import volatility_engine.signals
