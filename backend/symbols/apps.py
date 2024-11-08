from django.apps import AppConfig


class SymbolsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "symbols"

    def ready(self):
        import symbols.signals
