"""
ASGI config for VolWeb project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/3.2/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application
from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from VolWeb.routing import websockets_urlpatterns


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "VolWeb.settings")

application = ProtocolTypeRouter(
    {
        "http": get_asgi_application(), 

        "websocket": AuthMiddlewareStack(
            URLRouter(
                websockets_urlpatterns
                )
        )
    }
)
