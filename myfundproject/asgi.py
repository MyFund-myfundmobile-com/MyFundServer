"""
ASGI config for myfundproject project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/howto/deployment/asgi/
"""

import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from django.urls import path
from authentication import consumers
from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myfundproject.settings')

application = get_asgi_application()


application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(
        URLRouter([
            path("ws/chat/<int:recipient_id>/", consumers.ChatConsumer.as_asgi()),
            path("ws/balance_update/", consumers.BalanceUpdateConsumer.as_asgi()),  # Replace 'balance_update' with your desired URL path.
       ])
    ),
})
