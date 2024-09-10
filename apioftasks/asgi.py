import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from apiflutter.routing import websocket_urlpatterns  # Replace 'apiflutter' with your app name

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'apioftasks.settings')

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(
        URLRouter(
            websocket_urlpatterns
        )
    ),
})
