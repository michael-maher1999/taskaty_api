# consumers.py
from channels.generic.websocket import AsyncWebsocketConsumer
import json

class TaskNotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.group_name = 'notifications'

        # Join the group
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        # Leave the group
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )

    async def task_notification(self, event):
        message = event['message']

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'description': message['description'],
            'user': message['user'],
            'created_at': message['created_at'],
        }))
