from django.contrib import admin
from .models import Task ,otpUser,Comment,NotificationModel


admin.site.register(Task)
admin.site.register(Comment)

admin.site.register(otpUser)
admin.site.register(NotificationModel)

