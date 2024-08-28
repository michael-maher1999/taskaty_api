from django.contrib import admin
from .models import Task ,otpUser,Comment


admin.site.register(Task)
admin.site.register(Comment)

admin.site.register(otpUser)
