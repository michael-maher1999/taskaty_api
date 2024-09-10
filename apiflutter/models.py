# models.py
from datetime import timezone
from django.db import models
from django.contrib.auth.models import User

class Task(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('doing', 'Doing'),
        ('done', 'Done'),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    description = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    file = models.FileField(upload_to='tasks/', blank=True, null=True)  # Save files in 'media/tasks/'


    def __str__(self):
        return self.description
    

class Comment(models.Model):
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    file = models.FileField(upload_to='comment_images/', blank=True, null=True)  # Adjust path as needed


    def __str__(self):
        return self.content
    
class otpUser(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=15)
    time_otp = models.DateTimeField()
    time_created = models.DateTimeField(auto_now_add=True)
    


class NotificationModel(models.Model):
    description=models.CharField(max_length=500)
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    creat_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self) -> str:
        return f'Notification for {self.user.username}: {self.description}'
    
