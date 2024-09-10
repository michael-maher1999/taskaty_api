import json
import os
from django.http import JsonResponse
from django.contrib.auth.models import User
from .models import Task, Comment,otpUser,NotificationModel
from django.views.decorators.csrf import csrf_exempt
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
import base64
from django.contrib.auth.hashers import make_password
import random
import string
from django.core.mail import send_mail
from django.core.cache import cache
from django.utils import timezone
from django.conf import settings
from datetime import datetime, timedelta
import secrets
import string
import logging
from django.shortcuts import get_object_or_404
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync


# for E-mail

logger = logging.getLogger(__name__)


def generate_otp(length=10):
    """Generate a random user token of specified length."""
    characters = string.ascii_letters + string.digits
    otp = ''.join(secrets.choice(characters) for _ in range(length))
    return otp

@csrf_exempt
def signin(request):
    if request.method == 'GET':
        name = request.GET.get('name')
        email = request.GET.get('email')
        password = request.GET.get('password')

        if not all([name, email, password]):
            return JsonResponse({'error': 'Missing parameters'}, status=400)

        if User.objects.filter(username=name).exists():
            return JsonResponse({'error': 'Username is already taken'}, status=400)

        if User.objects.filter(email=email).exists():
            return JsonResponse({'error': 'Email is already in use'}, status=400)

        try:
            user = User.objects.create_user(username=name, email=email, password=password)
            return JsonResponse({'success': 'User created successfully'}, status=201)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

def login(request):
    if request.method == 'GET':
        email = request.GET.get('email')
        password = request.GET.get('password')
        
        if not email or not password:
            return JsonResponse({'error': 'Email and password are required'}, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return JsonResponse({'error': 'Invalid email or password'}, status=401)

        if user.check_password(password):
            return JsonResponse({'success': 'Login successful'}, status=200)
        else:
            return JsonResponse({'error': 'Invalid email or password'}, status=401)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

def add_task(request):
    if request.method == 'GET':
        email = request.GET.get('email')
        task_description = request.GET.get('task')

        if not email or not task_description:
            return JsonResponse({'error': 'Email and task are required'}, status=400)

        try:
            user = User.objects.get(email=email)
            task = Task.objects.create(user=user, description=task_description)

            notification = NotificationModel.objects.create(
                description=f"Task '{task_description}' added by {user.username}",
                user=user
            )

            # Send the notification via WebSocket
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                "notifications",
                {
                    "type": "task.notification",
                    "message": {
                        "description": notification.description,
                        "user": user.username,
                        "created_at": notification.creat_at.strftime("%Y-%m-%d %H:%M:%S"),
                    },
                },
            )

            return JsonResponse({'success': 'Task added successfully'}, status=200)
        except User.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({'error': 'Invalid request method'}, status=405)


 
def get_all_tasks(request):
    tasks = Task.objects.all()
    tasks_data = [
        {
            'id': task.id,
            'description': task.description,
            'created_at': task.created_at.isoformat(),
            'user': task.user.username,
            'status': task.status,
            'fileUrl': task.file.url if task.file else None,
            'comments': [
                {
                    'user': comment.user.username,
                    'content': comment.content,
                    'created_at': comment.created_at.isoformat(),
                    'fileUrl': comment.file.url if comment.file else None
                }
                for comment in task.comments.all()
            ]
        }
        for task in tasks
    ]
    return JsonResponse({'tasks': tasks_data}, status=200, safe=False)


def get_pending_tasks(request):
    tasks = Task.objects.filter(status='pending')
    tasks_data = [
        {
            'id': task.id,
            'description': task.description,
            'created_at': task.created_at.isoformat(),
            'user': task.user.username,
            'status': task.status,
            'comments': [
                {
                    'user': comment.user.username,
                    'content': comment.content,
                    'created_at': comment.created_at.isoformat(),
                }
                for comment in task.comments.all()
            ]
        }
        for task in tasks
    ]
    return JsonResponse({'tasks': tasks_data}, status=200, safe=False)

def get_doing_tasks(request):
    tasks = Task.objects.filter(status='doing')
    tasks_data = [
        {
            'id': task.id,
            'description': task.description,
            'created_at': task.created_at.isoformat(),
            'user': task.user.username,
            'status': task.status,
            'comments': [
                {
                    'user': comment.user.username,
                    'content': comment.content,
                    'created_at': comment.created_at.isoformat(),
                }
                for comment in task.comments.all()
            ]
        }
        for task in tasks
    ]
    return JsonResponse({'tasks': tasks_data}, status=200, safe=False)


def get_done_tasks(request):
    tasks = Task.objects.filter(status='done')
    tasks_data = [
        {
            'id': task.id,
            'description': task.description,
            'created_at': task.created_at.isoformat(),
            'user': task.user.username,
            'status': task.status,
            'comments': [
                {
                    'user': comment.user.username,
                    'content': comment.content,
                    'created_at': comment.created_at.isoformat(),
                }
                for comment in task.comments.all()
            ]
        }
        for task in tasks
    ]
    return JsonResponse({'tasks': tasks_data}, status=200, safe=False)



def update_task_status(request):
    if request.method == 'GET':
        task_id = request.GET.get('task_id')
        new_status = request.GET.get('status')

        if not all([task_id, new_status]):
            return JsonResponse({'error': 'Task ID and new status are required'}, status=400)

        valid_statuses = ['pending', 'doing', 'done']
        if new_status not in valid_statuses:
            return JsonResponse({'error': 'Invalid status value'}, status=400)

        try:
            task = Task.objects.get(id=task_id)
            task.status = new_status
            task.save()
            return JsonResponse({'success': 'Status updated successfully'}, status=200)
        except Task.DoesNotExist:
            return JsonResponse({'error': 'Task not found'}, status=404)

def request_otp(request):
    if request.method == 'GET':
        email = request.GET.get('email')
        if email:
            otp = generate_otp()
            expiration_time = timezone.now() + timedelta(minutes=5)

            try:
                user = User.objects.get(email=email)
                check_otp_user= otpUser.objects.filter(user=user)
                if check_otp_user.exists():
                    print('ssdsdsdsdssdssds')
                    check_otp_user.update(otp=otp,time_otp=expiration_time)
              
                 
                else:
                    otp_entry = otpUser(user=user, otp=otp, time_otp=expiration_time)
                    otp_entry.save()
                
                sender = settings.DEFAULT_FROM_EMAIL
                receiver = [email]
                subject = "OTP for Password Reset"
                message = f"Your OTP is {otp}. It will expire in 5 minutes."
                send_mail(subject, message, sender, receiver)

                return JsonResponse({'status': 'valid', 'message': 'OTP sent to email'}, safe=False)
            except User.DoesNotExist:
                return JsonResponse({'status': 'invalid', 'message': 'User not found'}, safe=False)
            except Exception as e:
                logger.error(f"Failed to send OTP email: {e}")
                return JsonResponse({'status': 'invalid', 'message': 'Failed to send OTP email'}, safe=False)
        else:
            return JsonResponse({'status': 'invalid', 'message': 'Email is required'}, safe=False)
    return JsonResponse({'status': 'No GET Request'}, safe=False)

def check_otp(request):
    if request.GET:
        otp = request.GET.get('otp')
        email = request.GET.get('email')
        if email and otp:
            print(email,otp)
            try:
                otp_obj = otpUser.objects.get(user__email=email)
                print(otp_obj.otp)

                if otp_obj.otp == otp:
                    if otp_obj.time_otp >= datetime.now() :
                        return JsonResponse({'status': 'valid', 'message': 'OTP valid'}, safe=False)
                    if otp_obj.time_otp < datetime.now() :
                        return JsonResponse({'status': 'invalid', 'message': 'otp expired'}, safe=False)
                else : 
                    return JsonResponse({'status': 'invalid', 'message': 'otp wrong'}, safe=False)
                    
            except User.DoesNotExist:
                return JsonResponse({'status': 'invalid', 'message': 'User not found'}, safe=False)
            
        else:
            return JsonResponse({'status': 'invalid', 'message': 'Email is required'}, safe=False)
    return JsonResponse({'status': 'No GET Request'}, safe=False)

def reset_password(request):
    if request.method == 'GET':
        email = request.GET.get('email')
        otp = request.GET.get('otp')
        new_password = request.GET.get('new_password')

        if not all([email, otp, new_password]):
            return JsonResponse({'status': 'invalid', 'message': 'All fields are required'}, safe=False)

        try:
            user = User.objects.get(email=email)
            otp_entry = otpUser.objects.filter(user=user, otp=otp).first()

            if otp_entry:
                if timezone.now() > otp_entry.time_otp:
                    return JsonResponse({'status': 'invalid', 'message': 'OTP expired'}, safe=False)

                if otp == otp_entry.otp:
                    user.password = make_password(new_password)  # Securely hash the new password
                    user.save()

                    otp_entry.delete()  # Remove the OTP entry after successful password reset

                    return JsonResponse({'status': 'valid', 'message': 'Password reset successfully'}, safe=False)
                else:
                    return JsonResponse({'status': 'invalid', 'message': 'Invalid OTP'}, safe=False)
            else:
                return JsonResponse({'status': 'invalid', 'message': 'Invalid OTP or email'}, safe=False)
        except User.DoesNotExist:
            return JsonResponse({'status': 'invalid', 'message': 'User not found'}, safe=False)
        except Exception as e:
            logger.error(f"Error resetting password: {e}")
            return JsonResponse({'status': 'invalid', 'message': 'Failed to reset password'}, safe=False)
    return JsonResponse({'status': 'No GET Request'}, safe=False)


@csrf_exempt
def upload_file_tasks(request):
    if request.method == 'POST':
        try:
            task_id = request.POST.get('task_id')
            file = request.FILES.get('file_data')

            if not task_id or not file:
                return JsonResponse({"error": "Missing required fields"}, status=400)

            task_obj = Task.objects.get(id=task_id)
            if task_obj:
                task_obj.file = file
                task_obj.save()

            # Return the file URL in the response
            file_url = task_obj.file.url if task_obj.file else None

            return JsonResponse({"message": "File uploaded successfully", "file_url": file_url}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=405)
    



@csrf_exempt
def add_comment(request):
    if request.method == "POST":
        try:
            task_id = request.POST.get('task_id')
            content = request.POST.get('content', '')
            email = request.POST.get('email')
            file = request.FILES.get('file_data')

            if not all([task_id, email]):
                return JsonResponse({'error': 'Task ID and email are required'}, status=400)

            task = Task.objects.get(id=task_id)
            user = User.objects.get(email=email)

            comment = Comment.objects.create(
                task=task,
                user=user,
                content=content,
                file=file
            )

            return JsonResponse({
                'success': 'Comment added successfully',
                'file_url': comment.file.url if comment.file else None
            }, status=200)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    else:
        return JsonResponse({'error': 'Unsupported Content-Type'}, status=415)


def notification(request):
    # Fetch all notifications
    notifications = NotificationModel.objects.all().values()
    print(notifications)
    
    # Convert the QuerySet to a list of dictionaries
    notifications_list = list(notifications)
    
    return JsonResponse({"notifications": notifications_list,
        "count": len(notifications_list)})
