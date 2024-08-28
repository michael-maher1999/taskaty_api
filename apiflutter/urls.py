# urls.py
from django.urls import path, re_path
from .view import *
from django.conf.urls.static import static
from django.conf import settings
from django.views.static import serve


urlpatterns = [
    path('api/signin/', signin, name='signin'),
    path('api/login/', login, name='login'),
    path('api/add_task/',add_task, name='add_task'),

    path('api/get_tasks/', get_all_tasks, name='get_all_tasks'),
    path('api/get_tasks/pending/', get_pending_tasks, name='get_pending_tasks'),
    path('api/get_tasks/doing/', get_doing_tasks, name='get_doing_tasks'),
    path('api/get_tasks/done/', get_done_tasks, name='get_done_tasks'),
    path('api/add_comment/', add_comment, name='add_comment'),
    path('api/update_task_status/', update_task_status, name='update_task_status'),
    path('api/forget_password/', reset_password, name='forget_password'),
    path('api/check_otp/', check_otp, name='check_otp'),
    path('api/request_otp/', request_otp, name='request_otp'),
    path('api/upload_file_tasks/', upload_file_tasks, name='upload_file_tasks'),
    re_path(r'^media/(?P<path>.*)$', serve,{'document_root': settings.MEDIA_ROOT}),
    re_path(r'^static/(?P<path>.*)$', serve,{'document_root': settings.STATIC_ROOT}),



]


# if settings.DEBUG:
#     urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
#     urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)