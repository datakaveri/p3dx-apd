from django.urls import path

from . import views

urlpatterns = [
        path('start', views.start),
        path('status/<uuid:job_id>', views.status),
        path('inference/<uuid:job_id>', views.inference),
]
