from django.urls import path

from . import views

urlpatterns = [
        path('userclasses', views.show_userclasses),
        path('verify', views.verify_enclave_call),
]
