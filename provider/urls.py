from django.urls import path

from . import views

urlpatterns = [
        path('', views.index, name='index'),
        path('view_create_job/', views.create_job_form, name='create_job_form'),
        path('create_job/', views.create_job, name='create_job'),
        path('jobs/', views.view_jobs, name='view_jobs'),
        path('runs/<uuid:job_id>', views.view_runs, name='view_runs'),
        path('run-status/<uuid:run_id>', views.view_run_status_page, name='view_run_status_page'),
        path('run-status-progress/<uuid:run_id>', views.view_run_status_info, name='view_run_status_page_info'),
]
