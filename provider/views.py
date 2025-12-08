from django.http import HttpResponse
from django.shortcuts import render, redirect
from .forms import JobForm
from .models import Provider, Job, App, Run
from .tables import JobsTable, RunsTable
import uuid
import isodate
from datetime import timedelta
from django_q.tasks import schedule
from django.contrib import messages

HARDCODED_RES_ID = '8bdebc63-ccb0-4930-bdbb-60ea9d7f7599'

def index(request):
    return HttpResponse("Hw")

def create_job_form(request):
    choice = JobForm()
    return render(request, 'provider/create.html', {'job' : choice} )

# TODO remove static provider
def create_job(request):

    job_id = uuid.uuid4()
    name = request.POST['name']
    description = request.POST['description']
    resource_id = HARDCODED_RES_ID
    app = App.objects.get(pk=request.POST['app'])
    provider = Provider.objects.get(iudx_id=uuid.UUID('7a5084ca-a42f-4499-bedc-9f5cf5aef409'))
    dataset_name = request.POST['dataset_name']
    resource_server_url = request.POST['resource_server_url']
    sched = None
    date_time = None

    # ----> disabling date_time submission    
    # if request.POST['date_time']:
        # date_time = request.POST['date_time']

    j = Job(job_id=job_id, name=name, description=description, resource_id=resource_id, app=app, provider=provider, schedule=sched, date_time=date_time, dataset_name=dataset_name, resource_server_url=resource_server_url)
    j.save()

    if app.execution_platform == App.AppExecutionPlatforms.AWS_NITRO:
        schedule('provider.runner.run_nitro_job', str(job_id), hook='provider.runner.post_run', schedule_type='O')
    elif app.execution_platform == App.AppExecutionPlatforms.INTEL_SGX:
        schedule('provider.runner.run_sgx_job', str(job_id), hook='provider.runner.post_run', schedule_type='O')
    elif app.execution_platform == App.AppExecutionPlatforms.AZURE_AMD_SEV:
        schedule('provider.runner.run_azure_amd_sev_job', str(job_id), hook='provider.runner.post_run', schedule_type='O')

    messages.success(request, 'Created job successfully')
    return redirect(create_job_form)
    # create schedule in django-q

# TODO remove static provider
def view_jobs(request):
    table = JobsTable(Job.objects.filter(provider__iudx_id=uuid.UUID('7a5084ca-a42f-4499-bedc-9f5cf5aef409')))

    return render(request, "provider/jobs.html", {
        "table": table
    })

# TODO remove static provider
def view_runs(request, job_id):
    table = RunsTable(Run.objects.filter(job__job_id=job_id, job__provider__iudx_id=uuid.UUID('7a5084ca-a42f-4499-bedc-9f5cf5aef409')))

    return render(request, "provider/runs.html", {
        "table": table
    })

def view_run_status_page(request, run_id):
    run_name = str(Run.objects.filter(run_id=run_id)[0])
    return render(request, 'provider/run-status.html', {"run_id": run_id, "run_name": run_name})

def view_run_status_info(request, run_id):
    status_info_json = Run.objects.filter(run_id=run_id)[0].status_info
    try:
        status_info_json["percentage"] = (status_info_json["step"] / status_info_json["maxSteps"]) * 100
    except Exception:
        status_info_json["percentage"] = 0
    return render(request, "provider/run-status-progress.html", {"status_info":status_info_json})
