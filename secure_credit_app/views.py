from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import logging
import json
import uuid

from django_q.tasks import schedule

from provider.models import Run, Job, App, Provider
from apd.platforms.maa_azure_amd_sev_attestation import maa_azure_amd_sev_check

logger = logging.getLogger(__name__)

RYTHUBANHDU_RESOURCE_ID = "c5422a0f-e60f-48e4-9d1e-1fa4b1714900"


@csrf_exempt
def start(request):
    body = json.loads(request.body.decode("utf-8"))

    apps = App.objects.filter(name="Smart Credit App")

    if len(apps) == 0:
        result = {
            "error": "App not found",
        }
        return JsonResponse(result, status=403)

    app = apps[0]

    job_id = uuid.uuid4()

    name = body["name"]
    description = body["description"]
    resource_id = RYTHUBANHDU_RESOURCE_ID

    body.pop("description")
    body.pop("name")

    provider = Provider.objects.get(
        iudx_id=uuid.UUID("7a5084ca-a42f-4499-bedc-9f5cf5aef409")
    )

    dataset_name = "Smart Credit Data"  # not used because it's getting an ADeX resource
    resource_server_url = (
        "Smart Credit Data"  # not used because the RS URL will be well-known to app
    )
    sched = None  # not used, the app is run immediately
    date_time = None  # not used

    j = Job(
        job_id=job_id,
        name=name,
        description=description,
        resource_id=resource_id,
        app=app,
        provider=provider,
        schedule=sched,
        date_time=date_time,
        dataset_name=dataset_name,
        resource_server_url=resource_server_url,
        additional_context=body,
    )
    j.save()

    schedule(
        "provider.runner.run_azure_amd_sev_job",
        str(job_id),
        hook="provider.runner.post_run",
        schedule_type="O",
    )

    result = {"id": str(job_id), "message": "Smart Credit App started successfully"}
    return JsonResponse(result, status=201)


@csrf_exempt
def status(request, job_id):

    run = Run.objects.filter(
        job__job_id=job_id,
        job__provider__iudx_id=uuid.UUID("7a5084ca-a42f-4499-bedc-9f5cf5aef409"),
    )

    if len(run) == 0:
        return JsonResponse({}, status=404)

    return JsonResponse(run[0].status_info, status=200)


@csrf_exempt
def inference(request, job_id):

    run = Run.objects.filter(
        job__job_id=job_id,
        job__provider__iudx_id=uuid.UUID("7a5084ca-a42f-4499-bedc-9f5cf5aef409"),
    )

    if len(run) == 0:
        return JsonResponse({}, status=404)

    if run[0].result is None:
        return JsonResponse({}, status=403)

    return JsonResponse(run[0].result, status=200)
