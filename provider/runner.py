from .boto_test import AwsClient
from .run_sgx import SgxClient
from .run_azure_amd_sev import AzureAmdSevClient
from .models import Run, Job, App
from datetime import datetime, timezone
import uuid

def run_nitro_job(job_id):
    job = Job.objects.get(job_id=job_id)
    app = job.app
    run_id = uuid.uuid4() 
    r = Run(run_id=run_id, job=job, status='R', started_at=datetime.now(timezone.utc), ended_at=datetime.now(timezone.utc))
    r.save()
    print("Running Nitro job", job.job_id, job.name)
    client = AwsClient()
    result = client.execute_enclave(app, run_id)
    result['run_id'] = str(run_id)
    return result

def run_sgx_job(job_id):
    job = Job.objects.get(job_id=job_id)
    app = job.app
    run_id = uuid.uuid4() 
    r = Run(run_id=run_id, job=job, status='R', started_at=datetime.now(timezone.utc), ended_at=datetime.now(timezone.utc))
    r.save()
    print("Running SGX job", job.job_id, job.name)
    client = SgxClient()
    result = client.execute_enclave(app, run_id)
    result['run_id'] = str(run_id)
    return result

def run_azure_amd_sev_job(job_id):
    job = Job.objects.get(job_id=job_id)
    app = job.app
    run_id = uuid.uuid4() 
    r = Run(run_id=run_id, job=job, status='R', started_at=datetime.now(timezone.utc), ended_at=datetime.now(timezone.utc))
    r.save()
    print("Running Azure AMD SEV job", job.job_id, job.name)
    client = AzureAmdSevClient()
    result = client.execute_enclave(app, run_id, job.dataset_name, job.resource_server_url, job.additional_context)
    result['run_id'] = str(run_id)
    return result

def post_run(task):
    print(task.result)
    result = task.result
    run_id = result.pop('run_id')
    r = Run.objects.get(run_id=run_id)
    r.status = 'S'
    r.ended_at=datetime.now(timezone.utc)
    r.result = result
    r.save()
