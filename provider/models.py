from django.db import models
from django.utils.translation import gettext_lazy as _

# Create your models here.

class App(models.Model):
    class AppExecutionPlatforms(models.TextChoices):
        AWS_NITRO = "NITRO", _("AWS Nitro")
        INTEL_SGX = "SGX", _("Intel SGX")
        AZURE_AMD_SEV = "AZURE AMD SEV", _("Azure AMD SEV")

    name = models.CharField(max_length=200)
    description = models.CharField(max_length=200)
    git_url = models.CharField(max_length=200)
    git_branch = models.CharField(max_length=200)
    git_commit_hash = models.CharField(max_length=200)
    base_pcrs = models.JSONField()
    execution_platform = models.CharField(max_length=20, choices=AppExecutionPlatforms.choices)

    def __str__(self):
        return self.name

class Provider(models.Model):
    iudx_id = models.UUIDField()

class Job(models.Model):
    job_id = models.UUIDField()
    name = models.CharField(max_length=200)
    description = models.CharField(max_length=200)
    resource_id = models.CharField(max_length=200)
    app = models.ForeignKey(App, on_delete=models.CASCADE)
    provider = models.ForeignKey(Provider, on_delete=models.CASCADE) 
    schedule = models.DurationField(null=True, blank=True)
    date_time = models.DateTimeField(null=True, blank=True)
    dataset_name = models.CharField(max_length=200)
    resource_server_url = models.CharField(max_length=200)
    additional_context = models.JSONField(null=True, blank=True)

    def __str__(self):
        return self.name

class Run(models.Model):
    class RunStatus(models.TextChoices):
        RUNNING = 'R'
        SUCCESS = 'S'
        FAILURE = 'F'
        KILLED = 'K'

    run_id = models.UUIDField()
    job = models.ForeignKey(Job, on_delete=models.CASCADE)
    status = models.CharField(max_length=1, choices=RunStatus.choices)
    status_info = models.JSONField(default=dict)
    started_at = models.DateTimeField()
    ended_at = models.DateTimeField()
    result = models.JSONField(null=True, blank=True)

    def __str__(self):
        return self.job.name + " at " + str(self.started_at)
