import django_tables2 as tables
from .models import Job, Run
from django.utils.html import format_html

class JobsTable(tables.Table):
    def render_name(self, value, record):
        return format_html("<a href='/provider/runs/{}'>{}</a>", record.job_id, value)

    class Meta:
        model = Job
        name = tables.Column()
        sequence = ("name", "description", "resource_id", "app", "schedule", "date_time")
        exclude = ("id", "job_id", "provider")

class RunsTable(tables.Table):
    def render_result(self, value, record):
        if record.status == Run.RunStatus.SUCCESS:
            name = str(record).replace(' ', '-') + ".json"
            filename_w_quotes = f'"{name}"'
            return format_html("<button type='button' class='btn btn-primary' onclick='download_inference({}, {})'>Download Inference</button>", value, filename_w_quotes)
        else:
            return format_html("<button type='button' class='btn btn-primary' disabled>Download Inference</button>")

    def render_status(self, value, record):
        return format_html("<a href='/provider/run-status/{}'>{}</a>", record.run_id, value)

    class Meta:
        model = Run
        sequence = ("job", "status", "started_at", "ended_at", "result")
        exclude = ("id", "run_id",)
