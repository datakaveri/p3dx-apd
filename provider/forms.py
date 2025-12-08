from django import forms
from .models import App, Job
from django.utils.translation import gettext_lazy as _

class AppModelChoiceField(forms.ModelChoiceField):
    def label_from_instance(self, obj):
        return f"{obj.name} - Runs on {App.AppExecutionPlatforms(obj.execution_platform).label}"

class JobForm(forms.ModelForm):
    date_time = forms.DateTimeField(disabled=True)
    #schedule = forms.DurationField(required=True, help_text='How often to run the enclave, in minutes',label='Schedule (in minutes)' )
    app = AppModelChoiceField(queryset=App.objects.all())

    class Meta:
        model = Job
        fields = ('name', 'description', 'app', 'dataset_name', 'resource_server_url', 'date_time')
        labels = {
                'resource_id': _('Resource ID'),
                'app': _('Application'),
                'dataset_name': _('Dataset Name'),
                'resource_server_url': _('Resource Server URL'),
                }
        help_texts = {
                'name': _('Name of the enclave task'),
                'app': _('The application to run on the enclave '),
                'dataset_name': _('Name of the dataset to be operated upon'),
                'resource_server_url': _('URL of the resource server containing the dataset'),
                }
