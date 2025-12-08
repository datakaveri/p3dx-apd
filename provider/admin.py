from django.contrib import admin

# Register your models here.

from .models import App, Provider, Job, Run

admin.site.register(App)
admin.site.register(Provider)
admin.site.register(Job)
admin.site.register(Run)
