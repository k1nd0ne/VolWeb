from django.contrib import admin
from django_celery_results.models import TaskResult
from windows_engine.models import Loot

# Register your models here.
admin.site.register(Loot)
