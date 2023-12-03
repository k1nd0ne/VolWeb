from celery import Celery
import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "VolWeb.settings")
app = Celery("VolWeb")
app.config_from_object("django.conf:settings", namespace="CELERY")

app.conf.update(
    result_expires=3600,
)
app.conf.task_track_started = True
app.autodiscover_tasks()
