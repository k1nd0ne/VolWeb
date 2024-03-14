from celery import Celery
import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "VolWeb.settings")
app = Celery("VolWeb")
app.config_from_object("django.conf:settings", namespace="CELERY")

app.conf.update(
    result_expires=3600,
)
app.conf.broker_transport_options = {
    "priority_steps": list(range(10)),
    "sep": ":",
    "queue_order_strategy": "priority",
}
app.conf.task_track_started = True
app.autodiscover_tasks()
