from celery import Celery
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'VolWeb.settings')
app = Celery('investigations',
             broker='redis://redis:6379/0',
             backend='redis://redis:6379/0',
             include=['investigations.tasks'])

# Optional configuration, see the application user guide.
app.conf.update(
    result_expires=3600,
)
app.autodiscover_tasks()
if __name__ == '__main__':
    app.start()
