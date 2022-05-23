from celery import Celery
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'VolWeb.settings')
app = Celery('investigations',
             broker=os.getenv('BROKER_URL'),
             backend='rpc://',
             include=['investigations.tasks'])

# Optional configuration, see the application user guide.
app.conf.update(
    result_expires=3600,
)
app.autodiscover_tasks()
if __name__ == '__main__':
    app.start()
