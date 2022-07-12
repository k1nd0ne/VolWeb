from celery import Celery
import os
from VolWeb.keyconfig import Secrets
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'VolWeb.settings')
app = Celery('investigations',
             broker=Secrets.BROKER_URL,
             backend='rpc://',
             include=['investigations.tasks','windows_engine.tasks'])

app.conf.update(
    result_expires=3600,
)
app.autodiscover_tasks()
if __name__ == '__main__':
    app.start()
