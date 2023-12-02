from celery import shared_task
from evidences.models import Evidence
from windows_engine.vol_windows import run_volweb_routine_windows


@shared_task
def start_analysis(instance_id):
    instance = Evidence.objects.get(dump_id=instance_id)
    if instance.dump_os == "Windows":
        print("GO FOR LAUNCH")
        run_volweb_routine_windows(instance)
