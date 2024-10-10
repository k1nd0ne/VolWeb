from celery import shared_task


@shared_task
def start_analysis(evidence_id):
    """
    The main celery task to launch the artefacts extraction
    """
    print("STARTED")
