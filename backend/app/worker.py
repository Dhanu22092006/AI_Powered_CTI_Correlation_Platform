from celery import Celery
from .config import settings

celery_app = Celery("cti_worker", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.update(task_serializer="json", accept_content=["json"], result_serializer="json", timezone="UTC")

@celery_app.task(name="health_check")
def health_check():
    return {"status": "ok"}
