from celery import Celery
from core.config import settings

celery_app = Celery("aperia", broker=settings.REDIS_URL, backend=settings.REDIS_URL)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_routes={
        "presentation.workers.scan_worker.*":        {"queue": "scan"},
        "presentation.workers.analysis_worker.*":    {"queue": "analysis"},
        "presentation.workers.remediation_worker.*": {"queue": "remediation"},
    },
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_time_limit=1800,
    task_soft_time_limit=1500,
    task_track_started=True,
    result_expires=86400,
)
