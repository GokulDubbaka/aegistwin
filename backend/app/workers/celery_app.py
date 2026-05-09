"""Celery application configuration."""
from celery import Celery
from app.core.config import settings

celery_app = Celery(
    "aegistwin",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_routes={
        "app.workers.tasks.run_offensive_mission": {"queue": "offensive"},
        "app.workers.tasks.run_defensive_analysis": {"queue": "defensive"},
    },
)
