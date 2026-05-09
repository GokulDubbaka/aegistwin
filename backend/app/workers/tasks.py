"""Async Celery tasks for background agent execution."""
import logging
from app.workers.celery_app import celery_app
from app.agents.offensive.agent import OffensiveMissionPlanner
from app.agents.defensive.agent import ActorClusterBuilder

logger = logging.getLogger(__name__)


@celery_app.task(name="app.workers.tasks.run_offensive_mission", bind=True)
def run_offensive_mission(self, tenant_id: str, engagement_id: str,
                          objective: str, assets: list,
                          allowed_targets: list = None) -> dict:
    """Background task: run full offensive mission."""
    try:
        planner = OffensiveMissionPlanner(tenant_id, engagement_id)
        return planner.run_mission(objective, assets, allowed_targets)
    except Exception as exc:
        logger.exception("Offensive mission task failed")
        raise self.retry(exc=exc, countdown=30, max_retries=2)


@celery_app.task(name="app.workers.tasks.run_defensive_analysis", bind=True)
def run_defensive_analysis(self, tenant_id: str, events: list) -> dict:
    """Background task: run defensive analysis on a batch of events."""
    try:
        builder = ActorClusterBuilder(tenant_id)
        return builder.build_cluster(events)
    except Exception as exc:
        logger.exception("Defensive analysis task failed")
        raise self.retry(exc=exc, countdown=30, max_retries=2)
