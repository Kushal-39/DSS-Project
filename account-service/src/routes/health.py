"""Health and readiness probe endpoints."""

from fastapi import APIRouter, Response, status
import httpx

from src.database import db
from src.config import settings

router = APIRouter(tags=["Health"])


@router.get("/healthz", status_code=status.HTTP_200_OK)
async def liveness():
    """Liveness probe: reports if process is running."""
    return {"status": "ok"}


@router.get("/readyz")
async def readiness(response: Response):
    """
    Readiness probe: pings database and policy engine.
    Returns 200 if dependencies are ready, 503 if not ready to serve traffic.
    """
    db_ok = await db.is_healthy()

    policy_engine_ok = False
    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            # Check OPA health or policy endpoint
            opa_health_url = settings.POLICY_ENGINE_URL.split("/v1/data")[0] + "/health"
            res = await client.get(opa_health_url)
            policy_engine_ok = res.status_code in (200, 204)
    except Exception:
        policy_engine_ok = False

    is_ready = db_ok and policy_engine_ok

    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "unhealthy",
            "database": "connected" if db_ok else "unreachable",
            "policy_engine": "reachable" if policy_engine_ok else "unreachable",
        }

    return {
        "status": "ready",
        "database": "connected",
        "policy_engine": "reachable" if policy_engine_ok else "unreachable",
    }
