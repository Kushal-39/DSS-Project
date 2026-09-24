"""Open Policy Agent (OPA) ABAC evaluation client."""

import logging
from decimal import Decimal
from typing import List, Tuple
import httpx

from src.config import settings

logger = logging.getLogger("account-service")


class PolicyClient:
    def __init__(self, endpoint_url: str):
        self.endpoint_url = endpoint_url

    async def evaluate(
        self,
        user_id: str,
        roles: List[str],
        action: str,
        resource: str,
        amount: Decimal,
        ip_address: str,
        mtls_verified: bool = True,
    ) -> Tuple[bool, str]:
        """
        Evaluate ABAC rules with Policy Engine (Person 3).
        Enforces the exact nested payload structure:
        {
          "input": {
            "subject": {"user_id": ..., "roles": [...]},
            "action": ...,
            "resource": ...,
            "context": {"amount": float, "ip_address": ..., "mTLS_verified": bool}
          }
        }
        """
        payload = {
            "input": {
                "subject": {
                    "user_id": str(user_id),
                    "roles": roles,
                },
                "action": action,
                "resource": resource,
                "context": {
                    "amount": float(amount),
                    "ip_address": ip_address,
                    "mTLS_verified": bool(mtls_verified),
                },
            }
        }

        try:
            async with httpx.AsyncClient(timeout=settings.POLICY_TIMEOUT_SECONDS) as client:
                response = await client.post(
                    self.endpoint_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )

            if response.status_code != 200:
                logger.warning(
                    f"Policy Engine returned non-200 status: {response.status_code} ({response.text})"
                )
                return False, f"policy_engine_error_{response.status_code}"

            data = response.json()
            result = data.get("result", {})
            # Contract: {"result": {"allow": true}}
            is_allowed = result.get("allow") is True

            if is_allowed:
                return True, "policy_allowed"
            else:
                return False, "policy_denied"

        except httpx.TimeoutException:
            logger.error("Policy Engine evaluation timed out — failing closed")
            return False, "policy_engine_timeout"
        except httpx.ConnectError:
            logger.error("Policy Engine unreachable — failing closed")
            return False, "policy_engine_unreachable"
        except Exception as e:
            logger.error(f"Policy evaluation unexpected error: {e} — failing closed")
            return False, f"policy_eval_exception_{type(e).__name__}"


policy_client = PolicyClient(settings.POLICY_ENGINE_URL)
