"""Bounded OTLP/JSON export and W3C trace propagation for Python services."""
import asyncio
from contextlib import suppress
import json
import os
import re
import secrets
import time
from datetime import datetime, timezone

import httpx

TRACE = re.compile(r"00-(?!0{32})[0-9a-f]{32}-(?!0{16})[0-9a-f]{16}-[0-9a-f]{2}")


class TraceMiddleware:
    def __init__(self, app, service):
        self.app, self.service = app, service
        self.queue = asyncio.Queue(maxsize=512)
        self.worker = None

    async def export(self):
        async with httpx.AsyncClient(timeout=2) as client:
            while True:
                payload = await self.queue.get()
                try:
                    await client.post(os.environ["OTLP_ENDPOINT"], json=payload,
                                      headers={"X-Telemetry-Token": os.getenv("TELEMETRY_INGEST_TOKEN", "")})
                except httpx.HTTPError:
                    pass
                finally:
                    self.queue.task_done()

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            async def lifecycle_send(message):
                if message["type"] == "lifespan.shutdown.complete" and self.worker:
                    with suppress(asyncio.TimeoutError):
                        await asyncio.wait_for(self.queue.join(), timeout=3)
                    self.worker.cancel()
                    with suppress(asyncio.CancelledError):
                        await self.worker
                    self.worker = None
                await send(message)
            await self.app(scope, receive, lifecycle_send)
            return
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope["headers"])
        parent = headers.get(b"traceparent", b"").decode("ascii", errors="ignore")
        if not TRACE.fullmatch(parent):
            parent = "00-" + secrets.token_hex(16) + "-" + secrets.token_hex(8) + "-01"
            parent_id = ""
        else:
            parent_id = parent.split("-")[2]
        trace_id, span_id = parent.split("-")[1], secrets.token_hex(8)
        current = f"00-{trace_id}-{span_id}-{parent.split('-')[3]}"
        scope["headers"] = [(key, value) for key, value in scope["headers"] if key != b"traceparent"] + [(b"traceparent", current.encode())]
        start = time.time_ns()
        status = 500

        async def traced_send(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                message["headers"] = [(key, value) for key, value in message.get("headers", []) if key.lower() != b"traceparent"] + [(b"traceparent", current.encode())]
            await send(message)

        try:
            await self.app(scope, receive, traced_send)
        finally:
            if self.service == "gateway":
                print(json.dumps({"time": datetime.now(timezone.utc).isoformat(), "service": self.service,
                                  "msg": "http_request", "method": scope["method"], "path": scope["path"],
                                  "status": status, "traceparent": current}), flush=True)
            if os.getenv("OTLP_ENDPOINT") and scope["path"] not in {"/healthz", "/readyz", "/metrics"}:
                span = {"traceId": trace_id, "spanId": span_id, "parentSpanId": parent_id,
                        "name": scope["method"] + " " + scope["path"], "kind": 2,
                        "startTimeUnixNano": str(start), "endTimeUnixNano": str(time.time_ns()),
                        "status": {"code": "STATUS_CODE_ERROR" if status >= 400 else "STATUS_CODE_OK"}}
                payload = {"resourceSpans": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": self.service}}]},
                                             "scopeSpans": [{"spans": [span]}]}]}
                if self.worker is None:
                    self.worker = asyncio.create_task(self.export())
                try:
                    self.queue.put_nowait(payload)
                except asyncio.QueueFull:
                    pass
