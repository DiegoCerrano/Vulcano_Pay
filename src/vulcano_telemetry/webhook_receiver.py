"""FastAPI server that authenticates incoming webhooks and enqueues them.

Configuration comes from environment variables (never hard-coded):

* ``VULCANO_WEBHOOK_SECRET``: shared HMAC secret (required).
* ``VULCANO_QUEUE_NAME``: queue name (default ``vulcano-events-queue``).
* ``VULCANO_SQS_ENDPOINT``: LocalStack URL (default ``http://localhost:4566``).
"""
import asyncio
import json
import logging
import os
import uuid
from functools import lru_cache
from typing import Any
from fastapi import FastAPI, Header, HTTPException, Request, status
from .core_sqs import (
    DEFAULT_ENDPOINT_URL,
    DEFAULT_QUEUE_NAME,
    get_queue_url,
    get_sqs_client,
    produce_event,
)
from .exceptions import (
    QueueTimeoutError,
    SQSConnectionError,
    WebhookSignatureError,
    WebhookTimestampError,
)

from .logging_engine import mask_signature
from .webhook_crypto import verify_signature

logger = logging.getLogger("vulcano_engine")
app = FastAPI(title="Vulcano Webhook Receiver")


@lru_cache(maxsize=4)
def _cached_client(endpoint_url: str) -> Any:
    """Return one SQS client per endpoint (one per request is slow)."""
    return get_sqs_client(endpoint_url)


@lru_cache(maxsize=4)
def _cached_queue_url(endpoint_url: str, queue_name: str) -> str:
    """Resolve the queue URL once; failures are not cached, so it retries."""
    return get_queue_url(_cached_client(endpoint_url), queue_name)


@app.post("/webhook", status_code=status.HTTP_202_ACCEPTED)
async def receive_webhook(
    request: Request,
    x_webhook_signature: str | None = Header(default=None),
) -> dict[str, str]:
    """Receive a signed webhook, verify it and publish it to SQS.
    Order of operations (it matters):
    1. Read the **raw bytes** of the body.
    2. Verify the HMAC signature and the timestamp over those bytes.
    3. Only then parse the JSON and publish it to SQS.
    4. Answer ``202 Accepted``.
    Args:
    request: The incoming HTTP request.
    x_webhook_signature: ``X-Webhook-Signature`` header (optional here so
    that a missing header yields 401 instead of FastAPI's 422).

    Returns:
    A small JSON acknowledgement with the ``trace_id`` and ``message_id``.
    Raises:
    HTTPException: 401 (bad/missing signature or timestamp), 400 (body
    is not a JSON object), 500 (server without secret) or
    503 (SQS unavailable).
    """

    trace_id = str(uuid.uuid4())
    secret = os.getenv("VULCANO_WEBHOOK_SECRET")
    if not secret:
        logger.error("VULCANO_WEBHOOK_SECRET is not configured")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Server misconfigured.")

    # 1) bytes crudos ANTES de cualquier .json(): la firma se calcula sobre
    # estos bytes exactos, no sobre un JSON re-serializado.
    raw_body = await request.body()
    # 2) autenticacion
    try:
        verify_signature(secret, x_webhook_signature or "", raw_body)
    except (WebhookSignatureError, WebhookTimestampError) as err:
        logger.warning(
            "Webhook rejected: %s",
            err,
            extra={
                "trace_id": trace_id,
                "webhook_signature": mask_signature(x_webhook_signature or ""),
            },
        )
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail=str(err)
        ) from err

    # 3) recien ahora se interpreta el JSON
    try:
        event_data = json.loads(raw_body)
    except ValueError as err:  # incluye JSONDecodeError y UnicodeDecodeError
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail="Body is not valid JSON."
        ) from err
    if not isinstance(event_data, dict):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail="Body must be a JSON object."
        )

    webhook_id = str(event_data.get("id", trace_id))
    event_topic = str(event_data.get("event_type", "payment.unknown"))

    # boto3 es bloqueante: to_thread lo saca del event loop para no frenar
    # a los demas requests.
    endpoint = os.getenv("VULCANO_SQS_ENDPOINT", DEFAULT_ENDPOINT_URL)
    queue_name = os.getenv("VULCANO_QUEUE_NAME", DEFAULT_QUEUE_NAME)
    try:
        queue_url = await asyncio.to_thread(
            _cached_queue_url, endpoint, queue_name
        )
        message_id = await asyncio.to_thread(
            produce_event,
            _cached_client(endpoint),
            queue_url,
            event_data,
            trace_id,
            event_topic,
        )
    except (SQSConnectionError, QueueTimeoutError) as err:
        logger.error(
            "Could not enqueue webhook",
            extra={"trace_id": trace_id, "webhook_id": webhook_id},
            exc_info=True,
        )
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, detail="Queue unavailable."
        ) from err

    logger.info(
        "Webhook verified and enqueued",
        extra={
            "trace_id": trace_id,
            "message_id": message_id,
            "webhook_id": webhook_id,
            "webhook_signature": mask_signature(x_webhook_signature or ""),
        },
    )
    return {
        "status": "accepted",
        "trace_id": trace_id,
        "message_id": message_id,
    }
