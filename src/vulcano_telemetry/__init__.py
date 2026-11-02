"""Vulcano Pay event engine: SQS + HMAC signed webhooks.
Public API of the package. The FastAPI receiver
(``vulcano_telemetry.webhook_receiver``) is intentionally *not* imported
here so that using the package does not require FastAPI.
"""
from .core_sqs import (
    consume_events,
    delete_event,
    dlq_name_for,
    ensure_queues,
    get_queue_url,
    get_sqs_client,
    produce_event,
)
from .exceptions import (
    CorruptedMessageError,
    QueueTimeoutError,
    SQSConnectionError,
    VulcanoError,
    WebhookDeliveryError,
    WebhookSignatureError,
    WebhookTimestampError,
)
from .logging_engine import (
    AsyncJSONFormatter,
    setup_vulcano_logging,
    stop_vulcano_logging,
)
from .sanitizer import (
    parse_json_object,
    parse_port,
    parse_queue_name,
    parse_secret_key,
    parse_wait_time,
    parse_webhook_url,
)
from .webhook_crypto import (
    SIGNATURE_HEADER,
    build_signature_header,
    generate_signature,
    verify_signature,
)

__version__ = "1.0.0"
__all__ = [
    # exceptions
    "VulcanoError",
    "SQSConnectionError",
    "QueueTimeoutError",
    "CorruptedMessageError",
    "WebhookSignatureError",
    "WebhookTimestampError",
    "WebhookDeliveryError",
    # sanitizer
    "parse_queue_name",
    "parse_wait_time",
    "parse_webhook_url",
    "parse_secret_key",
    "parse_port",
    "parse_json_object",
    # crypto
    "SIGNATURE_HEADER",
    "generate_signature",
    "build_signature_header",
    "verify_signature",
    # sqs
    "get_sqs_client",
    "ensure_queues",
    "dlq_name_for",
    "get_queue_url",
    "produce_event",
    "consume_events",
    "delete_event",
    # logging
    "AsyncJSONFormatter",
    "setup_vulcano_logging",
    "stop_vulcano_logging",
]
