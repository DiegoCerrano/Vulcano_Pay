"""
SQS access layer built on Boto3 and Local Stack.

Everything that talks to SQS lives here. Boto3 raises two
unrelated families of errors ("ClientError" for API errors
and "BotoCoreError" for networks problems.); This module translates
both into the engine's own exceptions so the rest of the code only
deals with :'vulcano_telemetry.exceptions'.
"""


import json
import logging
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any
from collections.abc import Generator

import boto3
from botocore.config import Config
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectTimeoutError,
    ReadTimeoutError,
)

from .exceptions import (
    CorruptedMessageError,
    QueueTimeoutError,
    SQSConnectionError,
)

logger = logging.getLogger("vulcano_engine")

DEFAULT_ENDPOINT_URL = "http://localhost:4566"
DEFAULT_QUEUE_NAME = "vulcano-events-queue"
DEFAULT_MAX_RECEIVE_COUNT = 3
DEFAULT_VISIBILITY_TIMEOUT = 30


def get_sqs_client(endpoint_url: str | None = None) -> Any:
    """Create a Boto3 SQS client pointing at LocalStack.
    Args:
    endpoint_url: LocalStack URL. Defaults to the ``VULCANO_SQS_ENDPOINT``
    environment variable, or ``http://localhost:4566``.
    Returns:
    A configured ``boto3`` SQS client.
    """
    endpoint = endpoint_url or os.getenv(
        "VULCANO_SQS_ENDPOINT", DEFAULT_ENDPOINT_URL
    )
    # read_timeout > 20 s: el Long Polling puede esperar hasta 20 s y no
    # queremos que el cliente corte antes. connect_timeout corto: si
    # LocalStack esta apagado, que falle rapido.
    config = Config(
        connect_timeout=3,
        read_timeout=30,
        retries={"max_attempts": 2, "mode": "standard"},
    )
    return boto3.client(
        "sqs",
        endpoint_url=endpoint,
        region_name="us-east-1",
        aws_access_key_id="test",  # credenciales simuladas (LocalStack)
        aws_secret_access_key="test",
        config=config,
    )


@contextmanager
def _translate_boto_errors(action: str, target: str) -> Generator[None, None, None]:
    """Translate Boto3 errors into engine exceptions (context manager).
    Args:
        action: Human readable description, e.g. ``"send a message"``.
        target: Queue URL or name, added to the error as a note.
    Raises:
        QueueTimeoutError: On connect/read timeouts.
        SQSConnectionError: On any other ``ClientError`` or ``BotoCoreError``.
    """
    try:
        yield
        # Orden importante: los timeouts son subclases de BotoCoreError, así que
        # deben capturarse ANTES que la clase general.
    except (ConnectTimeoutError, ReadTimeoutError) as err:
        timeout_error = QueueTimeoutError(f"Timeout while trying to {action}.")
        timeout_error.add_note(f"Target: {target}")
        raise timeout_error from err

    except (ClientError, BotoCoreError) as err:
        sqs_error = SQSConnectionError(f"Failed to {action}.")
        sqs_error.add_note(f"Target: {target}")
        raise sqs_error from err


def dlq_name_for(queue_name: str) -> str:
    """Derive the Dead Letter Queue name from the main queue name.
    Args:
    queue_name: Name like ``"vulcano-events-queue"``.
    Returns:
    The matching DLQ name, e.g. ``"vulcano-events-dlq"``.
    """
    return queue_name.removesuffix("-queue") + "-dlq"


def ensure_queues(
    sqs_client: Any,
    queue_name: str = DEFAULT_QUEUE_NAME,
    max_receive_count: int = DEFAULT_MAX_RECEIVE_COUNT,
    visibility_timeout: int = DEFAULT_VISIBILITY_TIMEOUT,
) -> tuple[str, str]:
    """Create (if needed) the main queue and its Dead Letter Queue.
    The main queue gets a *RedrivePolicy*: after a message has been received
    ``max_receive_count`` times without being deleted, SQS moves it to the
    DLQ automatically. This is how poison messages end up in the DLQ.
    The function is idempotent: calling it again is harmless.
    Args:
    sqs_client: Boto3 SQS client.
    queue_name: Name of the main queue.
    max_receive_count: Receives allowed before moving to the DLQ.
    visibility_timeout: Seconds a received message stays hidden.
    Returns:
    A tuple ``(queue_url, dlq_url)``.
    Raises:
    SQSConnectionError: If SQS cannot be reached or rejects the call.
    QueueTimeoutError: If SQS does not answer in time.
    """

    with _translate_boto_errors("create the queues", queue_name):
        dlq_url = sqs_client.create_queue(
            QueueName=dlq_name_for(queue_name)
        )["QueueUrl"]
        dlq_arn = sqs_client.get_queue_attributes(
            QueueUrl=dlq_url, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]

        # create_queue sin atributos es idempotente; los atributos se
        # aplican despues con set_queue_attributes (funciona aunque la cola
        # ya existiera con otra configuracion).
        queue_url = sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
        sqs_client.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes={
                "VisibilityTimeout": str(visibility_timeout),
                "RedrivePolicy": json.dumps(
                    {
                        "deadLetterTargetArn": dlq_arn,
                        "maxReceiveCount": str(max_receive_count),
                    }
                ),
            },
        )
    logger.info(
        "Queues ready: %s -> DLQ %s", queue_name, dlq_name_for(queue_name)
    )
    return queue_url, dlq_url


def get_queue_url(sqs_client: Any, queue_name: str) -> str:
    """Resolve the URL of an existing queue from its name.
    Args:
    sqs_client: Boto3 SQS client.
    queue_name: Name of the queue.
    Returns:
    The queue URL.
    Raises:
    SQSConnectionError: If SQS fails or the queue does not exist.
    QueueTimeoutError: If SQS does not answer in time.
    """
    with _translate_boto_errors("resolve the queue URL", queue_name):
        return sqs_client.get_queue_url(QueueName=queue_name)["QueueUrl"]


def produce_event(
    sqs_client: Any,
    queue_url: str,
    event_data: dict[str, Any],
    trace_id: str,
    event_topic: str,
    timestamp: str | None = None,
) -> str:
    """Publish a JSON event in the queue.
    Args:
    sqs_client: Boto3 SQS client.
    queue_url: Destination queue URL.
    event_data: Event payload (must be JSON serialisable).
    trace_id: Correlation id that follows the event end to end.
    event_topic: Event type, e.g. ``"payment.completed"``.
    timestamp: ISO 8601 UTC timestamp. Defaults to "now".
    Returns:
    The ``MessageId`` assigned by SQS.
    Raises:
    SQSConnectionError: If SQS cannot be reached or rejects the call.
    QueueTimeoutError: If SQS does not answer in time.
    """

    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()
    # Los MessageAttributes viajan junto al mensaje sin tener que parsearlo.
    attributes = {
        "TraceId": {"DataType": "String", "StringValue": trace_id},
        "EventTopic": {"DataType": "String", "StringValue": event_topic},
        "Timestamp": {"DataType": "String", "StringValue": timestamp},
    }

    with _translate_boto_errors("send a message", queue_url):
        response = sqs_client.send_message(
            QueueUrl=queue_url,
            MessageBody=json.dumps(event_data),
            MessageAttributes=attributes,
        )
    message_id = response["MessageId"]
    logger.info(
        "Event published to SQS (topic=%s)",
        event_topic,
        extra={"trace_id": trace_id, "message_id": message_id},
    )
    return message_id


def decode_message_body(message: dict[str, Any]) -> dict[str, Any]:
    """Decode the body of a raw SQS message into a dictionary.
    Args:
    message: A message as returned by ``receive_message``.
    Returns:
    The decoded JSON object.
    Raises:
    CorruptedMessageError: If the body is not valid JSON, or is valid
    JSON but not an object (poison message).
    """
    try:
        body = json.loads(message.get("Body", ""))
    except json.JSONDecodeError as err:
        corrupted = CorruptedMessageError("Message body is not valid JSON.")
        corrupted.add_note(f"MessageId: {message.get('MessageId')}")
        raise corrupted from err
    if not isinstance(body, dict):
        corrupted = CorruptedMessageError("Message body is not a JSON object.")
        corrupted.add_note(f"MessageId: {message.get('MessageId')}")
        raise corrupted
    return body


def consume_events(
    sqs_client: Any,
    queue_url: str,
    wait_time: int = 10,
    max_messages: int = 5,
    visibility_timeout: int | None = None,
) -> list[dict[str, Any]]:
    """Receive a batch of events using Long Polling.
    Poison messages are logged and **skipped without being deleted**, so SQS
    keeps counting receives and finally moves them to the DLQ. Healthy
    messages of the same batch are still returned.
    Args:
        sqs_client: Boto3 SQS client.
        queue_url: Queue to read from.
        wait_time: Long Polling seconds (``WaitTimeSeconds``, 1-20).
        max_messages: Maximum messages per batch (1-10).
        visibility_timeout: Optional override, in seconds.
    Returns:
        A list of dicts with ``receipt_handle``, ``message_id``,
        ``trace_id``, ``event_topic`` and ``body``.
    Raises:
        SQSConnectionError: If SQS cannot be reached or rejects the call.
        QueueTimeoutError: If SQS does not answer in time.
    """

    params: dict[str, Any] = {
        "QueueUrl": queue_url,
        "MaxNumberOfMessages": max_messages,
        "WaitTimeSeconds": wait_time,
        "MessageAttributeNames": ["All"],
    }
    if visibility_timeout is not None:
        params["VisibilityTimeout"] = visibility_timeout

    with _translate_boto_errors("receive messages", queue_url):
        response = sqs_client.receive_message(**params)

    events = []
    for message in response.get("Messages", []):
        try:
            body = decode_message_body(message)
        except CorruptedMessageError:
            logger.warning(
                "Poison message skipped (it will end up in the DLQ)",
                extra={"message_id": message.get("MessageId")},
                exc_info=True,
            )
            continue  # NO se borra: SQS lo contará y lo mandará a la DLQ

        attributes = message.get("MessageAttributes", {})
        events.append(
            {
                "receipt_handle": message["ReceiptHandle"],
                "message_id": message["MessageId"],
                "trace_id": attributes.get("TraceId", {}).get("StringValue"),
                "event_topic": attributes.get("EventTopic", {}).get(
                    "StringValue"
                ),
                "body": body,
            }
        )

    return events


def delete_event(
        sqs_client: Any, queue_url: str, receipt_handle: str
) -> None:
    """Delete a message that was processed successfully.
    Args:
    sqs_client: Boto3 SQS client.
    queue_url: Queue the message came from.
    receipt_handle: Handle returned by ``receive_message``.
    Raises:
    SQSConnectionError: If SQS cannot be reached or rejects the call.
    QueueTimeoutError: If SQS does not answer in time.
    """

    with _translate_boto_errors("delete a message", queue_url):
        sqs_client.delete_message(
            QueueUrl=queue_url, ReceiptHandle=receipt_handle
        )
