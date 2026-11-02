"""Command line entry point of the Vulcano Pay event engine.

Sub-commands::
    produce-sqs          publish one event straight to the SQS queue
    start-receiver       run the HTTP server that receives signed webhooks
    start-dispatcher     consume SQS and re-send each event as a signed webhook

Run it from the repository root, for example::
    python src/app_operator.py produce-sqs --topic payment.completed
"""
import argparse
import asyncio
import json
import logging
import os
import sys
import time
import uuid
from typing import Any

import requests
from vulcano_telemetry import (
    SIGNATURE_HEADER,
    QueueTimeoutError,
    SQSConnectionError,
    VulcanoError,
    WebhookDeliveryError,
    WebhookSignatureError,
    WebhookTimestampError,
    build_signature_header,
    consume_events,
    delete_event,
    ensure_queues,
    get_sqs_client,
    parse_json_object,
    parse_port,
    parse_queue_name,
    parse_secret_key,
    parse_wait_time,
    parse_webhook_url,
    produce_event,
    setup_vulcano_logging,
    stop_vulcano_logging,
)
from vulcano_telemetry.core_sqs import DEFAULT_ENDPOINT_URL, DEFAULT_QUEUE_NAME
from vulcano_telemetry.logging_engine import DEFAULT_LOG_FILE

logger = logging.getLogger("vulcano_engine")

# --- Exit codes (so a script or CI can tell what went wrong) ---------------
EXIT_OK = 0
EXIT_SIGNATURE_ERROR = 2
EXIT_TIMESTAMP_ERROR = 3
EXIT_SQS_ERROR = 4
EXIT_TIMEOUT_ERROR = 5
EXIT_DOMAIN_ERROR = 6

# --- Webhook delivery policy -----------------------------------------------
REQUEST_TIMEOUT = 10  # segundos por intento HTTP
RETRY_DELAYS = (1, 2)  # espera antes del 2do y 3er intento (3 intentos)
DEFAULT_DESTINATION_URL = "http://localhost:9000/webhook"

SAMPLE_PAYLOAD = (
    '{"id": "evt_1001", "event_type": "payment.completed", '
    '"transaction_id": "tx_9981", "amount": 350.0, "status": "COMPLETED"}'
)


# ==========================================================================
# Webhook dispatcher (client side)
# ==========================================================================
def _is_retryable(error: requests.RequestException) -> bool:
    """Decide whether a failed HTTP attempt deserves another try.
    Args:
        error: The exception raised by ``requests``.
    Returns:
        ``True`` for network errors, timeouts, 429 and 5xx responses;
        ``False`` for other 4xx responses (retrying will not help).
    """
    if isinstance(error, (requests.ConnectionError, requests.Timeout)):
        return True
    if isinstance(error, requests.HTTPError) and error.response is not None:
        status_code = error.response.status_code
        return status_code == 429 or status_code >= 500
    return False


def dispatch_webhook(
    target_url: str,
    secret: str,
    payload_dict: dict[str, Any],
    retry_delays: tuple[int, ...] = RETRY_DELAYS,
) -> None:
    """Sign a payload and POST it to the destination, with retries.
    Args:
        target_url: Destination webhook URL.
        secret: Shared HMAC secret used to sign the message.
        payload_dict: Event to send (JSON serialisable).
        retry_delays: Seconds to wait between attempts. Its length plus one
        is the maximum number of attempts.
    Raises:
        WebhookDeliveryError: If every attempt failed, or the failure is not
        worth retrying (e.g. 404).
    """
    # Serializamos UNA vez: lo que se firma y lo que se envia deben ser
    # exactamente los mismos bytes.
    payload = json.dumps(
        payload_dict, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    max_attempts = len(retry_delays) + 1
    for attempt in range(1, max_attempts + 1):
        # Se firma en CADA intento para que el timestamp siempre este fresco.
        headers = {
            "Content-Type": "application/json",
            SIGNATURE_HEADER: build_signature_header(secret, payload),
        }
        try:
            response = requests.post(
                target_url,
                data=payload,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            return
        except requests.RequestException as err:
            if not _is_retryable(err) or attempt == max_attempts:
                delivery_error = WebhookDeliveryError(
                    f"Webhook delivery failed after {attempt} attempt(s)."
                )
                delivery_error.add_note(f"Destination: {target_url}")
                raise delivery_error from err
            delay = retry_delays[attempt - 1]
            logger.warning(
                "Delivery attempt %d/%d failed (%s). Retrying in %ds",
                attempt,
                max_attempts,
                type(err).__name__,
                delay,
            )
            time.sleep(delay)


async def process_event(
    sqs_client: Any,
    queue_url: str,
    event: dict[str, Any],
    target_url: str,
    secret: str,
) -> bool:
    """Deliver one SQS event and delete it only if delivery succeeded.
    A failed delivery is **not** deleted: SQS will show it again after the
    visibility timeout and, after ``maxReceiveCount`` receives, move it to
    the Dead Letter Queue.
    Args:
        sqs_client: Boto3 SQS client.
        queue_url: Queue the event came from.
        event: One item returned by ``consume_events``.
        target_url: Destination webhook URL.
        secret: Shared HMAC secret.
    Returns:
        ``True`` if the event was delivered and deleted, ``False`` if the
        delivery failed.
    Raises:
        SQSConnectionError: If the message could not be deleted.
        QueueTimeoutError: If SQS timed out while deleting the message.
    """
    context = {
        "trace_id": event["trace_id"],
        "message_id": event["message_id"],
    }
    try:
        await asyncio.to_thread(
            dispatch_webhook, target_url, secret, event["body"]
        )
    except WebhookDeliveryError:
        logger.error(
            "Delivery failed; message kept in SQS",
            extra=context,
            exc_info=True,
        )
        return False
    await asyncio.to_thread(
        delete_event, sqs_client, queue_url, event["receipt_handle"]
    )
    logger.info("Webhook delivered and message deleted", extra=context)
    return True


async def dispatch_loop(
    sqs_client: Any,
    queue_url: str,
    target_url: str,
    secret: str,
    wait_time: int,
    max_batches: int | None = None,
) -> None:
    """Consume SQS with Long Polling and dispatch every event.
    Each batch is processed inside an ``asyncio.TaskGroup``. Delivery
    failures are handled per message; only infrastructure errors (SQS) escape
    as an ``ExceptionGroup``, which ``main`` catches with ``except*``.
    Args:
        sqs_client: Boto3 SQS client.
        queue_url: Queue to consume.
        target_url: Destination webhook URL.
        secret: Shared HMAC secret.
        wait_time: Long Polling seconds (1-20).
        max_batches: Stop after this many batches (``None`` = forever).
    Raises:
        ExceptionGroup: Wrapping ``SQSConnectionError`` or
        ``QueueTimeoutError``.
    """
    batches = 0
    while max_batches is None or batches < max_batches:
        # receive_message bloquea hasta wait_time segundos: va en un thread.
        events = await asyncio.to_thread(
            consume_events, sqs_client, queue_url, wait_time
        )
        async with asyncio.TaskGroup() as group:
            for event in events:
                group.create_task(
                    process_event(
                        sqs_client, queue_url, event, target_url, secret
                    )
                )
        batches += 1
        if events:
            logger.info("Batch finished (%d event(s))", len(events))


# ==========================================================================
# Sub-command runners
# ==========================================================================
async def run_producer(args: argparse.Namespace) -> None:
    """Run the ``produce-sqs`` sub-command.
    Args:
        args: Parsed command line arguments.
    """
    sqs_client = get_sqs_client(args.endpoint_url)
    queue_url, _ = await asyncio.to_thread(
        ensure_queues, sqs_client, args.queue
    )
    trace_id = str(uuid.uuid4())
    message_id = await asyncio.to_thread(
        produce_event,
        sqs_client,
        queue_url,
        args.payload,
        trace_id,
        args.topic,
    )
    print(f"Event published. MessageId={message_id} TraceId={trace_id}")


async def run_dispatcher(args: argparse.Namespace) -> None:
    """Run the ``start-dispatcher`` sub-command.
    Args:
        args: Parsed command line arguments.
    """
    sqs_client = get_sqs_client(args.endpoint_url)
    queue_url, _ = await asyncio.to_thread(
        ensure_queues, sqs_client, args.queue
    )
    logger.info("Dispatcher started (queue=%s)", args.queue)
    await dispatch_loop(
        sqs_client,
        queue_url,
        args.url,
        args.secret,
        args.wait_time,
        args.max_batches,
    )


def run_receiver(args: argparse.Namespace) -> None:
    """Run the ``start-receiver`` sub-command (blocking).
    Args:
        args: Parsed command line arguments.
    """
    import uvicorn  # import tardio: solo se necesita en este subcomando

    # El receptor lee su configuracion del entorno (ver webhook_receiver).
    os.environ["VULCANO_WEBHOOK_SECRET"] = args.secret
    os.environ["VULCANO_QUEUE_NAME"] = args.queue
    os.environ["VULCANO_SQS_ENDPOINT"] = args.endpoint_url
    ensure_queues(get_sqs_client(args.endpoint_url), args.queue)
    from vulcano_telemetry.webhook_receiver import app

    logger.info("Receiver starting on %s:%d", args.host, args.port)
    uvicorn.run(app, host=args.host, port=args.port)


def run_command(args: argparse.Namespace) -> None:
    """Dispatch to the sub-command selected by the user.
    Args:
        args: Parsed command line arguments.
    """
    try:
        if args.command == "produce-sqs":
            asyncio.run(run_producer(args))
        elif args.command == "start-dispatcher":
            asyncio.run(run_dispatcher(args))
        elif args.command == "start-receiver":
            run_receiver(args)
    except KeyboardInterrupt:
        # Ctrl+C no es un error: es la forma normal de detener un servicio.
        logger.info("Interrupted by the user (Ctrl+C)")


# ==========================================================================
# Argument parsing and main
# ==========================================================================
def build_parser() -> argparse.ArgumentParser:
    """Build the ``argparse`` parser with every sanitizer plugged in.
    Returns:
        The configured parser.
    """
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "-q",
        "--queue",
        type=parse_queue_name,
        default=DEFAULT_QUEUE_NAME,
        help="SQS queue name (default: %(default)s)",
    )
    common.add_argument(
        "--endpoint-url",
        type=parse_webhook_url,
        default=os.getenv("VULCANO_SQS_ENDPOINT", DEFAULT_ENDPOINT_URL),
        help="LocalStack URL (default: %(default)s)",
    )
    common.add_argument(
        "--log-file",
        default=DEFAULT_LOG_FILE,
        help="Active JSON log file (default: %(default)s)",
    )

    # El secreto se lee del entorno: lo que va por argumentos queda en el
    # historial de la terminal. argparse tambien valida el valor del entorno.
    secret_args = argparse.ArgumentParser(add_help=False)
    secret_args.add_argument(
        "--secret",
        type=parse_secret_key,
        default=os.getenv("VULCANO_WEBHOOK_SECRET"),
        help="HMAC secret (default: env VULCANO_WEBHOOK_SECRET)",
    )

    parser = argparse.ArgumentParser(
        prog="app_operator",
        description="Vulcano Pay event engine: SQS + signed webhooks.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    produce = subparsers.add_parser(
        "produce-sqs",
        parents=[common],
        help="Publish an event directly to SQS",
    )
    produce.add_argument("--topic", default="payment.completed")
    produce.add_argument(
        "--payload",
        type=parse_json_object,
        default=SAMPLE_PAYLOAD,
        help="JSON object to publish",
    )

    receiver = subparsers.add_parser(
        "start-receiver",
        parents=[common, secret_args],
        help="Start the HTTP webhook receiver",
    )
    receiver.add_argument("--host", default="127.0.0.1")
    receiver.add_argument("--port", type=parse_port, default=8000)

    dispatcher = subparsers.add_parser(
        "start-dispatcher",
        parents=[common, secret_args],
        help="Consume SQS and dispatch signed webhooks",
    )
    dispatcher.add_argument(
        "-w",
        "--wait-time",
        type=parse_wait_time,
        default=10,
        help="Long Polling seconds, 1-20 (default: %(default)s)",
    )
    dispatcher.add_argument(
        "--url",
        type=parse_webhook_url,
        default=DEFAULT_DESTINATION_URL,
        help="Destination webhook URL (default: %(default)s)",
    )
    dispatcher.add_argument(
        "--max-batches",
        type=int,
        default=None,
        help="Stop after N polling batches (default: run forever)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Program entry point.
    Args:
        argv: Command line arguments (defaults to ``sys.argv[1:]``).
    Returns:
        The process exit code.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "produce-sqs" and not args.secret:
        parser.error(
            "the HMAC secret is required: use --secret or set the "
            "VULCANO_WEBHOOK_SECRET environment variable"
        )

    listener = setup_vulcano_logging(args.log_file)
    exit_code = EXIT_OK

    try:
        run_command(args)
    # except* atrapa por tipo DENTRO de un ExceptionGroup. Dentro de un
    # except* no se puede usar return/break/continue, por eso se asigna
    # exit_code y se retorna al final.
    except* WebhookSignatureError as group:
        logger.error(
            "Forged or corrupted signatures: %d",
            len(group.exceptions),
            exc_info=group,
        )
        print("Signature error: see the log for details.", file=sys.stderr)
        exit_code = EXIT_SIGNATURE_ERROR
    except* WebhookTimestampError as group:
        logger.error(
            "Replay attacks or clock drift: %d",
            len(group.exceptions),
            exc_info=group,
        )
        print("Timestamp error: see the log for details.", file=sys.stderr)
        exit_code = EXIT_TIMESTAMP_ERROR
    except* SQSConnectionError as group:
        logger.error(
            "Network failures with SQS/LocalStack: %d",
            len(group.exceptions),
            exc_info=group,
        )
        print(
            "Cannot talk to SQS/LocalStack: is it running?",
            file=sys.stderr,
        )
        exit_code = EXIT_SQS_ERROR
    except* QueueTimeoutError as group:
        logger.error(
            "SQS timeouts: %d", len(group.exceptions), exc_info=group
        )
        print("SQS did not answer in time.", file=sys.stderr)
        exit_code = EXIT_TIMEOUT_ERROR
    except* VulcanoError as group:  # red de seguridad: cualquier otro error
        logger.error(
            "Unexpected domain errors: %d",
            len(group.exceptions),
            exc_info=group,
        )
        print("Domain error: see the log for details.", file=sys.stderr)
        exit_code = EXIT_DOMAIN_ERROR
    finally:
        # Apagado ordenado. PEP 765: aqui NO hay return/break/continue.
        stop_vulcano_logging(listener)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
