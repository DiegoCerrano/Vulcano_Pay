"""Chaos simulation suite for Vulcano Pay.
It injects the failures a production system eventually suffers: forged
signatures, replayed timestamps, hostile CLI input, a destination that
returns 500, an unreachable SQS and poison messages.
Tests marked ``integration`` need LocalStack running on localhost:4566 and
are skipped automatically when it is not available.
"""
import argparse
import asyncio
import json
import os
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests
from vulcano_telemetry import app_operator

from vulcano_telemetry import (
    SIGNATURE_HEADER,
    SQSConnectionError,
    WebhookDeliveryError,
    WebhookSignatureError,
    WebhookTimestampError,
    build_signature_header,
    consume_events,
    ensure_queues,
    get_sqs_client,
    parse_json_object,
    parse_port,
    parse_queue_name,
    parse_secret_key,
    parse_wait_time,
    parse_webhook_url,
    produce_event,
    verify_signature,
)

SECRET = "chaos-test-secret-0123456789"
BODY = b'{"id":"evt_1","event_type":"payment.completed","amount":10}'


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _free_port() -> int:
    """Return a TCP port that nobody is listening on."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _localstack_up() -> bool:
    """Tell whether LocalStack answers on localhost:4566."""
    try:
        with socket.create_connection(("localhost", 4566), timeout=1):
            return True
    except OSError:
        return False


requires_localstack = pytest.mark.skipif(
    not _localstack_up(), reason="LocalStack is not running on :4566"
)


class _Destination:
    """Tiny HTTP server that records requests and replies scripted statuses."""

    def __init__(self, statuses=(), status_for=None):
        self.statuses = list(statuses)
        self.status_for = status_for  # opcional: status segun el cuerpo
        self.received = []
        outer = self

        class Handler(BaseHTTPRequestHandler):

            def do_POST(self):  # noqa: N802 (nombre impuesto por http.server)
                length = int(self.headers.get("Content-Length", 0))
                outer.received.append(
                    {
                        "body": self.rfile.read(length),
                        "signature": self.headers.get(SIGNATURE_HEADER),
                    }
                )

                body = outer.received[-1]["body"]

                if outer.status_for is not None:
                    status = outer.status_for(body)
                else:
                    status = outer.statuses.pop(0) if outer.statuses else 200

                self.send_response(status)
                self.end_headers()

            def log_message(self, *args):  # silencia el ruido en consola
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/webhook"

        self._thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc_info):
        self.server.shutdown()
        self.server.server_close()


class _FakeSQS:
    """Minimal stand-in for a Boto3 SQS client (no network needed)."""

    def __init__(self, messages):
        self._messages = messages
        self.deleted = []

    def receive_message(self, **kwargs):
        return {"Messages": self._messages}

    def delete_message(self, **kwargs):
        self.deleted.append(kwargs["ReceiptHandle"])


# --------------------------------------------------------------------------
# 1. Cryptographic chaos (pure unit tests)
# --------------------------------------------------------------------------

def _flip_last_char(header: str) -> str:
    """Corrupt the last hex digit of the signature."""
    return header[:-1] + ("0" if header[-1] != "0" else "1")


@pytest.mark.parametrize(
    "header, body, expected",
    [
        pytest.param(
            _flip_last_char(build_signature_header(SECRET, BODY)),
            BODY, WebhookSignatureError, id="tampered-signature",
        ),
        pytest.param(
            build_signature_header(SECRET, BODY), BODY + b" ",
            WebhookSignatureError, id="tampered-body",
        ),
        pytest.param(
            build_signature_header("another-wrong-secret-1234", BODY), BODY,
            WebhookSignatureError, id="wrong-key",
        ),
        pytest.param("", BODY, WebhookSignatureError, id="missing-header"),
        pytest.param(
            "garbage", BODY, WebhookSignatureError,
            id="malformed-header",
        ),
        pytest.param(
            f"t={int(time.time())},v1=firma-con-eñe-é", BODY,
            WebhookSignatureError, id="non-ascii-signature",
        ),
        pytest.param(
            build_signature_header(SECRET, BODY, int(time.time()) - 3600),
            BODY, WebhookTimestampError, id="timestamp-1-hour-old",
        ),
        pytest.param(
            build_signature_header(SECRET, BODY, int(time.time()) + 3600),
            BODY, WebhookTimestampError, id="timestamp-1-hour-ahead",
        ),
    ],
)
def test_verify_signature_rejects_attacks(header, body, expected):
    """Every forged or replayed webhook must raise the right exception."""
    with pytest.raises(expected):
        verify_signature(SECRET, header, body)


def test_verify_signature_accepts_valid_webhook():
    """A correctly signed, fresh webhook is accepted."""
    header = build_signature_header(SECRET, BODY)
    assert verify_signature(SECRET, header, BODY) is True


# --------------------------------------------------------------------------
# 2. Hostile CLI input (sanitizers)
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "parser, bad_value",
    [
        (parse_queue_name, "events-queue"),
        (parse_queue_name, "vulcano-Events-queue"),
        (parse_queue_name, "vulcano-events-queue; rm -rf /"),
        (parse_queue_name, "vulcano--queue"),
        (parse_wait_time, "0"),
        (parse_wait_time, "21"),
        (parse_wait_time, "abc"),
        (parse_webhook_url, "ftp://localhost/webhook"),
        (parse_webhook_url, "localhost:8000/webhook"),
        (parse_webhook_url, "http://"),
        (parse_secret_key, "short"),
        (parse_port, "0"),
        (parse_port, "70000"),
        (parse_json_object, "[1, 2]"),
        (parse_json_object, "{not json"),
    ],
)
def test_sanitizers_reject_hostile_input(parser, bad_value):
    """Invalid CLI values are rejected with ArgumentTypeError."""
    with pytest.raises(argparse.ArgumentTypeError):
        parser(bad_value)


def test_sanitizers_accept_valid_input():
    """Valid values pass through (and are converted to the right type)."""
    assert parse_queue_name("vulcano-events-queue") == "vulcano-events-queue"
    assert parse_wait_time("20") == 20
    assert parse_webhook_url("http://localhost:8000/webhook")
    assert parse_secret_key("x" * 16) == "x" * 16
    assert parse_json_object('{"a": 1}') == {"a": 1}


# --------------------------------------------------------------------------
# 3. HTTP receiver chaos (real FastAPI server, no LocalStack needed because
# every attack is rejected BEFORE anything is sent to SQS)
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def receiver_url():
    """Start the real FastAPI receiver on a free port for this module."""
    import uvicorn

    from vulcano_telemetry.webhook_receiver import app

    previous = os.environ.get("VULCANO_WEBHOOK_SECRET")
    os.environ["VULCANO_WEBHOOK_SECRET"] = SECRET

    port = _free_port()

    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    )

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.time() + 10

    while not server.started and time.time() < deadline:
        time.sleep(0.05)

    assert server.started, "uvicorn did not start"

    yield f"http://127.0.0.1:{port}/webhook"

    server.should_exit = True
    thread.join(timeout=5)

    if previous is None:
        del os.environ["VULCANO_WEBHOOK_SECRET"]
    else:
        os.environ["VULCANO_WEBHOOK_SECRET"] = previous


def _post(url, body, header=None):
    """POST raw bytes with an optional signature header."""
    headers = {"Content-Type": "application/json"}

    if header is not None:
        headers[SIGNATURE_HEADER] = header

    return requests.post(url, data=body, headers=headers, timeout=5)


def test_receiver_rejects_tampered_signature(receiver_url):
    header = _flip_last_char(build_signature_header(SECRET, BODY))
    assert _post(receiver_url, BODY, header).status_code == 401


def test_receiver_rejects_tampered_body(receiver_url):
    header = build_signature_header(SECRET, BODY)
    assert _post(receiver_url, BODY + b" ", header).status_code == 401


def test_receiver_rejects_wrong_key(receiver_url):
    header = build_signature_header("another-wrong-secret-1234", BODY)
    assert _post(receiver_url, BODY, header).status_code == 401


def test_receiver_rejects_missing_header(receiver_url):
    assert _post(receiver_url, BODY).status_code == 401


def test_receiver_rejects_replayed_timestamp(receiver_url):
    header = build_signature_header(SECRET, BODY, int(time.time()) - 3600)
    response = _post(receiver_url, BODY, header)

    assert response.status_code == 401
    assert "Timestamp" in response.json()["detail"]


# --------------------------------------------------------------------------
# 4. Dispatcher chaos (destination returning errors)
# --------------------------------------------------------------------------

def test_dispatch_signs_the_exact_bytes_it_sends():
    with _Destination([200]) as destination:
        app_operator.dispatch_webhook(
            destination.url, SECRET, {"amount": 10}, retry_delays=(0, 0)
        )

    request = destination.received[0]

    assert verify_signature(SECRET, request["signature"], request["body"])
    assert json.loads(request["body"]) == {"amount": 10}


def test_dispatch_retries_and_then_fails_on_500():
    with _Destination([500, 500, 500]) as destination:
        with pytest.raises(WebhookDeliveryError) as info:
            app_operator.dispatch_webhook(
                destination.url, SECRET, {"a": 1}, retry_delays=(0, 0)
            )

    assert len(destination.received) == 3  # 1 intento + 2 reintentos
    assert isinstance(info.value.__cause__, requests.HTTPError)
    assert any("Destination" in note for note in info.value.__notes__)


def test_dispatch_recovers_after_a_transient_failure():
    with _Destination([503, 200]) as destination:
        app_operator.dispatch_webhook(
            destination.url, SECRET, {"a": 1}, retry_delays=(0, 0)
        )

    assert len(destination.received) == 2


def test_dispatch_does_not_retry_a_404():
    with _Destination([404]) as destination:
        with pytest.raises(WebhookDeliveryError):
            app_operator.dispatch_webhook(
                destination.url, SECRET, {"a": 1}, retry_delays=(0, 0)
            )

    assert len(destination.received) == 1


def test_dispatch_to_a_dead_server():
    url = f"http://127.0.0.1:{_free_port()}/webhook"

    with pytest.raises(WebhookDeliveryError):
        app_operator.dispatch_webhook(
            url, SECRET, {"a": 1}, retry_delays=(0, 0)
        )


def test_dispatch_loop_deletes_only_delivered_events():
    """A failing destination must leave its message in SQS (-> DLQ)."""

    def message(name):
        return {
            "MessageId": f"m-{name}",
            "ReceiptHandle": f"r-{name}",
            "Body": json.dumps({"id": name}),
            "MessageAttributes": {
                "TraceId": {"StringValue": f"t-{name}"}
            },
        }

    fake = _FakeSQS([message("ok"), message("bad")])

    with _Destination(
        status_for=lambda body: 500 if b'"bad"' in body else 200
    ) as destination:
        asyncio.run(
            app_operator.dispatch_loop(
                fake, "queue-url", destination.url, SECRET,
                wait_time=1, max_batches=1,
            )
        )

    assert fake.deleted == ["r-ok"]  # el fallido NO se borra


# --------------------------------------------------------------------------
# 5. SQS chaos
# --------------------------------------------------------------------------

def test_poison_messages_are_skipped_and_never_deleted():
    """A broken message must not block the healthy ones in the same batch."""
    good = {
        "MessageId": "m-good",
        "ReceiptHandle": "r-good",
        "Body": '{"amount": 10}',
        "MessageAttributes": {"TraceId": {"StringValue": "t-1"}},
    }

    poison = {
        "MessageId": "m-bad",
        "ReceiptHandle": "r-bad",
        "Body": "{{ not json",
    }

    not_an_object = {
        "MessageId": "m-list",
        "ReceiptHandle": "r-list",
        "Body": "[1, 2, 3]",
    }

    fake = _FakeSQS([poison, good, not_an_object])

    events = consume_events(fake, "queue-url", wait_time=1)

    assert [event["message_id"] for event in events] == ["m-good"]
    assert events[0]["trace_id"] == "t-1"
    assert fake.deleted == []  # sin delete => SQS lo reintentara y a la DLQ


def test_unreachable_sqs_raises_sqs_connection_error():
    """boto3 raises BotoCoreError (not ClientError) when nobody listens."""
    client = get_sqs_client(f"http://127.0.0.1:{_free_port()}")

    with pytest.raises(SQSConnectionError) as info:
        ensure_queues(client)

    assert info.value.__cause__ is not None  # raise ... from err
    assert any("Target" in note for note in info.value.__notes__)


def test_cli_translates_sqs_failure_into_exit_code(tmp_path):
    """``except*`` in main() maps SQSConnectionError to its exit code."""
    code = app_operator.main(
        [
            "produce-sqs",
            "--endpoint-url", f"http://127.0.0.1:{_free_port()}",
            "--log-file", str(tmp_path / "vulcano_events.log"),
        ]
    )

    assert code == app_operator.EXIT_SQS_ERROR


@pytest.mark.integration
@requires_localstack
def test_roundtrip_produce_consume_delete():
    """Happy path with the real LocalStack."""
    sqs = get_sqs_client("http://localhost:4566")
    name = f"vulcano-chaos-{uuid.uuid4().hex[:8]}-queue"

    queue_url, dlq_url = ensure_queues(sqs, name, visibility_timeout=5)

    try:
        produce_event(sqs, queue_url, {"amount": 5}, "trace-rt", "t.topic")
        events = consume_events(sqs, queue_url, wait_time=3)

        assert events[0]["body"] == {"amount": 5}
        assert events[0]["trace_id"] == "trace-rt"

    finally:
        sqs.delete_queue(QueueUrl=queue_url)
        sqs.delete_queue(QueueUrl=dlq_url)


@pytest.mark.integration
@requires_localstack
def test_poison_message_ends_in_the_dlq():
    """A message that can never be processed is moved to the DLQ by SQS."""
    sqs = get_sqs_client("http://localhost:4566")
    name = f"vulcano-chaos-{uuid.uuid4().hex[:8]}-queue"

    queue_url, dlq_url = ensure_queues(
        sqs, name, max_receive_count=2, visibility_timeout=1
    )

    poison_body = "{{ this is not json"

    try:
        sqs.send_message(QueueUrl=queue_url, MessageBody=poison_body)
        found = None
        deadline = time.time() + 40

        while found is None and time.time() < deadline:
            # consume_events salta el veneno SIN borrarlo: cada lectura suma
            # una recepcion hasta superar maxReceiveCount.
            consume_events(sqs, queue_url, wait_time=1)

            messages = sqs.receive_message(
                QueueUrl=dlq_url, WaitTimeSeconds=1
            ).get("Messages", [])

            if messages:
                found = messages[0]["Body"]

        assert found == poison_body

    finally:
        sqs.delete_queue(QueueUrl=queue_url)
        sqs.delete_queue(QueueUrl=dlq_url)
