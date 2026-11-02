"""Forensic validation of the JSON log pipeline.

These tests write real logs through ``setup_vulcano_logging`` (with a tiny
``max_bytes`` to force rotation), then open the ``.log.N.gz`` files and check
their content.
"""

import gzip
import json
import logging
import logging.handlers
from datetime import datetime, timedelta

import pytest

from vulcano_telemetry import (
    SQSConnectionError,
    WebhookSignatureError,
    build_signature_header,
    setup_vulcano_logging,
    stop_vulcano_logging,
)
from vulcano_telemetry.logging_engine import mask_signature


SECRET = "forensic-test-secret-0123456789"
LOGGER_NAME = "vulcano_engine"


@pytest.fixture(autouse=True)
def _clean_logger():
    """Detach the pipeline from the shared logger after every test."""
    yield

    logger = logging.getLogger(LOGGER_NAME)

    for handler in list(logger.handlers):
        logger.removeHandler(handler)


def _read_all_records(directory):
    """Read every JSON line from the active log and from every ``.gz``."""
    lines = []

    for path in sorted(directory.glob("vulcano_events.log*")):
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as compressed:
                lines.extend(compressed.read().splitlines())
        else:
            lines.extend(path.read_text(encoding="utf-8").splitlines())

    return [json.loads(line) for line in lines if line.strip()]


def _write_webhook_logs(directory, total, **setup_options):
    """Emit ``total`` realistic log lines and flush the pipeline."""
    listener = setup_vulcano_logging(
        str(directory / "vulcano_events.log"), **setup_options
    )

    logger = logging.getLogger(LOGGER_NAME)
    header = build_signature_header(SECRET, b'{"amount":10}')

    for index in range(total):
        logger.info(
            "Webhook verified and enqueued",
            extra={
                "trace_id": f"trace-{index}",
                "message_id": f"msg-{index}",
                "webhook_id": f"evt-{index}",
                "webhook_signature": mask_signature(header),
            },
        )

    stop_vulcano_logging(listener)

    return header


def test_rotation_creates_gzip_files_without_losing_records(tmp_path):
    total = 40

    _write_webhook_logs(
        tmp_path,
        total,
        max_bytes=1500,
        backup_count=30,
    )

    gz_files = list(tmp_path.glob("vulcano_events.log.*.gz"))

    assert gz_files, "rotation should have produced .gz backups"
    assert not list(tmp_path.glob("*.tmp")), "no half-written files"

    records = _read_all_records(tmp_path)

    assert len(records) == total  # descompresion sin perdida de datos
    assert {r["TraceId"] for r in records} == {
        f"trace-{i}" for i in range(total)
    }


def test_every_record_has_the_forensic_fields(tmp_path):
    header = _write_webhook_logs(tmp_path, 5)

    for record in _read_all_records(tmp_path):
        for field in (
            "TraceId",
            "MessageId",
            "WebhookId",
            "X-Webhook-Signature",
            "process",
            "threadName",
            "level",
            "message",
            "timestamp",
        ):
            assert field in record, f"missing {field}"

    # La firma completa (64 hex) NUNCA se escribe en el log.
    full_signature = header.split("v1=")[1]

    log_text = (
        tmp_path / "vulcano_events.log"
    ).read_text(encoding="utf-8")

    assert full_signature not in log_text


def test_timestamps_are_strict_iso8601_utc(tmp_path):
    _write_webhook_logs(tmp_path, 5)

    for record in _read_all_records(tmp_path):
        assert record["timestamp"].endswith("+00:00")

        parsed = datetime.fromisoformat(record["timestamp"])

        assert parsed.utcoffset() == timedelta(0)


def test_exception_group_is_serialised_recursively(tmp_path):
    listener = setup_vulcano_logging(
        str(tmp_path / "vulcano_events.log")
    )

    logger = logging.getLogger(LOGGER_NAME)

    sqs_error = SQSConnectionError("sqs down")
    sqs_error.add_note("Target: vulcano-events-queue")

    try:
        try:
            raise ConnectionRefusedError("connection refused")
        except ConnectionRefusedError as err:
            raise sqs_error from err

    except SQSConnectionError as chained:
        group = ExceptionGroup(
            "batch failed",
            [
                chained,
                WebhookSignatureError("bad signature"),
            ],
        )

        try:
            raise group
        except ExceptionGroup:
            logger.error("batch failed", exc_info=True)

    stop_vulcano_logging(listener)

    record = _read_all_records(tmp_path)[0]
    exception = record["exception"]

    assert exception["type"] == "ExceptionGroup"
    assert len(exception["exceptions"]) == 2

    first, second = exception["exceptions"]

    assert first["type"] == "SQSConnectionError"
    assert first["notes"] == ["Target: vulcano-events-queue"]
    assert first["cause"]["type"] == "ConnectionRefusedError"

    assert second["type"] == "WebhookSignatureError"
    assert isinstance(exception["traceback"], list)


def test_logging_goes_only_through_queue_handler(tmp_path):
    """Evaluation criterion: disk I/O only via QueueHandler/QueueListener."""
    listener = setup_vulcano_logging(
        str(tmp_path / "vulcano_events.log")
    )

    logger = logging.getLogger(LOGGER_NAME)

    try:
        # Exclude handlers injected by pytest for log capture.
        application_handlers = [
            handler
            for handler in logger.handlers
            if type(handler).__module__ != "_pytest.logging"
        ]

        assert application_handlers

        assert all(
            isinstance(handler, logging.handlers.QueueHandler)
            for handler in application_handlers
        )

    finally:
        assert isinstance(listener, logging.handlers.QueueListener)
        stop_vulcano_logging(listener)


def test_mask_signature_shortens_and_limits_input():
    header = "t=1700000000,v1=" + "ab" * 32

    assert mask_signature(header) == "t=1700000000,v1=abababababab..."
    assert len(mask_signature("x" * 5000)) == 200
