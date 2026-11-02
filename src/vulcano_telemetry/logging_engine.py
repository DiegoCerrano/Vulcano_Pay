"""Non-blocking structured JSON logging with gzip rotation.
Pipeline::
logger.info(...) -> QueueHandler -> queue.Queue (in memory)
QueueListener (secondary thread) <-+
|
|
AsyncJSONFormatter -> RotatingFileHandler (2 MB) -> .log.N.gz
The thread that logs only drops the record into an in-memory queue (a few
microseconds). Formatting and disk I/O happen in the listener thread, so a
slow disk never slows down the HTTP server or the SQS worker.
"""

import gzip
import json
import logging
import logging.handlers
import os
import queue
import re
import shutil
import traceback
from datetime import datetime, timezone

from pathlib import Path
from typing import Any
LOGGER_NAME = "vulcano_engine"
DEFAULT_LOG_FILE = "logs/vulcano_events.log"
DEFAULT_MAX_BYTES = 2 * 1024 * 1024  # 2 MB
DEFAULT_BACKUP_COUNT = 3
MAX_EXCEPTION_DEPTH = 8

# Atributos que ya trae todo LogRecord: lo que NO este aqui vino en "extra".
_STANDARD_ATTRIBUTES = set(
    logging.LogRecord("", 0, "", 0, "", (), None).__dict__
) | {"message", "asctime"}

# Nombre "python" del extra -> nombre del campo en el JSON.
_FIELD_NAMES = {
    "trace_id": "TraceId",
    "message_id": "MessageId",
    "webhook_id": "WebhookId",
    "webhook_signature": "X-Webhook-Signature",
}


def mask_signature(header_value: str) -> str:
    """Shorten the ``v1`` signature so the full value is never logged.
    Args:
    header_value: Raw ``X-Webhook-Signature`` header.
    Returns:
    The header with ``v1`` cut after 12 hex characters, limited to 200
    characters in total (the header is attacker-controlled input).
    """
    masked = re.sub(
        r"(v1=[0-9a-fA-F]{12})[0-9a-fA-F]+", r"\1...", header_value
    )
    return masked[:200]


def serialize_exception(exc: Exception, depth: int = 0) -> dict[str, Any]:
    """Convert an exception (and everything inside it) into a dictionary.
    The conversion is recursive: it follows the explicit cause
    (``raise ... from err``) and, for an ``ExceptionGroup``, every member of
    the group. Notes added with ``add_note()`` are included.
    Args:
    exc: The exception to serialise.
    depth: Current recursion depth (internal use).
    Returns:
    A JSON friendly dictionary.
    """
    data: dict[str, Any] = {
        "type": type(exc).__qualname__,
        "message": str(exc),
        "notes": list(getattr(exc, "__notes__", [])),
        "traceback": traceback.format_tb(exc.__traceback__),
    }

    if depth >= MAX_EXCEPTION_DEPTH:
        return data  # corta recursiones demasiado profundas
    if exc.__cause__ is not None:
        data["cause"] = serialize_exception(exc.__cause__, depth + 1)
    if isinstance(exc, ExceptionGroup):
        data["exceptions"] = [
            serialize_exception(sub, depth + 1) for sub in exc.exceptions
        ]
    return data


class AsyncJSONFormatter(logging.Formatter):
    """
    Format every ``LogRecord`` as one forensic JSON line.
    It is "async" because it runs inside the ``QueueListener`` thread, not
    in the thread that emitted the log.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Translate a log record into a JSON string.
        Args:
        record: The record to format.
        Returns:
        A single-line JSON document.
        """
        log_data: dict[str, Any] = {
            # record.created es el instante REAL del evento (no el de ahora).
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "process": record.process,
            "threadName": record.threadName,
        }

        # Todo lo que llego via extra={...} se agrega al JSON.
        for key, value in record.__dict__.items():
            if key not in _STANDARD_ATTRIBUTES:
                log_data[_FIELD_NAMES.get(key, key)] = value
        if record.exc_info and record.exc_info[1] is not None:
            log_data["exception"] = serialize_exception(record.exc_info[1])
        return json.dumps(log_data, ensure_ascii=False, default=str)


class NonBlockingQueueHandler(logging.handlers.QueueHandler):
    """``QueueHandler`` that keeps the record intact for the listener.
    The stock ``QueueHandler.prepare`` formats the record in the calling
    thread and erases ``exc_info``, which would destroy the exception tree.
    Here the record travels unchanged and is formatted in the listener
    thread by :class:`AsyncJSONFormatter`.
    """

    def prepare(self, record: logging.LogRecord) -> logging.LogRecord:
        """Return the record untouched.
        Args:
        record: The record being enqueued.
        Returns:
        The same record.
        """
        return record


def gzip_namer(default_name: str) -> str:
    """Add the ``.gz`` suffix to rotated file names.
    Args:
    default_name: Name chosen by ``RotatingFileHandler``
    (e.g. ``vulcano_events.log.1``).
    Returns:
    The same name ending in ``.gz``.
    """
    return default_name + ".gz"


def gzip_rotator(source: str, dest: str) -> None:
    """Compress ``source`` into ``dest`` atomically and delete ``source``.

    The data is first written to ``dest + ".tmp"`` and then moved with
    ``os.replace`` (atomic), so a crash never leaves a half written ``.gz``.

    Args:
    source: Path of the full log file.
    dest: Path of the compressed file to create.
    """
    tmp_dest = dest + ".tmp"
    with open(source, "rb") as file_in, gzip.open(tmp_dest, "wb") as file_out:
        shutil.copyfileobj(file_in, file_out)
    os.replace(tmp_dest, dest)
    os.remove(source)


def setup_vulcano_logging(
    log_file: str = DEFAULT_LOG_FILE,
    max_bytes: int = DEFAULT_MAX_BYTES,
    backup_count: int = DEFAULT_BACKUP_COUNT,
    level: int = logging.INFO,
    console: bool = False,
) -> logging.handlers.QueueListener:
    """Configure the non-blocking logging pipeline.
    Calling it twice is safe: the previous queue handler is replaced.
    Args:
    log_file: Path of the active log file.
    max_bytes: Size that triggers a rotation (default 2 MB).
    backup_count: Number of compressed backups to keep (default 3).
    level: Minimum level of the ``vulcano_engine`` logger.
    console: Also print the JSON lines to stderr.
    Returns:
    The started ``QueueListener``. Pass it to
    :func:`stop_vulcano_logging` when the program ends.
    """

    Path(log_file).parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )

    file_handler.setFormatter(AsyncJSONFormatter())
    file_handler.namer = gzip_namer
    file_handler.rotator = gzip_rotator
    handlers: list[logging.Handler] = [file_handler]
    if console:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(AsyncJSONFormatter())
        handlers.append(console_handler)

    log_queue: queue.Queue = queue.Queue(-1)  # sin limite de tamano
    listener = logging.handlers.QueueListener(log_queue, *handlers)
    listener.start()
    logger = logging.getLogger(LOGGER_NAME)
    for old in list(logger.handlers):
        if isinstance(old, logging.handlers.QueueHandler):
            logger.removeHandler(old)
    logger.addHandler(NonBlockingQueueHandler(log_queue))
    logger.setLevel(level)
    logger.propagate = False
    return listener


def stop_vulcano_logging(listener: logging.handlers.QueueListener) -> None:
    """Flush pending records and release the log files.
    Args:
    listener: The listener returned by :func:`setup_vulcano_logging`.
    """
    listener.stop()  # procesa lo que quede en la cola y detiene el hilo
    for handler in listener.handlers:
        handler.close()
