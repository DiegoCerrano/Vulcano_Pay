"""Declarative CLI validators (``type=`` callables for ``argparse``).
Each ``parse_*`` function receives the raw string typed by the user and
either returns the clean, correctly typed value or raises
``argparse.ArgumentTypeError``. argparse turns that error into a friendly
usage message, so invalid input is rejected before any business logic runs.
"""
import argparse
import json
import re
from typing import Any
from urllib.parse import urlparse

QUEUE_NAME_PATTERN = re.compile(r"vulcano-[a-z0-9-]+-queue")
MIN_WAIT_TIME = 1
MAX_WAIT_TIME = 20
MIN_SECRET_LENGTH = 16


def parse_queue_name(value: str) -> str:
    """Validate an SQS queue name against ``vulcano-<name>-queue``.

    Args:
        value: Raw queue name received from the command line.

    Returns:
        The same queue name, once validated.

    Raises:
        argparse.ArgumentTypeError: If the name does not match the pattern.
    """

    if not QUEUE_NAME_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError(
            f"Invalid queue name '{value}'. "
            "It must follow 'vulcano-<name>-queue' "
            "(lowercase letters, digits and hyphens)."
        )
    return value


def parse_wait_time(value: str) -> int:
    """Validate the Long Polling wait time (``WaitTimeSeconds``).

    Args:
        value: Raw number of seconds received from the command line.

    Returns:
        The wait time as an integer between 1 and 20.

    Raises:
        argparse.ArgumentTypeError: If it is not an integer in [1, 20].
    """
    try:
        seconds = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid wait time '{value}'. It must be an integer."
        ) from None

    if not MIN_WAIT_TIME <= seconds <= MAX_WAIT_TIME:
        raise argparse.ArgumentTypeError(
            f"Invalid wait time {seconds}. "
            f"It must be between {MIN_WAIT_TIME} and {MAX_WAIT_TIME} seconds."
        )
    return seconds


def parse_webhook_url(value: str) -> str:
    """Validate that a URL is an absolute HTTP or HTTPS URL.

    Args:
        value: Raw URL received from the command line.

    Returns:
        The same URL, once validated.

    Raises:
        argparse.ArgumentTypeError: If the scheme is not http/https or the
        host is missing.
    """
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise argparse.ArgumentTypeError(
            f"Invalid URL '{value}'. Expected something like "
            "'http://localhost:8000/webhook'."
        )
    return value


def parse_secret_key(value: str) -> str:
    """Validate the minimum length of the HMAC secret key.

    Args:
        value: Raw secret received from the command line or environment.

    Returns:
        The same secret, once validated.

    Raises:
        argparse.ArgumentTypeError: If it has fewer than 16 characters.
    """
    if len(value) < MIN_SECRET_LENGTH:
        raise argparse.ArgumentTypeError(
            f"The HMAC secret must have at least {MIN_SECRET_LENGTH} "
            "characters."
        )

    return value

# --- Extra validators (not required by the assignment, used by the CLI) ---


def parse_port(value: str) -> int:
    """Validate a TCP port number.

    Args:
        value: Raw port received from the command line.

    Returns:
        The port as an integer between 1 and 65535.

    Raises:
        argparse.ArgumentTypeError: If it is not an integer in [1, 65535].
    """

    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid port '{value}'. It must be an integer."
        ) from None

    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(
            f"Invalid port {port}. It must be between 1 and 65535."
        )
    return port


def parse_json_object(value: str) -> dict[str, Any]:
    """Validate that a string is a JSON *object* (not a list or a scalar).

    Args:
        value: Raw JSON text received from the command line.

    Returns:
        The decoded dictionary.

    Raises:
        argparse.ArgumentTypeError: If it is not valid JSON or not an object.
    """
    try:
        data = json.loads(value)
    except json.JSONDecodeError as err:
        raise argparse.ArgumentTypeError(
            f"Invalid JSON payload: {err}."
        ) from None

    if not isinstance(data, dict):
        raise argparse.ArgumentTypeError(
            "The payload must be a JSON object, e.g. '{\"amount\": 10}'."
        )
    return data
