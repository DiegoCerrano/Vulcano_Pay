"""HMAC-SHA256 signing and verification for webhooks.
Signature scheme (similar to the one used by Stripe)::
X-Webhook-Signature: t=<unix timestamp>,v1=<hex HMAC-SHA256>
The HMAC is computed over ``"<timestamp>." + raw_body_bytes`` using a secret
shared by both sides. Putting the timestamp *inside* the signed text means an
attacker cannot change it without invalidating the signature, which is what
makes the replay protection work.
"""


import hashlib
import hmac
import time

from .exceptions import WebhookSignatureError, WebhookTimestampError

SIGNATURE_HEADER = "X-Webhook-Signature"
DEFAULT_TOLERANCE_SECONDS = 300


def generate_signature(
        secret: str, timestamp: int, payload_bytes: bytes
) -> str:
    """Compute the HMAC-SHA256 signature of a Webhook.

    Args:
        secret: Sharet secret key.
        timestamp: Unix timestamp seconds that will travel in the header.
        payload_bytes: Exact bytes of the HTTP body.

    Returns:
        The signature encoded as a lowercase hexadecimal string.

    """

    to_sign = f"{timestamp}.".encode("utf-8") + payload_bytes
    return hmac.new(
        secret.encode("utf-8"), to_sign, hashlib.sha256
    ).hexdigest()


def build_signature_header(
        secret: str, payload_bytes: bytes, timestamp:
    int | None = None
) -> str:
    """
    Build the value of the "X-Webhook-Signature" header.

    Args:
        secret: Shared secret key.
        payload_bytes: Exact bytes of the HTTP body that will be sent.
        timestamp: Unix timestamp to sign. Defaults to "now".

    Returns:
        A string like ''"t=1700000000,v=ab12...''.
    """

    if timestamp is None:
        timestamp = int(time.time())

    signature = generate_signature(secret, timestamp, payload_bytes)
    return f"t={timestamp},v1={signature}"


def parse_signature_header(header_value: str) -> tuple[int, str]:
    """
    Extract 't' and 'v1' from an "X-Webhook-Signature" header.

    Args: 
        header_value: Raw header, e.g. "t=1700000,v1=ab12..."

    Returns:
        A tuple ''(timestamp, signature)''.

    Raises:
        WebhookSignatureError: If the header is empty or malformed.
    """

    if not header_value:
        raise WebhookSignatureError(f"Missing {SIGNATURE_HEADER} header.")
    try:
        parts = dict(
            item.strip().split("=", 1) for item in header_value.split(",")
        )
        return int(parts["t"]), parts["v1"]
    except (ValueError, KeyError) as err:
        raise WebhookSignatureError(
            f"Malformed {SIGNATURE_HEADER} header."
        ) from err


def verify_signature(
        secret: str,
        header_value: str,
        payload_bytes: bytes,
        tolerance_sec: int = DEFAULT_TOLERANCE_SECONDS,
) -> bool:
    """
    Verfiy an uncoming webhook signature.

    Two attacks are mitigated here.

    * **Replay attacks**: the timestamp must be within 
    ''tolerance_sec'' of the current time.
    * **Timig attacks**: the comparision uses ''hmac.compare_digest'',
    which takes the same time no matter where the two strings differ.

    Args:
        secret: Shared secret key.
        header_value: Raw "X-Webhook-Signature" header.
        payload_bytes: Exact bytes of the HTTP body (the *raw body*
            before any JSON parsing.)
        tolerance_sec: Maximum allowed clock difference in seconds.

    Returns:
        "True" when the signature is valid (it never returns False: any
        problem is reported with an exception.).

    Raises:
        WebhookSignatureError: Header missing/malformed or signature wrong.
        WebhookTimestampError: Timestamp outside the tolerance window.
    """

    timestamp, received_signature = parse_signature_header(header_value)

    # 1) Anti-Replay

    difference = abs(int(time.time()) - timestamp)

    if difference > tolerance_sec:
        raise WebhookTimestampError(
            f"Timestamp outside tolerance ({difference}s > {tolerance_sec}s)"
        )

    # 2) Anti-Timing

    expected_signature = generate_signature(secret, timestamp, payload_bytes)

    if not hmac.compare_digest(
        expected_signature.encode("utf-8"),
        received_signature.encode("utf-8"),
    ):
        raise WebhookSignatureError("HMAC-SHA256 signature does not match.")

    return True
