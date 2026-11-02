"""Custom exceptions for the Vulcano Pay event engine.
Every exception inherits from :class:`VulcanoError`, which inherits from
``Exception`` (never from ``BaseException``). That way ``except VulcanoError``
catches any domain error without swallowing ``KeyboardInterrupt`` or
``SystemExit``.

The hierarchy has two domains::
VulcanoError

+-- SQSConnectionError      (network / API failure talking to SQS)
+-- QueueTimeoutError       (SQS did not answer in time)
+-- CorruptedMessageError   (SQS message body is not a valid JSON object)
+-- WebhookSignatureError   (HMAC signature missing, malformed or wrong)
+-- WebhookTimestampError   (timestamp outside the tolerance window) 
+-- WebhookDeliveryError    (outgoing HTTP POST failed)

"""


class VulcanoError(Exception):
    """Base class for every error raised by the Vulcano Pay engine."""


# --------------------------------------------------------------------------
# SQS domain
# --------------------------------------------------------------------------


class SQSConnectionError(VulcanoError):
    """Raised when SQS (LocalStack) cannot be reached or rejects a call."""


class QueueTimeoutError(VulcanoError):
    """Raised when a call to SQS exceeds the connect or read timeout."""


class CorruptedMessageError(VulcanoError):
    """Raised when an SQS message body is not a valid JSON object.
    This is how a *poison message* is detected: a message that can never be
    processed, no matter how many times it is retried.
    """

# --------------------------------------------------------------------------
# Webhook domain
# --------------------------------------------------------------------------


class WebhookSignatureError(VulcanoError):
    """Raised when the HMAC-SHA256 signature is missing, malformed or wrong."""


class WebhookTimestampError(VulcanoError):
    """Raised when the signed timestamp is outside the tolerance window.
    A timestamp that is too old (or too far in the future) is the typical
    sign of a replay attack or of a badly desynchronised clock.
    """


class WebhookDeliveryError(VulcanoError):
    """Raised when the outgoing webhook HTTP POST fails after all
      retries."""
