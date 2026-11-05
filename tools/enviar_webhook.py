#!/usr/bin/env python3
"""Send valid or deliberately invalid signed webhooks to the receiver."""

import argparse
import os
import sys
import time
from pathlib import Path

import requests

# Permite ejecutarlo como `python tools/enviar_webhook.py` sin PYTHONPATH.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from vulcano_telemetry.webhook_crypto import (  # noqa: E402
    build_signature_header,
)


DEFAULT_RECEIVER = "http://127.0.0.1:8000/webhook"


def main():
    parser = argparse.ArgumentParser(
        description="Send a signed test webhook to Vulcano Pay."
    )
    parser.add_argument("--url", default=DEFAULT_RECEIVER)
    parser.add_argument(
        "--adulterar",
        action="store_true",
        help="Change the body after calculating its signature.",
    )
    parser.add_argument(
        "--viejo",
        action="store_true",
        help="Use a correctly signed timestamp from one hour ago.",
    )
    args = parser.parse_args()

    secret = os.getenv("VULCANO_WEBHOOK_SECRET")
    if not secret or len(secret) < 16:
        print(
            "[ERROR] VULCANO_WEBHOOK_SECRET must contain at least 16 chars.",
            file=sys.stderr,
        )
        return 2

    signed_body = (
        b'{"id":"evt_demo_001","event_type":"payment.completed",'
        b'"transaction_id":"tx_demo_001","amount":350.0,'
        b'"status":"COMPLETED"}'
    )
    sent_body = signed_body

    timestamp = None
    if args.viejo:
        timestamp = int(time.time()) - 3600

    signature = build_signature_header(
        secret, signed_body, timestamp=timestamp
    )

    if args.adulterar:
        sent_body = signed_body.replace(b'"amount":350.0', b'"amount":9999.0')

    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Signature": signature,
    }

    scenario = (
        "tampered" if args.adulterar else "expired" if args.viejo else "valid"
    )
    expected_status = 202 if scenario == "valid" else 401

    print(f"POST {args.url}")
    print(f"Scenario: {scenario}")

    try:
        response = requests.post(
            args.url,
            data=sent_body,
            headers=headers,
            timeout=5,
        )
        print(f"HTTP status: {response.status_code}")
        print(f"Response:    {response.text}")
        return 0 if response.status_code == expected_status else 1
    except requests.RequestException as error:
        print(f"[ERROR] Could not send webhook: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
