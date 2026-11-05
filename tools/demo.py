#!/usr/bin/env python3
"""Run an end-to-end Vulcano Pay demonstration.

Start LocalStack separately, export VULCANO_WEBHOOK_SECRET, then run:
    python tools/demo.py

The script starts the demo destination, the FastAPI receiver and the
SQS dispatcher, then sends one valid, one tampered and one expired webhook.
Press Enter or Ctrl+C to stop the background services.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import requests


ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"

# app_operator vive en src/ (consigna); si alguien lo dejo dentro del
# paquete, se ejecuta como modulo.
OPERATOR_SCRIPT = ROOT / "src" / "app_operator.py"
if OPERATOR_SCRIPT.exists():
    OPERATOR = [sys.executable, str(OPERATOR_SCRIPT)]
else:
    OPERATOR = [sys.executable, "-m", "vulcano_telemetry.app_operator"]
DESTINATION_URL = "http://127.0.0.1:9000/webhook"
RECEIVER_URL = "http://127.0.0.1:8000"
LOCALSTACK_HEALTH_URL = "http://localhost:4566/_localstack/health"


def wait_for_http(url: str, process: subprocess.Popen, label: str,
                  timeout: int = 20) -> bool:
    """Wait until an HTTP endpoint responds or its process exits."""
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if process.poll() is not None:
            print(f"[ERROR] {label} stopped unexpectedly.")
            return False

        try:
            response = requests.get(url, timeout=1)
            if response.ok:
                print(f"[OK] {label} is ready.")
                return True
        except requests.RequestException:
            pass

        time.sleep(0.5)

    print(f"[ERROR] Timed out waiting for {label}: {url}")
    return False


def stop_processes(processes: list[subprocess.Popen]) -> None:
    """Stop child processes in reverse startup order."""
    for process in reversed(processes):
        if process.poll() is None:
            process.terminate()

    for process in reversed(processes):
        if process.poll() is None:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def run_webhook(label: str, env: dict[str, str], *arguments: str) -> None:
    """Run one webhook scenario and show its HTTP result."""
    print(f"\n{'=' * 64}\n{label}\n{'=' * 64}")
    subprocess.run(
        [sys.executable, str(TOOLS / "enviar_webhook.py"), *arguments],
        cwd=ROOT,
        env=env,
        check=False,
    )


def main() -> int:
    print("\n" + "=" * 64)
    print("                 VULCANO PAY - LIVE DEMO")
    print("=" * 64)

    secret = os.getenv("VULCANO_WEBHOOK_SECRET", "")
    if len(secret) < 16:
        print(
            "\n[ERROR] Define VULCANO_WEBHOOK_SECRET with at least "
            "16 characters before running the demo."
        )
        print('Example: export VULCANO_WEBHOOK_SECRET="demo_secret_123456"')
        return 2

    try:
        response = requests.get(LOCALSTACK_HEALTH_URL, timeout=2)
        response.raise_for_status()
    except requests.RequestException:
        print("\n[ERROR] LocalStack is not responding on localhost:4566.")
        print("Start it first:")
        print("docker run --rm -p 4566:4566 localstack/localstack")
        return 3

    print("[OK] LocalStack is responding.")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get(
        "PYTHONPATH", ""
    )
    env.setdefault("VULCANO_QUEUE_NAME", "vulcano-events-queue")
    env.setdefault("VULCANO_SQS_ENDPOINT", "http://localhost:4566")

    log_dir = ROOT / "logs" / (
        "demo_" + datetime.now().strftime("%Y%m%d_%H%M%S")
    )
    log_dir.mkdir(parents=True, exist_ok=True)

    processes: list[subprocess.Popen] = []

    try:
        print("\n[1/3] Starting the demo destination...")
        destination = subprocess.Popen(
            [sys.executable, str(TOOLS / "destino_demo.py")],
            cwd=ROOT,
            env=env,
        )
        processes.append(destination)

        if not wait_for_http(
            "http://127.0.0.1:9000/health", destination, "Demo destination"
        ):
            return 4

        print("\n[2/3] Starting the FastAPI receiver...")
        receiver = subprocess.Popen(
            [
                *OPERATOR,
                "start-receiver",
                "--host", "127.0.0.1",
                "--port", "8000",
                "--log-file", str(log_dir / "receiver.log"),
            ],
            cwd=ROOT,
            env=env,
        )
        processes.append(receiver)

        if not wait_for_http(
            RECEIVER_URL + "/openapi.json", receiver, "FastAPI receiver"
        ):
            return 5

        print("\n[3/3] Starting the SQS dispatcher...")
        dispatcher = subprocess.Popen(
            [
                *OPERATOR,
                "start-dispatcher",
                "--url", DESTINATION_URL,
                "--wait-time", "2",
                "--log-file", str(log_dir / "dispatcher.log"),
            ],
            cwd=ROOT,
            env=env,
        )
        processes.append(dispatcher)
        time.sleep(2)

        if dispatcher.poll() is not None:
            print("[ERROR] Dispatcher stopped during startup.")
            return 6

        print("\nServices are running.")
        print(f"Receiver:    {RECEIVER_URL}/webhook")
        print(f"Destination: {DESTINATION_URL}")
        print(f"Logs:        {log_dir.relative_to(ROOT)}")

        # Scenario 1: valid signature. Expected result: HTTP 202 and delivery.
        run_webhook(
            "SCENARIO 1 - VALID WEBHOOK (expected HTTP 202)",
            env,
        )
        time.sleep(2)

        # Scenario 2: body is changed after signing. Expected result: HTTP 401.
        run_webhook(
            "SCENARIO 2 - TAMPERED BODY (expected HTTP 401)",
            env,
            "--adulterar",
        )

        # Scenario 3: correct signature but expired timestamp (HTTP 401).
        run_webhook(
            "SCENARIO 3 - EXPIRED TIMESTAMP (expected HTTP 401)",
            env,
            "--viejo",
        )

        print("\n" + "=" * 64)
        print("DEMO FINISHED")
        print("Expected: 202 for the valid webhook; 401 for both attacks.")
        print("The valid event should appear in the destination terminal.")
        print(f"Receiver log:    {log_dir / 'receiver.log'}")
        print(f"Dispatcher log:  {log_dir / 'dispatcher.log'}")
        print("\nPress Enter to stop the demo services.")
        input()

        return 0

    except KeyboardInterrupt:
        print("\n[DEMO] Interrupted.")
        return 130
    finally:
        print("\n[DEMO] Stopping receiver, dispatcher and destination...")
        stop_processes(processes)
        print("[DEMO] All demo processes stopped.")


if __name__ == "__main__":
    raise SystemExit(main())
