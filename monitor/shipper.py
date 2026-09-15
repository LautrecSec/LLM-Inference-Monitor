#!/usr/bin/env python3
"""Redact LLM inference logs, compute security indicators, and emit Sentinel-ready events.

Reads JSONL records (one inference per line), produces events for the custom stream
Custom-LLMInference_CL, and either prints them (default) or ships them to the Azure
Monitor Logs Ingestion API (--ship).

Environment variables (only needed with --ship):
    AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET   service principal
    DCE_ENDPOINT        https://<dce>.<region>.ingest.monitor.azure.com
    DCR_IMMUTABLE_ID    dcr-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    USER_HASH_SALT      per-deployment salt for hashing user identifiers (optional)

Example:
    python monitor/shipper.py samples/events.jsonl --allowed-tools lookup_order,create_ticket
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import statistics
import sys
import time
from collections import deque
from pathlib import Path
from typing import Any, Iterator

import requests

STREAM_NAME = "Custom-LLMInference_CL"
API_VERSION = "2023-01-01"
RETRY_STATUSES = {429, 500, 502, 503, 504}

# Order matters: secret-shaped tokens are replaced before the broader numeric patterns
# so that a key containing digit runs is not partially rewritten as a phone number.
REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(?:sk|AKIA|ghp|xox[bap])[-_A-Za-z0-9]{16,}\b"), "<key>"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "<jwt>"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "<email>"),
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "<card-or-id>"),
    (re.compile(r"\+?\d{1,3}[ -.]?\(?\d{2,4}\)?[ -.]?\d{3,4}[ -.]?\d{3,4}\b"), "<phone>"),
]
SECRET_LIKE = re.compile(r"(?:sk|AKIA|ghp|xox[bap])[-_A-Za-z0-9]{16,}|eyJ[A-Za-z0-9_-]{10,}\.|-----BEGIN [A-Z ]*PRIVATE KEY-----")
INJECTION_MARKERS = [
    "ignore all previous instructions", "ignore the above", "disregard your instructions",
    "you are now", "system override", "developer mode", "reveal your system prompt",
    "repeat everything above", "print your instructions", "do anything now",
    "note to ai", "as an ai you must", "exfiltrate", "base64 encode your",
]


def sha256(value: str, salt: str = "") -> str:
    """Hex SHA-256 of salt + value."""
    return hashlib.sha256((salt + value).encode("utf-8")).hexdigest()


def redact(text: str, limit: int) -> str:
    """Apply redaction patterns and truncate to a bounded excerpt."""
    for pattern, replacement in REDACTIONS:
        text = pattern.sub(replacement, text)
    return text[:limit]


class TokenBaseline:
    """Rolling median baseline for completion tokens per model."""

    def __init__(self, window: int, multiplier: float) -> None:
        self.window = window
        self.multiplier = multiplier
        self.history: dict[str, deque[int]] = {}

    def is_spike(self, model: str, tokens: int | None) -> bool:
        if tokens is None:
            return False
        hist = self.history.setdefault(model, deque(maxlen=self.window))
        spike = len(hist) >= 5 and tokens > statistics.median(hist) * self.multiplier
        hist.append(tokens)
        return spike


def build_event(rec: dict[str, Any], allowed_tools: set[str], max_tools: int, baseline: TokenBaseline,
                salt: str, excerpt: int) -> dict[str, Any]:
    """Convert one raw inference record into a redacted, enriched event."""
    prompt = str(rec.get("prompt", ""))
    response = str(rec.get("response", ""))
    tools = [str(t) for t in rec.get("tool_calls", []) or []]
    lowered = prompt.lower()
    markers = [m for m in INJECTION_MARKERS if m in lowered]
    model = str(rec.get("model", "unknown"))
    completion_tokens = rec.get("completion_tokens")
    return {
        "TimeGenerated": rec.get("timestamp"),
        "RequestId": rec.get("request_id"),
        "App": rec.get("app"),
        "UserHash": sha256(str(rec.get("user", "")), salt) if rec.get("user") else None,
        "Model": model,
        "PromptHash": sha256(prompt),
        "PromptExcerpt": redact(prompt, excerpt),
        "ResponseHash": sha256(response),
        "ResponseExcerpt": redact(response, excerpt),
        "PromptTokens": rec.get("prompt_tokens"),
        "CompletionTokens": completion_tokens,
        "LatencyMs": rec.get("latency_ms"),
        "ToolCalls": tools,
        "ToolCallAnomaly": bool((allowed_tools and any(t not in allowed_tools for t in tools)) or len(tools) > max_tools),
        "InjectionMarkers": markers,
        "InjectionScore": len(markers),
        "SecretLikeOutput": bool(SECRET_LIKE.search(response)),
        "TokenSpike": baseline.is_spike(model, completion_tokens),
        "ClientIp": rec.get("client_ip"),
    }


def read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    """Yield parsed objects from a JSONL file, skipping blank and malformed lines with a warning."""
    with path.open(encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"warning: line {n} skipped ({exc})", file=sys.stderr)
                continue
            if isinstance(obj, dict):
                yield obj


class LogsIngestionClient:
    """Minimal Azure Monitor Logs Ingestion API client using client credentials."""

    def __init__(self, timeout: float, max_retries: int) -> None:
        required = ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "DCE_ENDPOINT", "DCR_IMMUTABLE_ID")
        missing = [k for k in required if not os.environ.get(k)]
        if missing:
            raise SystemExit(f"missing environment variables: {', '.join(missing)}")
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        self.url = (f"{os.environ['DCE_ENDPOINT'].rstrip('/')}/dataCollectionRules/{os.environ['DCR_IMMUTABLE_ID']}"
                    f"/streams/{STREAM_NAME}?api-version={API_VERSION}")
        self.session.headers.update({"Authorization": f"Bearer {self._token()}", "Content-Type": "application/json"})

    def _token(self) -> str:
        resp = self.session.post(
            f"https://login.microsoftonline.com/{os.environ['AZURE_TENANT_ID']}/oauth2/v2.0/token",
            data={"grant_type": "client_credentials", "client_id": os.environ["AZURE_CLIENT_ID"],
                  "client_secret": os.environ["AZURE_CLIENT_SECRET"], "scope": "https://monitor.azure.com/.default"},
            timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()["access_token"]

    def send(self, events: list[dict[str, Any]]) -> None:
        """POST a batch of events with bounded retries; raises on final failure."""
        delay = 1.0
        for attempt in range(self.max_retries + 1):
            resp = self.session.post(self.url, json=events, timeout=self.timeout)
            if resp.status_code in RETRY_STATUSES and attempt < self.max_retries:
                time.sleep(delay)
                delay = min(delay * 2, 16.0)
                continue
            resp.raise_for_status()
            return
        raise RuntimeError("retries exhausted")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", type=Path, help="JSONL file of inference records")
    parser.add_argument("--allowed-tools", default="", help="comma-separated tool allowlist")
    parser.add_argument("--max-tools", type=int, default=5, help="tool calls per request above which to flag")
    parser.add_argument("--spike-multiplier", type=float, default=3.0)
    parser.add_argument("--baseline-window", type=int, default=50)
    parser.add_argument("--excerpt-chars", type=int, default=300)
    parser.add_argument("--batch-size", type=int, default=200)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--max-retries", type=int, default=3)
    parser.add_argument("--ship", action="store_true", help="send events to Azure Monitor instead of printing")
    args = parser.parse_args(argv)

    if not args.input.is_file():
        print(f"error: {args.input} not found", file=sys.stderr)
        return 2

    allowed = {t.strip() for t in args.allowed_tools.split(",") if t.strip()}
    baseline = TokenBaseline(args.baseline_window, args.spike_multiplier)
    salt = os.environ.get("USER_HASH_SALT", "")
    client = LogsIngestionClient(args.timeout, args.max_retries) if args.ship else None

    batch: list[dict[str, Any]] = []
    total = flagged = 0
    for rec in read_jsonl(args.input):
        event = build_event(rec, allowed, args.max_tools, baseline, salt, args.excerpt_chars)
        total += 1
        flagged += int(event["InjectionScore"] > 0 or event["ToolCallAnomaly"] or event["SecretLikeOutput"] or event["TokenSpike"])
        if client is None:
            print(json.dumps(event))
            continue
        batch.append(event)
        if len(batch) >= args.batch_size:
            client.send(batch)
            batch.clear()
    if client is not None and batch:
        client.send(batch)
    print(f"processed {total} record(s), {flagged} with at least one indicator", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
