# llm-inference-monitor

Telemetry pipeline for LLM applications: capture request and response records, redact sensitive content, compute security indicators (prompt-injection markers, tool-call anomalies, token spikes, secret-like output), and emit JSON events shaped for Microsoft Sentinel ingestion through the Azure Monitor Logs Ingestion API.

## Purpose

Most LLM applications log either nothing or everything. Neither is useful to a SOC. This project defines a minimal, privacy-aware inference telemetry schema and a shipper that turns raw application logs into security events a detection engineer can write KQL against.

Design goals:

- Redact by default. Raw prompts and completions are hashed, not stored; only bounded, redacted excerpts are kept for triage.
- Indicators computed at the edge, so Sentinel rules can key on fields such as `InjectionScore` and `ToolCallAnomaly` instead of parsing free text.
- Standard transport. Events are posted to a Data Collection Endpoint (DCE) and Data Collection Rule (DCR) using the documented Logs Ingestion API with an Entra ID service principal. No agent required.
- Dry-run first. Without `--ship`, the tool prints events to stdout so the schema and indicators can be reviewed before any Azure resources exist.

## Architecture overview

```
LLM app / gateway  --JSONL-->  monitor/shipper.py  --HTTPS-->  DCE -> DCR -> Log Analytics (LLMInference_CL)
                                    |                                              |
                                    v                                              v
                             redaction + indicators                     Sentinel analytics rules, hunting
```

1. The application (or an API gateway such as Azure API Management in front of Azure OpenAI) writes one JSON object per inference to a log file.
2. `shipper.py` reads the JSONL, redacts each record, computes indicators, and builds a `LLMInference_CL` event.
3. In `--ship` mode the tool acquires a token via the OAuth 2.0 client credentials flow (`https://monitor.azure.com/.default`) and posts batches to `POST {DCE}/dataCollectionRules/{DCR immutable id}/streams/Custom-LLMInference_CL?api-version=2023-01-01`.
4. Sentinel analytics rules (examples in the roadmap) alert on high injection scores, unapproved tool calls, and token anomalies.

## Input record format (JSONL)

```json
{"timestamp": "2026-09-14T12:00:00Z", "request_id": "3f2b...", "app": "support-bot", "user": "alice@example.com",
 "model": "gpt-4o", "prompt": "...", "response": "...", "tool_calls": ["lookup_order"],
 "prompt_tokens": 812, "completion_tokens": 140, "latency_ms": 930, "client_ip": "203.0.113.10"}
```

## Output event schema (`Custom-LLMInference_CL`)

| Column | Type | Description |
|---|---|---|
| TimeGenerated | datetime | Inference timestamp (UTC) |
| RequestId | string | Application request id |
| App | string | Application or agent name |
| UserHash | string | SHA-256 of the user identifier with a per-deployment salt |
| Model | string | Model or deployment name |
| PromptHash | string | SHA-256 of the raw prompt |
| PromptExcerpt | string | Redacted, truncated excerpt for triage |
| ResponseHash | string | SHA-256 of the raw response |
| ResponseExcerpt | string | Redacted, truncated excerpt |
| PromptTokens | int | Prompt tokens reported by the provider |
| CompletionTokens | int | Completion tokens reported by the provider |
| LatencyMs | int | End-to-end latency |
| ToolCalls | dynamic | Tool or function names invoked |
| ToolCallAnomaly | bool | Any tool not on the allowlist, or count above threshold |
| InjectionMarkers | dynamic | Injection phrases matched in the prompt |
| InjectionScore | int | Number of markers matched |
| SecretLikeOutput | bool | Output contains a key- or token-shaped string |
| TokenSpike | bool | Completion tokens above a rolling baseline multiple |
| ClientIp | string | Caller IP if provided |

The DCR transform can be a pass-through (`source`) when the stream columns match the table columns.

## Features

- Regex redaction of email addresses, phone numbers, credit-card-shaped numbers, and common API key formats; hashes for the raw text.
- Indicators: injection marker matching, tool-call allowlist and count checks, rolling median token baseline with a configurable spike multiplier, secret-like output detection.
- Logs Ingestion API client with timeouts, bounded retries with backoff on 429 and 5xx, and batch size limits.
- Dry-run mode prints events as JSON lines; nothing leaves the machine.
- Credentials only from environment variables.

## Quick start

```bash
git clone https://github.com/<your-user>/llm-inference-monitor.git
cd llm-inference-monitor
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Dry run: print enriched events, ship nothing
python monitor/shipper.py samples/events.jsonl --allowed-tools lookup_order,create_ticket

# Ship to Azure Monitor (requires a DCE, a DCR with stream Custom-LLMInference_CL, and a
# service principal with the Monitoring Metrics Publisher role on the DCR)
export AZURE_TENANT_ID="<tenant>"
export AZURE_CLIENT_ID="<app id>"
export AZURE_CLIENT_SECRET="<from your secret manager>"
export DCE_ENDPOINT="https://<dce-name>-<id>.<region>.ingest.monitor.azure.com"
export DCR_IMMUTABLE_ID="dcr-<immutable id>"
export USER_HASH_SALT="<random per-deployment value>"
python monitor/shipper.py samples/events.jsonl --ship
```

## Repo layout

```
.
├── monitor/
│   └── shipper.py
├── samples/
│   └── events.jsonl
├── requirements.txt
├── .gitignore
└── README.md
```

## Roadmap

- Terraform for the DCE, DCR, custom table, and role assignment.
- Sentinel analytics rule examples: injection score threshold, unapproved tool call, token spike per user, secret-like output.
- Streaming mode (tail a file or read from an HTTP callback) instead of batch JSONL.
- Optional FastAPI reverse proxy that captures telemetry inline for OpenAI-compatible endpoints.
- MITRE ATLAS technique tagging on emitted events.

## License

MIT
