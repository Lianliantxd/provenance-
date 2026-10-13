#!/usr/bin/env python3
"""Run the unmodified author entry point with an auditable local-only transport.

The transport adds CPU/runtime options, not prompt text. No Gold is read here.
All payloads stay private to this run. Budget failures bypass author fallback.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import runpy
import signal
import subprocess
import sys
import time
from typing import Any
from urllib.parse import urlparse

RUN = Path(__file__).resolve().parents[1]
PROTOCOL = RUN / "06_frozen_llm_protocol.json"


def utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")
    path.chmod(0o600)


class HardStop(BaseException):
    """Do not let a controller's broad except Exception suppress a budget stop."""


class Budget:
    def __init__(self, limits: dict[str, int]) -> None:
        self.limits = limits
        self.calls = 0
        self.used_tokens = 0

    def reserve(self, context: int, output: int) -> None:
        if self.calls >= self.limits["max_calls"]:
            raise HardStop("MODEL_CALL_LIMIT")
        if self.used_tokens + context + output > self.limits["max_total_tokens"]:
            raise HardStop("TOKEN_RESERVATION_LIMIT")
        self.calls += 1

    def settle(self, data: dict[str, Any], context: int, output: int) -> int:
        vals = [data.get("prompt_eval_count"), data.get("eval_count")]
        if any(type(v) is not int or v < 0 for v in vals):
            raise HardStop("MISSING_TOKEN_TELEMETRY")
        if vals[0] > context or vals[1] > output:
            raise HardStop("BACKEND_TOKEN_BOUND_VIOLATION")
        total = sum(vals)
        self.used_tokens += total
        return total


def adapt_payload(payload: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    if payload.get("model") != config["model"] or payload.get("stream") is not False:
        raise HardStop("UNAPPROVED_MODEL_OR_STREAM")
    if payload.get("think") is not False or payload.get("format") != "json":
        raise HardStop("UNAPPROVED_REQUEST_FORMAT")
    result = copy.deepcopy(payload)
    result.setdefault("options", {}).update(config["runtime_options"])
    result["keep_alive"] = 0
    if result["prompt"] != payload["prompt"]:
        raise HardStop("PROMPT_CHANGED")
    return result


def preflight(protocol: dict[str, Any]) -> None:
    repo = Path(protocol["author_repo_path"])
    if (repo / ".env.local").exists():
        raise HardStop("AUTHOR_ENV_FILE_PRESENT")
    for path, expected in protocol["integrity_sha256"].items():
        if sha(Path(path)) != expected:
            raise HardStop("FROZEN_FILE_CHANGED: " + str(path))
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    status = subprocess.check_output(["git", "status", "--porcelain"], cwd=repo, text=True).strip()
    if head != protocol["author_commit"] or status:
        raise HardStop("AUTHOR_GIT_CHANGED")


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["probe", "case"])
    args = parser.parse_args()
    protocol = json.loads(PROTOCOL.read_text())
    config = protocol["model_channel"]
    endpoint = urlparse(config["endpoint"])
    if (endpoint.scheme, endpoint.hostname, endpoint.port, endpoint.path) != ("http", "127.0.0.1", 11434, "/api/generate") or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
        raise HardStop("ONLY_FIXED_LOCAL_BACKEND_ALLOWED")
    preflight(protocol)
    limits = protocol["probe_budget" if args.mode == "probe" else "case_budget"]
    out = RUN / ("probe" if args.mode == "probe" else "traces")
    if (out / "started.json").exists():
        raise HardStop("REFUSE_SECOND_ATTEMPT")
    if args.mode == "case":
        probe = json.loads((RUN / "probe/completion.json").read_text())
        if probe.get("status") != "PASS":
            raise HardStop("PROBE_NOT_PASSED")
    save(out / "started.json", {"utc": utc(), "mode": args.mode, "protocol_sha256": sha(PROTOCOL)})
    os.environ.update(protocol["environment"])
    os.environ["BENCH_NUM_CTX"] = str(limits["context_tokens"])
    os.environ["BENCH_NUM_PREDICT"] = str(limits["output_tokens"])
    os.environ["BENCH_OLLAMA_URL"] = config["endpoint"]
    sys.path.insert(0, protocol["module_path"])
    import requests

    original_request = requests.sessions.Session.request
    budget = Budget(limits)
    started = time.monotonic()
    ledger_path = out / "model_calls.jsonl"

    def emit(record: dict[str, Any]) -> None:
        with ledger_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def request(session: Any, method: str, url: str, **kwargs: Any) -> Any:
        session.trust_env = False
        if method.upper() == "GET" and url == "http://127.0.0.1:11434/api/tags":
            return original_request(session, method, url, timeout=5, allow_redirects=False)
        if method.upper() != "POST" or url != config["endpoint"]:
            raise HardStop("NETWORK_DESTINATION_BLOCKED")
        tag_response = original_request(session, "GET", "http://127.0.0.1:11434/api/tags", timeout=5, allow_redirects=False)
        tag_response.raise_for_status()
        tags = tag_response.json()
        matched = [m for m in tags.get("models", []) if m.get("name") == config["model"]]
        if len(matched) != 1 or matched[0].get("digest") != config["model_digest"]:
            raise HardStop("MODEL_DIGEST_CHANGED")
        original = kwargs.get("json")
        if not isinstance(original, dict):
            raise HardStop("NON_JSON_REQUEST")
        payload = adapt_payload(original, config)
        opts = payload["options"]
        if opts.get("num_ctx") != limits["context_tokens"] or opts.get("num_predict") != limits["output_tokens"]:
            raise HardStop("REQUEST_BUDGET_OPTIONS_CHANGED")
        budget.reserve(limits["context_tokens"], limits["output_tokens"])
        number = budget.calls
        prefix = out / f"call_{number:03d}"
        save(prefix.with_suffix(".model_metadata.json"), matched[0])
        save(prefix.with_suffix(".author_request.json"), original)
        save(prefix.with_suffix(".effective_request.json"), payload)
        record = {"call": number, "started_utc": utc(), "status": "STARTED", "model": config["model"],
                  "prompt_sha256": hashlib.sha256(payload["prompt"].encode()).hexdigest(),
                  "prompt_utf8_bytes": len(payload["prompt"].encode()), "system_field_present": "system" in payload,
                  "token_reservation": limits["context_tokens"] + limits["output_tokens"]}
        emit(record)
        call_start = time.monotonic()
        try:
            response = original_request(session, method, url, json=payload,
                                        timeout=(5, limits["request_timeout_seconds"]), allow_redirects=False)
            prefix.with_suffix(".response_body.txt").write_bytes(response.content)
            record.update(http_status=response.status_code, response_body_sha256=sha(prefix.with_suffix(".response_body.txt")))
            if response.status_code != 200:
                raise HardStop("BACKEND_HTTP_FAILURE")
            data = response.json()
            if data.get("model") != config["model"] or data.get("done") is not True:
                raise HardStop("BACKEND_ID_OR_COMPLETION_MISMATCH")
            tokens = budget.settle(data, limits["context_tokens"], limits["output_tokens"])
            record.update(status="COMPLETE", prompt_tokens=data["prompt_eval_count"], output_tokens=data["eval_count"],
                          total_tokens=tokens, cumulative_tokens=budget.used_tokens, response_model=data["model"],
                          done_reason=data.get("done_reason"))
            return response
        except BaseException as exc:
            record.update(status="FAILED", error_type=type(exc).__name__, error=str(exc))
            raise HardStop("TRANSPORT_OR_BUDGET_FAILURE: " + str(exc)) from exc
        finally:
            record.update(ended_utc=utc(), elapsed_seconds=round(time.monotonic()-call_start, 6))
            emit(record)
            print(json.dumps({k: record.get(k) for k in ["call", "status", "elapsed_seconds", "total_tokens", "error"]}), flush=True)

    requests.sessions.Session.request = request

    def timeout_handler(signum: int, frame: Any) -> None:
        raise HardStop("WALL_TIME_LIMIT")

    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(limits["max_wall_seconds"])
    completion: dict[str, Any] = {"mode": args.mode, "status": "FAILED"}
    try:
        if args.mode == "probe":
            from run_chain_reconstruction_paper_systems import call_ollama
            result = call_ollama(protocol["probe_prompt"], config["model"], limits["request_timeout_seconds"], temperature=0)
            parsed = json.loads(result)
            if parsed != {"ok": True, "value": 2}:
                raise HardStop("SYNTHETIC_JSON_PROBE_INVALID")
            completion["status"] = "PASS"
        else:
            sys.argv = protocol["author_argv"][1:]
            runpy.run_path(sys.argv[0], run_name="__main__")
            completion["status"] = "AUTHOR_ENTRY_RETURNED"
    except BaseException as exc:
        completion.update(error_type=type(exc).__name__, error=str(exc))
    finally:
        signal.alarm(0)
        requests.sessions.Session.request = original_request
        completion.update(completed_utc=utc(), elapsed_seconds=round(time.monotonic()-started,6),
                          model_attempts=budget.calls, reported_total_tokens=budget.used_tokens,
                          external_api_cost_usd=0, gold_read_by_runner=False)
        save(out / "completion.json", completion)
    print(json.dumps(completion), flush=True)
    return 0 if completion["status"] in {"PASS", "AUTHOR_ENTRY_RETURNED"} else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (HardStop, Exception) as exc:
        failure = RUN / "logs" / ("preflight_failure_" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json")
        save(failure, {"utc": utc(), "error_type": type(exc).__name__, "error": str(exc)})
        print("HARD_STOP: " + str(exc), file=sys.stderr)
        raise SystemExit(3)
