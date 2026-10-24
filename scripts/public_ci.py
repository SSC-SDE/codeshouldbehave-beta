#!/usr/bin/env python3
"""Bounded public-ci-v1 control plane. Reviewed repositories are data, never code.

No command publishes remotely by default. The local primitives are shared by the
trusted workflow helpers; unknown authority, billing or signature is a denial.
Only explicit activated provider adapters write; offline commands never authorize writes.
"""
from __future__ import annotations

import argparse
import importlib.util
import base64
from datetime import datetime, timezone
import hashlib
import gzip
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable


SCHEMA = "csb-public-ci-config-v1"
STATE_SCHEMA = "csb-public-state-v1"
REQUEST_SCHEMA = "csb-public-request-v1"
INDEX_SCHEMA = "csb-public-index-v1"
PREDICATE_TYPE = "https://codeshouldbehave.dev/attestations/public-state/v1"
MIB = 1024 * 1024
MAX_STATE_BYTES = 128 * 1024
MAX_PROOF_BYTES = 256 * 1024
MAX_CONFIG_BYTES = 128 * 1024
MAX_BUNDLE_BYTES = 8 * MIB
MAX_REPORT_COMPRESSED = 4 * MIB
MAX_HANDOFF_BYTES = 5 * MIB
MAX_HANDOFF_TOTAL = 32 * MIB
MAX_SITE_BYTES = 64 * MIB
MAX_SITE_ARCHIVE = 70 * MIB
MAX_REPOSITORY_ARTIFACT_BYTES = 172 * MIB
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")
PAGES_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")


class Refusal(ValueError):
    """An explicit incomplete/deferred state, never an architectural success."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def object_fields(value: Any, required: set[str], optional: set[str] = frozenset(),
                  name: str = "record") -> dict:
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        raise Refusal(f"{name}: missing or unsupported fields")
    return value


def integer(value: Any, low: int, high: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise Refusal(f"{name}: invalid integer")
    return value


def text(value: Any, pattern: re.Pattern, name: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise Refusal(f"{name}: invalid value")
    return value


def utc(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise Refusal("timestamp must be explicit UTC")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise Refusal("invalid UTC timestamp") from exc


def timestamp(value: datetime | None = None) -> str:
    return (value or datetime.now(timezone.utc)).isoformat(timespec="seconds").replace("+00:00", "Z")


def relative_path(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value.encode()) > 1024 or "\\" in value or "\x00" in value:
        raise Refusal("invalid relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in (".", "..", ".git") for part in value.split("/")) or "" in value.split("/") or any(char in value for char in (":", "%", "?", "#")):
        raise Refusal("unsafe relative path")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise Refusal("control character in path")
    return value


def repository(value: Any) -> dict:
    object_fields(value, {"id", "owner", "name"}, name="repository")
    integer(value["id"], 1, 2**63 - 1, "repository id")
    text(value["owner"], NAME, "repository owner")
    text(value["name"], NAME, "repository name")
    return dict(value)


def read_json(path: Path, cap: int) -> Any:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > cap:
        raise Refusal("missing, linked or oversized JSON input")
    try:
        def pairs(items: list[tuple[str, Any]]) -> dict:
            result = {}
            for key, value in items:
                if key in result:
                    raise Refusal("duplicate JSON key")
                result[key] = value
            return result
        return json.loads(path.read_bytes(), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Refusal("non-finite JSON")))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Refusal("invalid bounded JSON") from exc


def write_new_json(path: Path, value: Any, cap: int = MAX_STATE_BYTES) -> None:
    data = canonical(value) + b"\n"
    if len(data) > cap:
        raise Refusal("output record exceeds byte budget")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as output:
        output.write(data)


def load_config(value: Any, *, runtime: bool = False) -> dict:
    object_fields(value, {"schema_version", "repository", "default_branch", "workflow_path",
                          "workflow_sha256", "policy_path", "policy_sha256", "context_path",
                          "context_sha256", "engine", "site", "receipt", "budget", "operations"}, name="config")
    if value["schema_version"] != SCHEMA:
        raise Refusal("unsupported public CI config")
    repository(value["repository"])
    branch = value["default_branch"]
    if not isinstance(branch, str) or not branch or len(branch) > 200 or any(x in branch for x in ("..", "@{", "\\", " ", "\n", ":", "~", "^", "?", "*", "[")) or branch.startswith(("/", "-")) or branch.endswith(("/", ".", ".lock")):
        raise Refusal("invalid default branch")
    for key in ("workflow_path", "policy_path", "context_path"):
        relative_path(value[key])
    if not value["workflow_path"].startswith(".github/workflows/") or not value["workflow_path"].endswith((".yml", ".yaml")):
        raise Refusal("controller is not an installed workflow")
    for key in ("workflow_sha256", "policy_sha256", "context_sha256"):
        text(value[key], SHA256, key)
    engine = object_fields(value["engine"], {"commit", "flowdiff_sha256", "exporter_sha256"},
                           {"package_url", "package_sha256", "package_signer_workflow", "package_attestation_url", "package_attestation_sha256"}, name="engine")
    text(engine["commit"], COMMIT, "engine commit")
    for key in ("flowdiff_sha256", "exporter_sha256"):
        text(engine[key], SHA256, key)
    if ("package_url" in engine) != ("package_sha256" in engine):
        raise Refusal("engine package URL/digest must be paired")
    if "package_url" in engine:
        if not isinstance(engine["package_url"], str) or not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/download/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.tar\.gz", engine["package_url"]):
            raise Refusal("engine package must use a pinned public GitHub release URL")
        text(engine["package_sha256"], SHA256, "package digest")
        if "package_signer_workflow" in engine and not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml", engine["package_signer_workflow"]):
            raise Refusal("invalid release signer workflow")
    elif "package_signer_workflow" in engine:
        raise Refusal("release signer requires a pinned package")
    if ("package_attestation_url" in engine) != ("package_attestation_sha256" in engine):
        raise Refusal("release attestation URL/digest must be paired")
    if "package_attestation_url" in engine:
        if "package_url" not in engine or not isinstance(engine["package_attestation_url"], str) or not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/download/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.sigstore\.json", engine["package_attestation_url"]):
            raise Refusal("attestation must be a pinned public release bundle")
        text(engine["package_attestation_sha256"], SHA256, "release attestation digest")
    site = object_fields(value["site"], {"origin", "base_path"}, name="site")
    if not isinstance(site["origin"], str) or not re.fullmatch(r"https://[a-zA-Z0-9.-]+\.github\.io", site["origin"]):
        raise Refusal("public-ci-v1 requires an exact GitHub Pages origin")
    base = site["base_path"]
    if base != f"/{value['repository']['name']}/":
        raise Refusal("site prefix must match the repository project path")
    receipt = object_fields(value["receipt"], {"task", "environment", "signer_workflow"}, name="receipt")
    if receipt["task"] != "csb-public-state-v1" or receipt["environment"] != "csb-public-state":
        raise Refusal("unsupported state receipt namespace")
    expected_signer = f"{value['repository']['owner']}/{value['repository']['name']}/{value['workflow_path']}"
    if receipt["signer_workflow"] != expected_signer:
        raise Refusal("signer workflow differs from installed controller")
    budget = object_fields(value["budget"], {"proof_mode", "account", "repository_byte_limit"},
                           {"evidence_path", "evidence_sha256"}, name="budget")
    if budget["proof_mode"] not in ("organization_api", "operator_observation", "unavailable") or budget["account"] != value["repository"]["owner"]:
        raise Refusal("unsupported budget authority")
    if budget["repository_byte_limit"] != MAX_REPOSITORY_ARTIFACT_BYTES or isinstance(budget["repository_byte_limit"], bool):
        raise Refusal("public-ci-v1 repository artifact guard must be exactly 172 MiB")
    if budget["proof_mode"] == "operator_observation":
        if "evidence_path" not in budget or "evidence_sha256" not in budget:
            raise Refusal("operator observation must pin the exact base-owned evidence")
        relative_path(budget["evidence_path"]); text(budget["evidence_sha256"], SHA256, "budget evidence digest")
    elif "evidence_path" in budget or "evidence_sha256" in budget:
        raise Refusal("unexpected operator evidence")
    operations = object_fields(value["operations"], {"analysis", "publication", "checks"}, name="operations")
    if any(not isinstance(item, bool) for item in operations.values()):
        raise Refusal("operation switches must be booleans")
    if runtime and (budget["proof_mode"] != "operator_observation" or any(value[key] == "0" * 64 for key in ("workflow_sha256", "policy_sha256", "context_sha256")) or any(engine[key] == "0" * 64 for key in ("flowdiff_sha256", "exporter_sha256")) or engine["commit"] == "0" * 40):
        raise Refusal("unavailable: verified billing/trust configuration is required")
    return json.loads(canonical(value))


def verify_operator_budget(config: dict, root: Path, now: datetime) -> dict:
    budget = config["budget"]
    if budget["proof_mode"] != "operator_observation":
        raise Refusal("operator budget proof not selected")
    path = root / relative_path(budget["evidence_path"])
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024 or digest(path.read_bytes()) != budget["evidence_sha256"]:
        raise Refusal("operator budget evidence digest mismatch")
    value = read_json(path, 16 * 1024)
    object_fields(value, {"schema_version", "account", "source", "observed_at", "expires_at", "plan", "products"}, name="operator budget")
    if value["schema_version"] != "csb-public-operator-budget-v1" or value["account"] != budget["account"] or value["source"] != "https://github.com/settings/billing/budgets" or value["plan"] != "free":
        raise Refusal("operator budget authority/plan mismatch")
    observed, expires = utc(value["observed_at"]), utc(value["expires_at"])
    if not observed <= now < expires or not 0 < (expires - observed).total_seconds() <= 86400:
        raise Refusal("operator budget observation expired/future/too long")
    if not isinstance(value["products"], list) or len(value["products"]) != 2:
        raise Refusal("both Actions and Packages hard stops are required")
    products = set()
    for product in value["products"]:
        object_fields(product, {"product", "budget_amount_usd", "prevent_further_usage", "status"}, name="operator product")
        if product["product"] not in ("actions", "packages") or product["product"] in products or isinstance(product["budget_amount_usd"], bool) or product["budget_amount_usd"] != 0 or product["prevent_further_usage"] is not True or product["status"] != "usage_blocked":
            raise Refusal("operator record does not attest enforced zero paid overage")
        products.add(product["product"])
    return value


def verify_installed_inputs(config: dict, trusted_root: Path) -> None:
    for path_key, hash_key in (("workflow_path", "workflow_sha256"), ("policy_path", "policy_sha256"), ("context_path", "context_sha256")):
        path = trusted_root / relative_path(config[path_key])
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * MIB or digest(path.read_bytes()) != config[hash_key]:
            raise Refusal(f"base-owned {path_key} integrity failed")
        if any(parent.is_symlink() for parent in path.parents if parent != trusted_root.parent):
            raise Refusal("linked trusted configuration parent")


def verify_run(config: dict, run: Any, default_head: str, workflow_bytes: bytes) -> dict:
    required = {"id", "run_attempt", "event", "head_sha", "head_branch", "path", "repository"}
    object_fields(run, required, {"status", "conclusion"}, name="trusted run")
    integer(run["id"], 1, 2**63 - 1, "run id")
    integer(run["run_attempt"], 1, 10_000, "run attempt")
    if repository(run["repository"]) != config["repository"] or run["event"] not in ("workflow_run", "schedule", "workflow_dispatch"):
        raise Refusal("untrusted controller origin")
    if run["head_branch"] != config["default_branch"] or run["head_sha"] != text(default_head, COMMIT, "default head") or run["path"] != config["workflow_path"]:
        raise Refusal("controller must run the exact current default-branch workflow")
    if digest(workflow_bytes) != config["workflow_sha256"]:
        raise Refusal("controller workflow digest changed")
    return dict(run)


def empty_state(config: dict) -> dict:
    return {"schema_version": STATE_SCHEMA, "repository": config["repository"], "sequence": 0,
            "previous_receipt_sha256": None, "site_generation": 0, "site_manifest_sha256": None,
            "pages_deployment_id": None, "cursor": 0, "discovery_page": 1, "next_queue_sequence": 1,
            "pending": [], "completed": [], "withdrawn": [], "consent_epoch": 1, "cleanup": [],
            "last_observed_at": None, "promotion_intent": None, "check_updates": [], "site_artifact_id": None, "previous_site_artifact_id": None}


def validate_state(value: Any, config: dict) -> dict:
    object_fields(value, {"schema_version", "repository", "sequence", "previous_receipt_sha256",
                          "site_generation", "site_manifest_sha256", "pages_deployment_id", "cursor",
                          "discovery_page", "next_queue_sequence", "pending", "completed", "withdrawn", "consent_epoch", "cleanup",
                          "last_observed_at"}, {"budget_activation", "maintenance_cursor", "promotion_intent", "check_updates", "site_artifact_id", "previous_site_artifact_id"}, name="state")
    if value["schema_version"] != STATE_SCHEMA or repository(value["repository"]) != config["repository"]:
        raise Refusal("state belongs to another repository/schema")
    for key in ("sequence", "site_generation", "cursor"):
        integer(value[key], 0, 2**63 - 1, key)
    integer(value["next_queue_sequence"], 1, 2**63 - 1, "next queue sequence")
    integer(value["discovery_page"], 1, 10_000, "discovery page")
    integer(value["consent_epoch"], 1, 2**63 - 1, "consent epoch")
    for key in ("previous_receipt_sha256", "site_manifest_sha256"):
        if value[key] is not None:
            text(value[key], SHA256, key)
    if value["site_generation"] == 0:
        if value["site_manifest_sha256"] is not None or value["pages_deployment_id"] is not None:
            raise Refusal("generation zero cannot claim a published site")
    else:
        text(value["site_manifest_sha256"], SHA256, "site manifest")
        text(value["pages_deployment_id"], PAGES_ID, "Pages deployment")
    for key in ("site_artifact_id", "previous_site_artifact_id"):
        if value.get(key) is not None:
            integer(value[key], 1, 2**63 - 1, key)
    if value["last_observed_at"] is not None:
        utc(value["last_observed_at"])
    if "maintenance_cursor" in value:
        integer(value["maintenance_cursor"], 0, 2**31 - 1, "maintenance cursor")
    if value.get("budget_activation") is not None:
        activation = object_fields(value["budget_activation"], {"schema_version", "account", "evidence_sha256", "budget_policy_sha256", "activated_at"}, name="budget activation")
        if activation["schema_version"] != "csb-public-budget-activation-v1" or activation["account"] != config["budget"]["account"]:
            raise Refusal("budget activation account mismatch")
        for key in ("evidence_sha256", "budget_policy_sha256"):
            text(activation[key], SHA256, key)
        utc(activation["activated_at"])
    if value.get("promotion_intent") is not None:
        intent = object_fields(value["promotion_intent"], {"site_generation", "site_manifest_sha256", "artifact_id", "pages_build_version", "run_id", "run_attempt", "created_at"}, name="promotion intent")
        if intent["site_generation"] != value["site_generation"] + 1:
            raise Refusal("promotion intent generation mismatch")
        text(intent["site_manifest_sha256"], SHA256, "intended site digest")
        text(intent["pages_build_version"], PAGES_ID, "intended Pages version")
        integer(intent["artifact_id"], 1, 2**63 - 1, "intended artifact")
        integer(intent["run_id"], 1, 2**63 - 1, "intent run")
        integer(intent["run_attempt"], 1, 10_000, "intent attempt")
        utc(intent["created_at"])
    pending = value["pending"]
    if not isinstance(pending, list) or len(pending) > 100:
        raise Refusal("pending queue exceeds profile")
    seen, positions = set(), set()
    for item in pending:
        object_fields(item, {"pr_number", "selected_baseline", "proposal", "comparison_key", "draft", "queue_sequence", "attempts", "status", "reason"}, name="pending head")
        number = integer(item["pr_number"], 1, 2**31 - 1, "PR number")
        position = integer(item["queue_sequence"], 1, value["next_queue_sequence"] - 1, "queue position")
        if number in seen or position in positions:
            raise Refusal("duplicate queue identity/position")
        seen.add(number); positions.add(position)
        for key in ("selected_baseline", "proposal"):
            text(item[key], COMMIT, key)
        text(item["comparison_key"], SHA256, "pending comparison key")
        integer(item["attempts"], 0, 2, "retry count")
        if not isinstance(item["draft"], bool) or item["status"] not in ("pending", "deferred", "running", "failed") or not isinstance(item["reason"], str) or len(item["reason"]) > 128:
            raise Refusal("invalid pending status")
    if not isinstance(value["completed"], list) or len(value["completed"]) > 100:
        raise Refusal("completed observation cache exceeds profile")
    completed_numbers = set()
    for item in value["completed"]:
        object_fields(item, {"pr_number", "comparison_key", "outcome"}, name="completed head")
        number = integer(item["pr_number"], 1, 2**31 - 1, "completed PR")
        if number in completed_numbers or item["outcome"] not in ("published", "unsupported", "failure", "cancelled"):
            raise Refusal("invalid/duplicate completed head")
        completed_numbers.add(number); text(item["comparison_key"], SHA256, "completed comparison key")
    updates = value.get("check_updates", [])
    if not isinstance(updates, list) or len(updates) > 100:
        raise Refusal("check repair ledger exceeds profile")
    update_ids = set()
    for item in updates:
        object_fields(item, {"request", "public_report_id", "conclusion", "reason"}, {"verdict"}, name="check update")
        if "verdict" in item and item["verdict"] not in ("change_detected", "no_change_detected", "incomplete"):
            raise Refusal("invalid check verdict")
        if "verdict" in item and item["conclusion"] != verdict_conclusion(item):
            raise Refusal("check conclusion differs from verdict")
        request = validate_ledger_request(item["request"], config)
        if request["request_id"] in update_ids or item["conclusion"] not in ("success", "neutral", "failure", "cancelled") or item["reason"] not in ("", "analysis_unavailable", "superseded"):
            raise Refusal("invalid or duplicate check repair identity")
        update_ids.add(request["request_id"])
        if item["public_report_id"] is not None:
            text(item["public_report_id"], SHA256, "check public report")
        elif item["conclusion"] in ("success", "neutral"):
            raise Refusal("successful/neutral check requires a published report")
    for key in ("withdrawn", "cleanup"):
        if not isinstance(value[key], list) or len(value[key]) > 1000:
            raise Refusal("bounded state ledger is full")
        if len(set(value[key])) != len(value[key]):
            raise Refusal("duplicate state ledger identity")
        for item in value[key]:
            text(item, SHA256, key)
    if len(canonical(value)) > MAX_STATE_BYTES:
        raise Refusal("state exceeds byte budget; no unsafe truncation")
    return json.loads(canonical(value))


def validate_pr(item: Any, config: dict) -> dict:
    object_fields(item, {"number", "repository", "selected_baseline", "proposal", "state", "draft", "public", "consent"}, name="provider PR")
    integer(item["number"], 1, 2**31 - 1, "PR number")
    if repository(item["repository"]) != config["repository"] or item["public"] is not True or item["consent"] is not True:
        raise Refusal("PR is outside approved public repository/consent")
    for key in ("selected_baseline", "proposal"):
        text(item[key], COMMIT, key)
    if item["state"] not in ("open", "closed") or not isinstance(item["draft"], bool):
        raise Refusal("invalid provider PR state")
    return dict(item)


def comparison_key(config: dict, item: dict) -> str:
    return digest(canonical({"repository": config["repository"], "pr_number": item.get("number", item.get("pr_number")),
                             "selected_baseline": item["selected_baseline"], "proposal": item["proposal"],
                             "policy_sha256": config["policy_sha256"], "context_sha256": config["context_sha256"], "engine": config["engine"]}))


def plan(config: dict, previous: dict, observations: list[dict], observed_at: str, *,
         existing_handoff_bytes: int = 0, rate_remaining: int = 5000, rate_limit: int = 5000, admission_limit: int = 6) -> dict:
    state = validate_state(previous, config)
    utc(observed_at)
    integer(existing_handoff_bytes, 0, MAX_HANDOFF_TOTAL, "handoff inventory")
    integer(rate_limit, 1, 1_000_000, "provider rate limit")
    integer(rate_remaining, 0, rate_limit, "provider rate remaining")
    if not isinstance(observations, list) or len(observations) > 100:
        raise Refusal("provider discovery page exceeds 100; retain cursor")
    values = [validate_pr(item, config) for item in observations]
    numbers = [item["number"] for item in values]
    if len(set(numbers)) != len(numbers):
        raise Refusal("duplicate provider PR observation")
    pending = {item["pr_number"]: item for item in state["pending"]}
    completed = {item["pr_number"]: item for item in state["completed"]}
    ordered = sorted(values, key=lambda item: (item["number"] <= state["cursor"], item["number"]))
    for item in ordered:
        number = item["number"]
        state["cursor"] = number
        if item["state"] == "closed":
            pending.pop(number, None)
            completed.pop(number, None)
            continue
        key = comparison_key(config, item)
        if completed.get(number, {}).get("comparison_key") == key:
            continue
        completed.pop(number, None)
        old = pending.get(number)
        if old and old["comparison_key"] == key:
            old["draft"] = item["draft"]
            continue
        if old is None and len(pending) >= 100:
            # Do not silently advance beyond undiscoverable work on a full queue.
            state["cursor"] = previous["cursor"]
            break
        position = old["queue_sequence"] if old else state["next_queue_sequence"]
        if old is None:
            state["next_queue_sequence"] += 1
        pending[number] = {"pr_number": number, "selected_baseline": item["selected_baseline"],
                           "proposal": item["proposal"], "comparison_key": key, "draft": item["draft"],
                           "queue_sequence": position, "attempts": 0, "status": "pending", "reason": ""}
    selected = sorted((item for item in pending.values() if item["status"] != "failed"), key=lambda item: item["queue_sequence"])[:20]
    integer(admission_limit, 0, 6, "admission limit")
    slots = min(admission_limit, (MAX_HANDOFF_TOTAL - existing_handoff_bytes) // MAX_HANDOFF_BYTES)
    if rate_remaining < max(1, (rate_limit + 4) // 5) + 20:
        slots = 0
    admitted = []
    for index, item in enumerate(selected):
        if index < slots:
            item["status"], item["reason"] = "running", ""
            admitted.append(dict(item))
        else:
            item["status"], item["reason"] = "deferred", "quota_or_rate_reservation"
    state["pending"] = sorted(pending.values(), key=lambda item: item["queue_sequence"])
    state["completed"] = sorted(completed.values(), key=lambda item: item["pr_number"])
    state["sequence"] += 1
    state["previous_receipt_sha256"] = digest(canonical(previous))
    state["last_observed_at"] = observed_at
    validate_state(state, config)
    return {"schema_version": "csb-public-plan-v1", "state": state, "admitted": admitted,
            "max_parallel": 2, "handoff_reservation_bytes": len(admitted) * MAX_HANDOFF_BYTES,
            "deferred": len(state["pending"]) - len(admitted)}


def finish_head(state: dict, pr_number: int, proposal: str, outcome: str, reason: str = "") -> dict:
    result = json.loads(canonical(state))
    item = next((entry for entry in result["pending"] if entry["pr_number"] == pr_number), None)
    if item is None or item["proposal"] != proposal:
        raise Refusal("superseded completion cannot alter current pending head")
    if outcome in ("published", "unsupported", "cancelled", "failure"):
        result["pending"].remove(item)
        result["completed"] = [old for old in result["completed"] if old["pr_number"] != pr_number]
        result["completed"].append({"pr_number": pr_number, "comparison_key": item["comparison_key"], "outcome": outcome})
        if len(result["completed"]) > 100:
            raise Refusal("completed queue budget exhausted; no silent forgetting")
    elif outcome == "transient":
        item["attempts"] = min(2, item["attempts"] + 1)
        if item["attempts"] >= 2:
            return finish_head(result, pr_number, proposal, "failure", reason)
        item["status"] = "pending"
        item["reason"] = reason[:128]
    elif outcome == "deferred":
        item["status"], item["reason"] = "deferred", reason[:128]
    else:
        raise Refusal("unknown completion state")
    return result


def request_for(config: dict, pending: dict, run: dict, baseline: str, observed_at: str, *, baseline_mode: str = "merge_base") -> dict:
    request = {"schema_version": REQUEST_SCHEMA, "repository": config["repository"], "pr_number": pending["pr_number"],
               "selected_baseline": pending["selected_baseline"], "baseline": text(baseline, COMMIT, "analysis baseline"),
               "proposal": pending["proposal"], "policy_sha256": config["policy_sha256"],
               "context_sha256": config["context_sha256"], "engine": config["engine"],
               "controller_sha": run["head_sha"], "run_id": run["id"], "run_attempt": run["run_attempt"],
               "observed_at": observed_at, "baseline_mode": baseline_mode}
    request["request_id"] = digest(canonical(request))
    return request


def validate_request(value: Any, config: dict) -> dict:
    required = {"schema_version", "repository", "pr_number", "selected_baseline", "baseline", "proposal", "policy_sha256",
                "context_sha256", "engine", "controller_sha", "run_id", "run_attempt", "observed_at", "baseline_mode", "request_id"}
    object_fields(value, required, name="analysis request")
    if value["schema_version"] != REQUEST_SCHEMA or value["repository"] != config["repository"] or value["engine"] != config["engine"] or any(value[key] != config[key] for key in ("policy_sha256", "context_sha256")):
        raise Refusal("request trust/context mismatch")
    integer(value["pr_number"], 1, 2**31 - 1, "PR number")
    integer(value["run_id"], 1, 2**63 - 1, "run id")
    integer(value["run_attempt"], 1, 10_000, "run attempt")
    for key in ("selected_baseline", "baseline", "proposal", "controller_sha"):
        text(value[key], COMMIT, key)
    utc(value["observed_at"])
    if value["baseline_mode"] not in ("exact", "merge_base") or (value["baseline_mode"] == "exact" and value["baseline"] != value["selected_baseline"]):
        raise Refusal("invalid baseline mode/identity")
    identity = {key: item for key, item in value.items() if key != "request_id"}
    if value["request_id"] != digest(canonical(identity)):
        raise Refusal("request digest mismatch")
    return value


def validate_ledger_request(value: dict, config: dict) -> dict:
    # A previously attested repair can outlive an engine or context upgrade.
    # It conveys only an old check identity, never authority for new analysis.
    old_config = dict(config)
    for key in ("engine", "policy_sha256", "context_sha256"):
        if key not in value:
            raise Refusal("missing attested check request identity")
        old_config[key] = value[key]
    return validate_request(value, old_config)


def current_fence(config: dict, request: dict, fresh: dict) -> None:
    pr = validate_pr(fresh, config)
    if pr["state"] != "open" or pr["number"] != request["pr_number"] or any(pr[key] != request[key] for key in ("selected_baseline", "proposal")):
        raise Refusal("superseded: provider comparison changed")


def budget_activation(config: dict, trusted_root: Path, previous: dict, now: datetime) -> dict:
    """Activation uses recent observed controls; subsequent controls are unobserved.

    The owner maintaining enforced $0 hardstops is an operating precondition. This
    function does not reinterpret old browser evidence as a live account API read.
    The returned activation must be persisted in the cryptographically attested
    state before it can authorize subsequent uploads.
    """
    policy_hash = digest(canonical(config["budget"]))
    active = previous.get("budget_activation")
    if active is not None:
        if active["budget_policy_sha256"] != policy_hash or active["evidence_sha256"] != config["budget"].get("evidence_sha256"):
            raise Refusal("budget policy changed; recent activation is required")
        return dict(active)
    observation = verify_operator_budget(config, trusted_root, now)
    return {"schema_version": "csb-public-budget-activation-v1", "account": observation["account"],
            "evidence_sha256": config["budget"]["evidence_sha256"], "budget_policy_sha256": policy_hash,
            "activated_at": timestamp(now)}


class GitHub:
    """Repository-scoped, bounded GitHub adapter; tokens never reach workers."""
    def __init__(self, config: dict, *, allow_writes: bool = False, max_calls: int = 100,
                 transport: Callable | None = None, budget: Any = None):
        self.config, self.allow_writes, self.max_calls = config, allow_writes, max_calls
        self.calls, self.transport, self.handoff_bytes, self.budget = 0, transport, 0, budget
        self.prefix = f"repos/{config['repository']['owner']}/{config['repository']['name']}"
        self._workflow_cache, self._run_cache, self._receipt_cache = {}, {}, {}

    def api(self, path: str, *, method: str = "GET", body: dict | None = None, allow_404: bool = False) -> Any:
        if self.calls >= self.max_calls:
            raise Refusal("deferred: provider call budget exhausted")
        if not (path == "rate_limit" or path.startswith(self.prefix + "/") or path == self.prefix):
            raise Refusal("provider path escapes configured repository")
        if method not in ("GET", "POST", "PATCH", "DELETE") or (method != "GET" and not self.allow_writes):
            raise Refusal("remote writes are disabled")
        if self.budget is not None:
            try:
                self.budget.reserve(method, path)
            except ValueError as exc:
                raise Refusal("deferred: application REST ticket exhausted or invalid") from exc
        if self.transport is None and os.environ.get("GITHUB_ACTIONS") == "true" and self.budget is None:
            raise Refusal("live controller REST transport requires its durable stage ticket")
        self.calls += 1
        if self.transport is not None:
            status, value = self.transport(method, path, body)
        else:
            token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
            if not token:
                raise Refusal("repository-scoped workflow token is unavailable")
            env = clean_environment(); env["GH_TOKEN"] = token
            executable = shutil.which("gh")
            if executable is None:
                raise Refusal("trusted GitHub CLI is unavailable")
            argv = [executable, "api", "--hostname", "github.com", "--include", "--method", method,
                    "-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2022-11-28", path]
            if body is not None:
                argv += ["--input", "-"]
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                process = subprocess.Popen(argv, stdin=subprocess.PIPE if body is not None else subprocess.DEVNULL,
                                           stdout=stdout, stderr=stderr, env=env, start_new_session=True)
                started = time.monotonic()
                try:
                    if body is not None:
                        assert process.stdin is not None
                        process.stdin.write(canonical(body)); process.stdin.close()
                    while process.poll() is None:
                        if time.monotonic() - started > 15 or stdout.tell() + stderr.tell() > 4 * MIB:
                            raise Refusal("provider request deadline/response budget exhausted")
                        time.sleep(0.025)
                    if stdout.tell() + stderr.tell() > 4 * MIB:
                        raise Refusal("provider response budget exhausted")
                    stdout.seek(0); raw = stdout.read(4 * MIB + 1)
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=5)
            if len(raw) > 4 * MIB:
                raise Refusal("provider response budget exhausted")
            parts = re.split(br"\r?\n\r?\n", raw, maxsplit=1)
            match = re.match(br"HTTP/\S+\s+(\d{3})", parts[0])
            if len(parts) != 2 or match is None:
                raise Refusal("provider transport returned no verifiable status")
            status = int(match.group(1))
            try:
                value = json.loads(parts[1]) if parts[1].strip() else None
            except (ValueError, UnicodeError) as exc:
                raise Refusal("provider JSON unavailable") from exc
        if status == 404 and allow_404:
            return None
        if not 200 <= status < 300:
            raise Refusal(f"provider operation refused ({status}); no paid fallback")
        return value

    def repository_info(self) -> dict:
        result = self.api(self.prefix)
        expected = self.config["repository"]
        if result.get("id") != expected["id"] or result.get("owner", {}).get("login", "").lower() != expected["owner"].lower() or result.get("name", "").lower() != expected["name"].lower() or result.get("private") is not False or result.get("visibility") != "public" or result.get("default_branch") != self.config["default_branch"]:
            raise Refusal("repository identity/public visibility/default branch changed")
        return result

    def workflow_bytes(self, commit: str) -> bytes:
        text(commit, COMMIT, "workflow commit")
        if commit in self._workflow_cache:
            return self._workflow_cache[commit]
        result = self.api(f"{self.prefix}/contents/{self.config['workflow_path']}?ref={commit}")
        if result.get("type") != "file" or result.get("encoding") != "base64" or integer(result.get("size"), 1, 128 * 1024, "workflow byte length") < 1:
            raise Refusal("installed workflow is unavailable")
        try:
            data = base64.b64decode(result["content"].replace("\n", ""), validate=True)
        except (ValueError, KeyError) as exc:
            raise Refusal("workflow encoding invalid") from exc
        if len(data) != result["size"] or digest(data) != self.config["workflow_sha256"]:
            raise Refusal("installed workflow integrity changed")
        self._workflow_cache[commit] = data
        return data

    def trusted_run(self, run_id: int, *, require_current: bool, run_attempt: int | None = None) -> dict:
        integer(run_id, 1, 2**63 - 1, "run id")
        if run_attempt is None and require_current and os.environ.get("GITHUB_RUN_ID") == str(run_id):
            run_attempt = integer(int(os.environ.get("GITHUB_RUN_ATTEMPT", "0")), 1, 10_000, "current run attempt")
        key = (run_id, run_attempt)
        cached = self._run_cache.get(key) if run_attempt is not None else None
        projected = json.loads(cached) if cached is not None else None
        if projected is None:
            suffix = "" if run_attempt is None else "/attempts/" + str(integer(run_attempt, 1, 10_000, "run attempt"))
            value = self.api(f"{self.prefix}/actions/runs/{run_id}{suffix}")
            projected = {"id": value.get("id"), "run_attempt": value.get("run_attempt"), "event": value.get("event"),
                         "head_sha": value.get("head_sha"), "head_branch": value.get("head_branch"), "path": value.get("path"),
                         "repository": {"id": value.get("repository", {}).get("id"), "owner": value.get("repository", {}).get("owner", {}).get("login"), "name": value.get("repository", {}).get("name")}}
            if run_attempt is not None and projected["run_attempt"] != run_attempt:
                raise Refusal("provider returned another run attempt")
        # Only immutable run-attempt fields and workflow-at-commit bytes are reused.
        # The mutable default branch ref is always freshly read for write fences.
        expected_head = projected["head_sha"]
        if require_current:
            ref = self.api(f"{self.prefix}/git/ref/heads/{self.config['default_branch']}")
            expected_head = ref.get("object", {}).get("sha")
        verified = verify_run(self.config, projected, expected_head, self.workflow_bytes(projected["head_sha"]))
        self._run_cache[(run_id, verified["run_attempt"])] = canonical(verified)
        return json.loads(canonical(verified))

    def pull(self, number: int) -> dict:
        item = self.api(f"{self.prefix}/pulls/{integer(number, 1, 2**31 - 1, 'PR number')}")
        return self.project_pull(item)

    def project_pull(self, item: dict) -> dict:
        if item.get("base", {}).get("repo", {}).get("id") != self.config["repository"]["id"]:
            raise Refusal("PR base repository differs from configured identity")
        return validate_pr({"number": item.get("number"), "repository": self.config["repository"],
                            "selected_baseline": item.get("base", {}).get("sha"), "proposal": item.get("head", {}).get("sha"),
                            "state": item.get("state"), "draft": item.get("draft"), "public": True, "consent": True}, self.config)

    def artifact_inventory(self, reserve: int) -> int:
        total, self.handoff_bytes = 0, 0
        for page in range(1, 11):
            result = self.api(f"{self.prefix}/actions/artifacts?per_page=100&page={page}")
            values = result.get("artifacts")
            if not isinstance(values, list) or len(values) > 100:
                raise Refusal("repository artifact inventory unavailable")
            for item in values:
                if item.get("expired") is not True:
                    total += integer(item.get("size_in_bytes"), 0, 2**63 - 1, "artifact bytes")
                    if str(item.get("name", "")).startswith("csb-public-handoff-"):
                        self.handoff_bytes += item["size_in_bytes"]
            if total + reserve > MAX_REPOSITORY_ARTIFACT_BYTES:
                raise Refusal("deferred: repository artifact reservation exceeds 172 MiB")
            if len(values) < 100:
                return total
        raise Refusal("artifact inventory truncated; upload refused")

    def restore_state(self) -> dict:
        # Bounded latest-record lookup. Invalid/newer records never cause a silent
        # fresh start; an ambiguous or overflowed history requires operator recovery.
        records = self.api(f"{self.prefix}/deployments?task={self.config['receipt']['task']}&environment={self.config['receipt']['environment']}&per_page=10")
        if not isinstance(records, list) or len(records) >= 10:
            raise Refusal("publication receipt discovery unavailable")
        if not records:
            return empty_state(self.config)
        verified = []
        for record in records:
            envelope = record.get("payload")
            if isinstance(envelope, str):
                try:
                    envelope = json.loads(envelope)
                except ValueError as exc:
                    raise Refusal("unverifiable receipt record; recovery required") from exc
            try:
                object_fields(envelope, {"schema_version", "subject", "subject_sha256", "verification_bundle"}, name="receipt envelope")
                if envelope["schema_version"] != "csb-public-receipt-envelope-v1" or len(canonical(envelope)) > MAX_PROOF_BYTES or digest(canonical(envelope["subject"])) != envelope["subject_sha256"]:
                    raise Refusal("unverifiable receipt record; recovery required")
                subject = envelope["subject"]
                receipt_key = digest(canonical(envelope))
                if receipt_key in self._receipt_cache:
                    encoded_state, commit = self._receipt_cache[receipt_key]
                    state = json.loads(encoded_state)
                    if record.get("sha") != commit:
                        raise Refusal("cached immutable receipt commit changed")
                    verified.append(validate_state(state, self.config))
                    continue
                object_fields(subject, {"schema_version", "kind", "state", "controller_sha", "workflow_sha256", "run_id", "run_attempt"}, name="receipt subject")
                if subject["schema_version"] != "csb-public-receipt-v1" or subject["workflow_sha256"] != self.config["workflow_sha256"]:
                    raise Refusal("unverifiable receipt record; recovery required")
                run = self.trusted_run(subject["run_id"], require_current=False, run_attempt=subject["run_attempt"])
                if subject["run_attempt"] != run["run_attempt"] or subject["controller_sha"] != run["head_sha"]:
                    raise Refusal("unverifiable receipt record; recovery required")
                verify_receipt_with_gh(self.config, subject, envelope["verification_bundle"], run)
                state = validate_state(subject["state"], self.config)
                if record.get("sha") != run["head_sha"]:
                    raise Refusal("unverifiable receipt record; recovery required")
                self._receipt_cache[receipt_key] = (canonical(state), run["head_sha"])
                verified.append(state)
            except (Refusal, KeyError, TypeError) as exc:
                raise Refusal("unverifiable receipt record; recovery required") from exc
        if not verified:
            raise Refusal("no verifiable receipt; never reset accepted state")
        verified.sort(key=lambda item: item["sequence"], reverse=True)
        if len(verified) > 1 and verified[0]["sequence"] == verified[1]["sequence"] and canonical(verified[0]) != canonical(verified[1]):
            raise Refusal("conflicting attested state sequence")
        if len(verified) > 1 and (verified[0]["sequence"] != verified[1]["sequence"] + 1 or verified[0]["previous_receipt_sha256"] != digest(canonical(verified[1]))):
            raise Refusal("retained receipt chain is ambiguous")
        return verified[0]


def github_plan(config: dict, trusted_root: Path, output: Path, *, provider: GitHub | None = None) -> dict:
    load_config(config, runtime=True)
    if config["operations"]["analysis"] is not True:
        raise Refusal("analysis activation is disabled")
    verify_installed_inputs(config, trusted_root)
    provider = provider or GitHub(config)
    provider.repository_info()
    run_id = integer(int(os.environ.get("GITHUB_RUN_ID", "0")), 1, 2**63 - 1, "workflow run id")
    run = provider.trusted_run(run_id, require_current=True)
    previous = provider.restore_state()
    if previous.get("promotion_intent") is not None:
        raise Refusal("indeterminate Pages promotion requires explicit recovery")
    now = datetime.now(timezone.utc)
    activated = budget_activation(config, trusted_root, previous, now)
    policy = read_json(trusted_root / config["policy_path"], MAX_CONFIG_BYTES)
    if policy.get("repository") != config["repository"] or policy.get("public") is not True or policy.get("publication_consent") is not True or policy.get("baseline_mode") not in ("exact", "merge_base"):
        raise Refusal("base-owned public scope policy unavailable")
    rate = provider.api("rate_limit").get("resources", {}).get("core", {})
    page = previous["discovery_page"]
    discovered = provider.api(f"{provider.prefix}/pulls?state=open&sort=created&direction=asc&per_page=80&page={page}")
    if not isinstance(discovered, list) or len(discovered) > 80:
        raise Refusal("bounded provider discovery failed")
    observations = {item["number"]: provider.project_pull(item) for item in discovered}
    known = {item["pr_number"] for item in previous["pending"] + previous["completed"]}
    maintenance_cursor = previous.get("maintenance_cursor", 0)
    maintenance = sorted(known, key=lambda number: (number <= maintenance_cursor, number))[:3]
    for number in maintenance:
        observations[number] = provider.pull(number)
        maintenance_cursor = number
    artifacts = provider.artifact_inventory(0)
    repository_slots = max(0, min(3, (MAX_REPOSITORY_ARTIFACT_BYTES - artifacts - MIB) // MAX_HANDOFF_BYTES))
    result = plan(config, previous, list(observations.values()), timestamp(now), existing_handoff_bytes=integer(provider.handoff_bytes, 0, MAX_HANDOFF_TOTAL, "handoff inventory"),
                  rate_remaining=integer(rate.get("remaining"), 0, 1_000_000, "rate remaining"), rate_limit=integer(rate.get("limit"), 1, 1_000_000, "rate limit"), admission_limit=repository_slots)
    result["state"]["discovery_page"] = page + 1 if len(discovered) == 80 else 1
    result["state"]["maintenance_cursor"] = maintenance_cursor
    result["state"]["budget_activation"] = activated
    acknowledge_delivered_checks(config, result["state"], provider, limit=3)
    result["repository_reservation"] = {"observed_bytes": artifacts, "handoff_bytes": result["handoff_reservation_bytes"], "control_bytes": MIB, "limit": MAX_REPOSITORY_ARTIFACT_BYTES}
    requests = []
    for pending in result["admitted"]:
        mode = policy["baseline_mode"]
        baseline = pending["selected_baseline"]
        if mode == "merge_base":
            comparison = provider.api(f"{provider.prefix}/compare/{pending['selected_baseline']}...{pending['proposal']}")
            baseline = text(comparison.get("merge_base_commit", {}).get("sha"), COMMIT, "provider merge base")
        requests.append(request_for(config, pending, run, baseline, timestamp(now), baseline_mode=mode))
    result["requests"] = requests
    result["previous_state"] = previous
    result["run"] = run
    result["provider_calls"] = provider.calls
    validate_state(result["state"], config)
    write_new_json(output, result, 512 * 1024)
    return result


def check_outcome(*, complete: bool = False, gaps: list | None = None, deferred: bool = False,
                  failure: bool = False, superseded: bool = False) -> str:
    if superseded:
        return "cancelled"
    if failure:
        return "failure"
    return "success" if complete and not gaps and not deferred else "neutral"


def review_verdict(coverage: dict, artifact: dict, changes: list | None = None) -> str:
    """Classify verified static evidence, never workflow success or runtime safety."""
    statuses = [artifact.get("hld_status"), artifact.get("lld_status")]
    observed = any(change.get("resolution") == "observed_structure" and change.get("kind") in ("call_observation_changed", "control_flow_changed", "return_changed", "error_flow_changed") for change in (changes or []))
    if "change_detected" in statuses or observed:
        return "change_detected"
    if (coverage.get("complete") is True and not coverage.get("gaps")
            and not coverage.get("deferred_details")
            and all(value == "no_change_detected_within_scope" for value in statuses)):
        return "no_change_detected"
    return "incomplete"


def verdict_conclusion(update: dict) -> str:
    if update["conclusion"] in ("failure", "cancelled"):
        return update["conclusion"]
    # Older durable records lack a verdict. They must not become a green claim.
    return "success" if update.get("verdict") == "no_change_detected" else "neutral"


def tree_inventory(root: Path, byte_cap: int, file_cap: int, *, entry_cap: int | None = None, allow_disappeared: bool = False) -> tuple[list[tuple[str, Path]], int]:
    if root.is_symlink() or not root.is_dir():
        raise Refusal("invalid input directory")
    result, total, entries = [], 0, 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            entries += 1
            if entries > (entry_cap if entry_cap is not None else file_cap * 2 + 16):
                raise Refusal("directory entry inventory exceeds budget")
            path = Path(directory) / name
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                if allow_disappeared:
                    continue
                raise
            if stat.S_ISLNK(metadata.st_mode) or not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)) or (stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1):
                raise Refusal("linked or special publication file")
        for name in files:
            path = Path(directory) / name
            rel = relative_path(path.relative_to(root).as_posix())
            try:
                size = path.stat().st_size
            except FileNotFoundError:
                if allow_disappeared:
                    continue
                raise
            total += size
            result.append((rel, path))
            if total > byte_cap or len(result) > file_cap:
                raise Refusal("directory inventory exceeds budget")
    return sorted(result), total


def validate_bundle(root: Path, request: dict | None = None) -> dict:
    files, _ = tree_inventory(root, MAX_BUNDLE_BYTES, 1000)
    manifest = read_json(root / "manifest.json", 1024 * 1024)
    required = {"schema_version", "review_id", "public_report_id", "analysis_review_id", "repository", "pr_number",
                "selected_baseline", "baseline", "proposal", "scope_version", "policy_digest", "engine", "files", "routes", "coverage", "capabilities"}
    object_fields(manifest, required, name="public manifest")
    if manifest["schema_version"] != "csb-public-report-v1":
        raise Refusal("unsupported public report schema")
    public_id = text(manifest["public_report_id"], SHA256, "public report id")
    if manifest["review_id"] != public_id:
        raise Refusal("public wrapper identity mismatch")
    repository(manifest["repository"])
    integer(manifest["pr_number"], 1, 2**31 - 1, "PR number")
    for key in ("selected_baseline", "baseline", "proposal"):
        text(manifest[key], COMMIT, key)
    text(manifest["policy_digest"], SHA256, "public policy digest")
    engine = object_fields(manifest["engine"], {"package", "version", "hld_generator", "lld_generator", "lld_parser", "public_projection"}, name="public engine")
    if engine["package"] != "flowdiff" or engine["public_projection"] != "csb-public-report-v1" or any(not isinstance(item, str) or not item or len(item) > 128 for item in engine.values()):
        raise Refusal("unsupported public engine profile")
    if request is not None and any(manifest[key] != request[key] for key in ("repository", "pr_number", "selected_baseline", "baseline", "proposal")):
        raise Refusal("public artifact comparison substitution")
    if not isinstance(manifest["files"], list) or len(manifest["files"]) > 999:
        raise Refusal("invalid public file allowlist")
    expected = {"manifest.json"}
    for entry in manifest["files"]:
        object_fields(entry, {"path", "sha256", "bytes", "kind"}, name="public file")
        rel = relative_path(entry["path"])
        if rel in expected or not isinstance(entry["kind"], str) or not rel.endswith((".json", ".md")):
            raise Refusal("duplicate or executable public file")
        expected.add(rel)
        size = integer(entry["bytes"], 0, MAX_BUNDLE_BYTES, "public file size")
        file_path = root / rel
        if not file_path.is_file() or file_path.is_symlink() or file_path.stat().st_size != size or digest(file_path.read_bytes()) != text(entry["sha256"], SHA256, "file hash"):
            raise Refusal("public file integrity failure")
    if {rel for rel, _ in files} != expected:
        raise Refusal("unexpected or missing public payload file")
    routes = object_fields(manifest["routes"], {"artifact", "hld", "lld_catalog", "lld_details", "sources", "file_sources", "exports"}, name="public routes")
    def route(path: Any) -> None:
        if relative_path(path) not in expected - {"manifest.json"}:
            raise Refusal("public route is not allowlisted")
    route(routes["artifact"])
    for key in ("hld", "lld_catalog"):
        if routes[key] is not None:
            route(routes[key])
    for key in ("lld_details", "sources"):
        if not isinstance(routes[key], list) or len(routes[key]) > 10_000:
            raise Refusal("invalid public binding table")
        for binding in routes[key]:
            object_fields(binding, {"entry", "parent_hld", "component", "baseline_entry", "correspondence_kind", "path"}, {"evidence"}, name="public binding")
            route(binding["path"])
    for key in ("file_sources", "exports"):
        if not isinstance(routes[key], list) or len(routes[key]) > 1000:
            raise Refusal("invalid public route table")
        for binding in routes[key]:
            object_fields(binding, {"file_path", "side", "parent_hld", "path"} if key == "file_sources" else {"view", "path"}, name="public source/export route")
            route(binding["path"])
            if key == "file_sources" and binding["side"] not in ("baseline", "proposal"):
                raise Refusal("invalid source side")
    identity = {key: value for key, value in manifest.items() if key not in ("review_id", "public_report_id")}
    if digest(canonical(identity)) != public_id:
        raise Refusal("public content root mismatch")
    coverage = object_fields(manifest["coverage"], {"complete", "gaps", "deferred_details"}, name="coverage")
    if not isinstance(coverage["complete"], bool) or not isinstance(coverage["gaps"], list):
        raise Refusal("invalid public coverage")
    integer(coverage["deferred_details"], 0, 100_000, "deferred detail count")
    caps = object_fields(manifest["capabilities"], {"hld", "lld", "source", "export", "confirmation"}, name="public capabilities")
    if caps.get("confirmation") is not False or any(not isinstance(value, bool) for value in caps.values()):
        raise Refusal("public report cannot expose confirmation")
    return manifest


def pack_handoff(root: Path, output: Path) -> str:
    validate_bundle(root)
    if output.exists() or output.is_symlink():
        raise Refusal("handoff output must be new")
    try:
        with output.open("xb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed, tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for rel, path in tree_inventory(root, MAX_BUNDLE_BYTES, 1000)[0]:
                info = archive.gettarinfo(str(path), arcname=rel)
                info.uid = info.gid = 0; info.uname = info.gname = ""; info.mtime = 0; info.mode = 0o644
                with path.open("rb") as source:
                    archive.addfile(info, source)
        if output.stat().st_size > MAX_REPORT_COMPRESSED:
            raise Refusal("compressed public report exceeds budget")
        return digest(output.read_bytes())
    except Exception:
        output.unlink(missing_ok=True)
        raise


def unpack_handoff(archive_path: Path, output: Path) -> dict:
    if archive_path.is_symlink() or not archive_path.is_file() or archive_path.stat().st_size > MAX_HANDOFF_BYTES:
        raise Refusal("handoff archive exceeds budget")
    if output.exists() or output.is_symlink():
        raise Refusal("extraction directory must be new")
    output.mkdir(parents=True)
    try:
        seen, total = set(), 0
        # Bound the entire tar stream before its parser can allocate an oversized
        # extended header. The public format never needs PAX/GNU extensions.
        with tempfile.TemporaryFile() as expanded:
            with gzip.open(archive_path, "rb") as compressed:
                data = compressed.read(MAX_BUNDLE_BYTES + 4 * MIB + 1)
            if len(data) > MAX_BUNDLE_BYTES + 4 * MIB:
                raise Refusal("compressed archive expansion exhausted")
            expanded.write(data); expanded.seek(0)
            archive = tarfile.open(fileobj=expanded, mode="r:")
            with archive:
                for member in archive:
                    rel = relative_path(member.name)
                    if not member.isfile() or member.islnk() or member.issym() or member.size < 0 or rel in seen or member.pax_headers:
                        raise Refusal("unsafe archive entry")
                    seen.add(rel); total += member.size
                    if len(seen) > 1000 or total > MAX_BUNDLE_BYTES:
                        raise Refusal("archive expansion exceeds budget")
                    target = output / rel
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    if source is None:
                        raise Refusal("missing archive file")
                    data = source.read(member.size + 1)
                    if len(data) != member.size:
                        raise Refusal("archive size mismatch")
                    with target.open("xb") as destination:
                        destination.write(data)
        return validate_bundle(output)
    except Exception:
        shutil.rmtree(output)
        raise


def receipt_subject(config: dict, previous: dict, state: dict, run: dict, *, kind: str) -> dict:
    validate_state(previous, config); validate_state(state, config)
    if kind not in ("cursor_only", "site_intent", "site_promotion") or state["sequence"] != previous["sequence"] + 1 or state["previous_receipt_sha256"] != digest(canonical(previous)):
        raise Refusal("invalid receipt sequence/chain")
    if state["consent_epoch"] < previous["consent_epoch"] or not set(previous["withdrawn"]) <= set(state["withdrawn"]):
        raise Refusal("withdrawal state cannot roll back")
    if previous.get("budget_activation") is not None and state.get("budget_activation") != previous["budget_activation"]:
        raise Refusal("existing budget activation cannot be silently replaced")
    if kind == "cursor_only" and any(state[key] != previous[key] for key in ("site_generation", "site_manifest_sha256", "pages_deployment_id")):
        raise Refusal("cursor receipt cannot promote a site")
    if kind == "cursor_only" and state.get("promotion_intent") != previous.get("promotion_intent"):
        raise Refusal("cursor receipt cannot alter a promotion intent")
    if kind == "site_intent":
        if previous.get("promotion_intent") is not None or state.get("promotion_intent") is None or any(state[key] != previous[key] for key in ("site_generation", "site_manifest_sha256", "pages_deployment_id")):
            raise Refusal("intent must preserve last-good site until readback")
    if kind == "site_promotion":
        intent = previous.get("promotion_intent")
        if intent is None or state["site_generation"] != previous["site_generation"] + 1 or state["site_manifest_sha256"] != intent["site_manifest_sha256"] or state.get("promotion_intent") is not None:
            raise Refusal("site promotion requires the exact previous attested intent")
    return {"schema_version": "csb-public-receipt-v1", "kind": kind, "state": state,
            "controller_sha": text(run["head_sha"], COMMIT, "controller SHA"),
            "workflow_sha256": config["workflow_sha256"], "run_id": run["id"], "run_attempt": run["run_attempt"]}


def deployment_payload(subject: dict, verification_bundle: dict) -> dict:
    # Store proof with the subject, independently of short-lived Actions artifacts.
    payload = {"schema_version": "csb-public-receipt-envelope-v1", "subject": subject,
               "subject_sha256": digest(canonical(subject)), "verification_bundle": verification_bundle}
    if len(canonical(payload)) > MAX_PROOF_BYTES:
        raise Refusal("unavailable: durable receipt proof exceeds finite storage contract")
    return payload


def verify_attestation(config: dict, subject: dict, verified: Any, *, expected_run: dict) -> None:
    """Consume ONLY successful cryptographic gh verification output, not raw claims."""
    if not isinstance(verified, list) or not verified:
        raise Refusal("missing cryptographically verified attestation")
    expected_digest = digest(canonical(subject))
    expected_invocation = f"https://github.com/{config['repository']['owner']}/{config['repository']['name']}/actions/runs/{expected_run['id']}/attempts/{expected_run['run_attempt']}"
    found = False
    for result in verified:
        verification = result.get("verificationResult", {}) if isinstance(result, dict) else {}
        certificate = verification.get("signature", {}).get("certificate", {})
        statement = verification.get("statement", {})
        subjects = statement.get("subject", [])
        if not isinstance(certificate, dict) or not isinstance(statement, dict):
            continue
        if certificate.get("sourceRepositoryIdentifier") != str(config["repository"]["id"]):
            continue
        expected_repository_uri = f"https://github.com/{config['repository']['owner']}/{config['repository']['name']}"
        if certificate.get("issuer") != "https://token.actions.githubusercontent.com" or certificate.get("sourceRepositoryURI") != expected_repository_uri or certificate.get("sourceRepositoryVisibilityAtSigning") != "public":
            continue
        if certificate.get("buildSignerURI") != expected_repository_uri + "/" + config["workflow_path"] + "@refs/heads/" + config["default_branch"] or certificate.get("buildSignerDigest") != expected_run["head_sha"]:
            continue
        if certificate.get("sourceRepositoryDigest") != expected_run["head_sha"] or certificate.get("sourceRepositoryRef") != "refs/heads/" + config["default_branch"]:
            continue
        # Run identity must be certificate-bound, never predicate-only.
        if certificate.get("runInvocationURI") != expected_invocation or certificate.get("runnerEnvironment") != "github-hosted":
            continue
        if statement.get("predicateType") != PREDICATE_TYPE or statement.get("predicate") != subject:
            continue
        if any(isinstance(item, dict) and item.get("digest", {}).get("sha256") == expected_digest for item in subjects):
            found = True
    if not found:
        raise Refusal("attestation signer/repository/ref/run/subject policy mismatch")


def verify_receipt_with_gh(config: dict, subject: dict, bundle: dict, expected_run: dict,
                           *, runner: Callable = subprocess.run) -> list:
    if len(canonical(bundle)) > MAX_PROOF_BYTES or len(canonical(subject)) > MAX_STATE_BYTES:
        raise Refusal("attestation input exceeds budget")
    with tempfile.TemporaryDirectory(prefix="csb-receipt-") as directory:
        root = Path(directory)
        subject_path, bundle_path = root / "receipt.json", root / "proof.json"
        subject_path.write_bytes(canonical(subject)); bundle_path.write_bytes(canonical(bundle))
        argv = ["gh", "attestation", "verify", str(subject_path), "--repo", f"{config['repository']['owner']}/{config['repository']['name']}",
                "--bundle", str(bundle_path), "--signer-workflow", config["receipt"]["signer_workflow"],
                "--signer-digest", expected_run["head_sha"], "--source-digest", expected_run["head_sha"],
                "--source-ref", "refs/heads/" + config["default_branch"], "--deny-self-hosted-runners",
                "--predicate-type", PREDICATE_TYPE, "--format", "json"]
        result = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=30)
        if result.returncode != 0 or len(result.stdout) > 2 * MIB:
            raise Refusal("receipt cryptographic verification failed/unavailable")
        try:
            verified = json.loads(result.stdout)
        except (ValueError, UnicodeError) as exc:
            raise Refusal("invalid attestation verification output") from exc
        verify_attestation(config, subject, verified, expected_run=expected_run)
        return verified


def clean_environment() -> dict:
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": "/nonexistent",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/usr/bin/false", "GIT_PAGER": "cat"}


def bounded_process(argv: list[str], *, timeout: float, env: dict | None = None,
                    watch_directory: Path | None = None, byte_cap: int = 256 * MIB,
                    entry_cap: int = 20_000, runner: Callable | None = None) -> bytes:
    if runner is not None:
        result = runner(argv, timeout=timeout, env=env or clean_environment())
        if result.returncode:
            raise Refusal("bounded subprocess failed")
        return result.stdout
    def limits() -> None:
        resource.setrlimit(resource.RLIMIT_AS, (512 * MIB, 512 * MIB))
        resource.setrlimit(resource.RLIMIT_CPU, (max(1, int(timeout) + 1), max(2, int(timeout) + 2)))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
        resource.setrlimit(resource.RLIMIT_FSIZE, (256 * MIB, 256 * MIB))
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(argv, stdout=stdout, stderr=stderr, env=env or clean_environment(), start_new_session=True,
                                   preexec_fn=limits if sys.platform == "linux" else None)
        started = time.monotonic()
        try:
            while process.poll() is None:
                if time.monotonic() - started > timeout:
                    raise Refusal("bounded subprocess deadline exhausted")
                if stdout.tell() + stderr.tell() > 1024 * 1024:
                    raise Refusal("bounded subprocess output exhausted")
                if watch_directory is not None and watch_directory.exists():
                    tree_inventory(watch_directory, byte_cap, entry_cap, entry_cap=entry_cap, allow_disappeared=True)
                time.sleep(0.05)
            if process.returncode:
                raise Refusal("bounded subprocess failed (details withheld)")
            if stdout.tell() + stderr.tell() > 1024 * 1024:
                raise Refusal("bounded subprocess output exhausted")
            stdout.seek(0)
            result = stdout.read(1024 * 1024 + 1)
            if len(result) > 1024 * 1024:
                raise Refusal("bounded subprocess output exhausted")
            if watch_directory is not None:
                tree_inventory(watch_directory, byte_cap, entry_cap, entry_cap=entry_cap)
            return result
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)


def fetch_public_objects(config: dict, request: dict, output: Path, *, runner: Callable | None = None) -> dict:
    validate_request(request, config)
    if output.exists() or output.is_symlink():
        raise Refusal("Git object mirror must be new")
    output.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    def call(args: list[str]) -> bytes:
        remaining = 60 - (time.monotonic() - started)
        if remaining <= 0:
            raise Refusal("Git object fetch deadline exhausted")
        return bounded_process(["git", "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=", "-c", "http.followRedirects=false",
                                "-c", "gc.auto=0", "-c", "maintenance.auto=false", "-c", "pack.threads=1",
                                "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never", *args],
                               timeout=remaining, watch_directory=output if output.exists() else None, runner=runner)
    try:
        with tempfile.TemporaryDirectory(prefix="csb-empty-template-") as template:
            call(["init", "--bare", "--template=" + template, str(output)])
        slug = f"{config['repository']['owner']}/{config['repository']['name']}"
        call(["-C", str(output), "fetch", "--depth=128", "--no-tags", "--no-recurse-submodules", "--no-write-fetch-head", "--quiet",
              "https://github.com/" + slug + ".git", request["selected_baseline"], request["proposal"]])
        for commit in (request["selected_baseline"], request["proposal"]):
            actual = call(["-C", str(output), "rev-parse", "--verify", commit + "^{commit}"]).decode().strip()
            if actual != commit:
                raise Refusal("Git object identity mismatch")
        merge_base = (call(["-C", str(output), "merge-base", request["selected_baseline"], request["proposal"]]).decode().strip()
                      if request["baseline_mode"] == "merge_base" else request["selected_baseline"])
        if merge_base != request["baseline"]:
            raise Refusal("bounded Git ancestry differs from pinned analysis baseline")
        return {"repository": config["repository"], "selected_baseline": request["selected_baseline"], "baseline": merge_base, "proposal": request["proposal"]}
    except Exception:
        if output.exists() and not output.is_symlink():
            shutil.rmtree(output)
        raise


def sandbox_argv(flowdiff: Path, exporter: Path, mirror: Path, policy: Path,
                 context: Path, output: Path, request: dict, *, export: bool = False) -> list[str]:
    if sys.platform != "linux" or shutil.which("bwrap") is None:
        raise Refusal("unavailable: credential-free network-isolated Linux sandbox is required")
    for path in (flowdiff, exporter, policy, context):
        if path.is_symlink() or not path.is_file():
            raise Refusal("sandbox trusted input is missing/linked")
    if mirror.is_symlink() or not mirror.is_dir() or output.is_symlink() or not output.is_dir():
        raise Refusal("sandbox data/output directory invalid")
    argv = ["bwrap", "--unshare-all", "--new-session", "--die-with-parent", "--clearenv",
            "--ro-bind", "/usr", "/usr", "--ro-bind-try", "/lib", "/lib", "--ro-bind-try", "/lib64", "/lib64",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/in", "--dir", "/engine",
            "--ro-bind", str(mirror.resolve()), "/in/repository", "--ro-bind", str(policy.resolve()), "/in/policy.json",
            "--ro-bind", str(context.resolve()), "/in/context.json", "--ro-bind", str(flowdiff.resolve()), "/engine/flowdiff",
            "--ro-bind", str(exporter.resolve()), "/engine/csb-public-report", "--bind", str(output.resolve()), "/out",
            "--chdir", "/out"]
    for key, value in clean_environment().items():
        argv += ["--setenv", key, "/tmp" if key == "HOME" else value]
    if export:
        return argv + ["/engine/csb-public-report", "--artifact", "/out/private.json", "--policy", "/in/policy.json", "--output", "/out/public",
                       "--repository-id", str(request["repository"]["id"]), "--repository", request["repository"]["owner"] + "/" + request["repository"]["name"],
                       "--pr-number", str(request["pr_number"]), "--selected-baseline", request["selected_baseline"], "--baseline", request["baseline"], "--proposal", request["proposal"]]
    return argv + ["/engine/flowdiff", "review", "--repo", "/in/repository", "--base", request["selected_baseline"], "--head", request["proposal"],
                   *(["--merge-base"] if request["baseline_mode"] == "merge_base" else []),
                   "--github-repository", request["repository"]["owner"] + "/" + request["repository"]["name"],
                   "--onboarding-context", "/in/context.json", "--internal-artifact", "--cache-dir", "/out/private-cache",
                   "--output", "/out/private.html", "--artifact", "/out/private.json"]


def analyze(config: dict, request: dict, trusted_root: Path, binary_directory: Path,
            mirror: Path, output: Path, *, runner: Callable | None = None) -> dict:
    validate_request(request, config); verify_installed_inputs(config, trusted_root)
    flowdiff, exporter = binary_directory / "flowdiff", binary_directory / "csb-public-report"
    for path, key in ((flowdiff, "flowdiff_sha256"), (exporter, "exporter_sha256")):
        if path.is_symlink() or not path.is_file() or digest(path.read_bytes()) != config["engine"][key]:
            raise Refusal("trusted native binary digest mismatch")
    if output.exists() or output.is_symlink():
        raise Refusal("analysis staging directory must be new")
    output.mkdir(parents=True)
    started = time.monotonic()
    try:
        for export in (False, True):
            remaining = min(120, 600 - (time.monotonic() - started))
            if remaining <= 0:
                raise Refusal("whole comparison deadline exhausted")
            argv = sandbox_argv(flowdiff, exporter, mirror, trusted_root / config["policy_path"], trusted_root / config["context_path"], output, request, export=export)
            bounded_process(argv, timeout=remaining, watch_directory=output, byte_cap=64 * MIB, entry_cap=20_000, runner=runner)
        manifest = validate_bundle(output / "public", request)
        return {"public_report_id": manifest["public_report_id"], "conclusion": check_outcome(complete=manifest["coverage"]["complete"], gaps=manifest["coverage"]["gaps"], deferred=bool(manifest["coverage"]["deferred_details"]))}
    finally:
        # No source-bearing private IR survives an analysis attempt.
        for name in ("private.json", "private.html", "private-cache"):
            path = output / name
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            elif path.exists() or path.is_symlink():
                path.unlink()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        raise Refusal("unexpected publication redirect")


def http_bytes(url: str, cap: int, *, timeout: float = 10) -> bytes:
    opener = urllib.request.build_opener(NoRedirect)
    request = urllib.request.Request(url, headers={"Accept": "application/json", "Cache-Control": "no-cache"})
    with opener.open(request, timeout=timeout) as response:
        if response.status != 200:
            raise Refusal("published snapshot is unavailable")
        value = response.read(cap + 1)
    if len(value) > cap:
        raise Refusal("published response exceeds expected byte budget")
    return value


def restore_public_site(config: dict, state: dict, output: Path, *, get: Callable = http_bytes) -> Path | None:
    """Restore only exact digest-pinned inert bytes, including the live-state fence."""
    url = config["site"]["origin"] + config["site"]["base_path"]
    if state["site_generation"] == 0:
        try:
            get(url + "site-manifest.json", 4 * MIB)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise Refusal("initial Pages state cannot be established") from exc
        raise Refusal("existing/indeterminate site cannot be overwritten without a trusted receipt")
    if output.exists() or output.is_symlink():
        raise Refusal("restore output must be new")
    data = get(url + "site-manifest.json", 4 * MIB)
    if digest(data) != state["site_manifest_sha256"]:
        raise Refusal("indeterminate live Pages generation; promotion refused")
    try:
        manifest = json.loads(data)
    except (ValueError, UnicodeError) as exc:
        raise Refusal("published manifest invalid") from exc
    object_fields(manifest, {"schema_version", "observed_at", "files"}, name="site manifest")
    if manifest["schema_version"] != "csb-public-site-v1" or not isinstance(manifest["files"], list) or len(manifest["files"]) > 20_000:
        raise Refusal("unsupported/bounded site manifest required")
    output.mkdir(parents=True)
    total, seen = len(data), {"site-manifest.json"}
    started = time.monotonic()
    try:
        (output / "site-manifest.json").write_bytes(data)
        for item in manifest["files"]:
            object_fields(item, {"path", "bytes", "sha256"}, name="site file")
            rel = relative_path(item["path"])
            if rel in seen:
                raise Refusal("duplicate restored site file")
            seen.add(rel)
            size = integer(item["bytes"], 0, MAX_SITE_BYTES, "site file byte length")
            total += size
            if total > MAX_SITE_BYTES or time.monotonic() - started > 120:
                raise Refusal("site restore deadline/byte budget exhausted")
            value = get(url + rel, size)
            if len(value) != size or digest(value) != text(item["sha256"], SHA256, "site file digest"):
                raise Refusal("restored site content mismatch")
            destination = output / rel; destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as target:
                target.write(value)
        import public_site
        public_site.verify_site(output, state["site_manifest_sha256"])
        return output
    except Exception:
        shutil.rmtree(output)
        raise


def upload_preflight(config: dict, trusted_root: Path, reserve: int, *, provider: GitHub | None = None) -> dict:
    load_config(config, runtime=True)
    if config["operations"]["publication"] is not True:
        raise Refusal("public uploads/publication have not been activated")
    verify_installed_inputs(config, trusted_root)
    provider = provider or GitHub(config)
    provider.repository_info()
    state = provider.restore_state()
    activation = budget_activation(config, trusted_root, state, datetime.now(timezone.utc))
    used = provider.artifact_inventory(integer(reserve, 0, MAX_SITE_ARCHIVE, "upload reservation"))
    return {"repository_bytes": used, "reserved_bytes": reserve,
            "repository_byte_limit": MAX_REPOSITORY_ARTIFACT_BYTES,
            "budget_activation": activation, "current_account_controls": "unobserved",
            "operating_precondition": "Owner maintains enforced Actions and Packages USD 0 hardstops"}


def run_analysis_request(config: dict, request: dict, trusted_root: Path, binaries: Path, output: Path,
                         *, mirror: Path | None = None, offline: bool = False, provider: GitHub | None = None) -> dict:
    validate_request(request, config)
    if output.exists() or output.is_symlink():
        raise Refusal("analysis handoff directory must be new")
    output.mkdir(parents=True)
    result = {"schema_version": "csb-public-analysis-result-v1", "request": request,
              "public_report_id": None, "archive_sha256": None, "conclusion": "failure", "reason": "analysis_unavailable"}
    if not offline:
        load_config(config, runtime=True)
        if not config["operations"]["analysis"]:
            raise Refusal("analysis activation is disabled")
        provider = provider or GitHub(config)
        provider.repository_info(); current_fence(config, request, provider.pull(request["pr_number"]))
        if str(request["run_id"]) != os.environ.get("GITHUB_RUN_ID") or str(request["run_attempt"]) != os.environ.get("GITHUB_RUN_ATTEMPT"):
            raise Refusal("request does not belong to this trusted workflow attempt")
    elif mirror is None:
        raise Refusal("offline analysis requires an explicit local object mirror")
    with tempfile.TemporaryDirectory(prefix="csb-analysis-") as temporary:
        temporary_root = Path(temporary)
        try:
            if mirror is None:
                mirror = temporary_root / "objects"
                fetch_public_objects(config, request, mirror)
            value = analyze(config, request, trusted_root, binaries, mirror, temporary_root / "worker")
            archive_sha = pack_handoff(temporary_root / "worker/public", output / "handoff.tar.gz")
            if provider is not None:
                provider.repository_info(); current_fence(config, request, provider.pull(request["pr_number"]))
            result.update(public_report_id=value["public_report_id"], archive_sha256=archive_sha, conclusion=value["conclusion"], reason="")
        except Refusal as exc:
            if str(exc).startswith("superseded"):
                result["conclusion"], result["reason"] = "cancelled", "superseded"
            (output / "handoff.tar.gz").unlink(missing_ok=True)
    write_new_json(output / "result.json", result, 32 * 1024)
    return result


def validate_analysis_result(value: Any, config: dict, requests: dict[str, dict]) -> dict:
    object_fields(value, {"schema_version", "request", "public_report_id", "archive_sha256", "conclusion", "reason"}, name="analysis result")
    request = validate_request(value["request"], config)
    if value["schema_version"] != "csb-public-analysis-result-v1" or requests.get(request["request_id"]) != request:
        raise Refusal("analysis result is not from this controller plan")
    if value["conclusion"] not in ("success", "neutral", "failure", "cancelled") or value["reason"] not in ("", "analysis_unavailable", "superseded"):
        raise Refusal("invalid analysis result state")
    if value["conclusion"] in ("success", "neutral"):
        text(value["public_report_id"], SHA256, "public result id")
        text(value["archive_sha256"], SHA256, "handoff digest")
    elif value["public_report_id"] is not None or value["archive_sha256"] is not None:
        raise Refusal("failed analysis cannot advertise a source-bearing handoff")
    return value


def queue_checks(config: dict, plan_value: dict, provider: GitHub) -> list[dict]:
    if not config["operations"]["checks"] or not provider.allow_writes:
        raise Refusal("check writes have not been activated")
    provider.repository_info()
    durable = provider.restore_state()
    accepted = {item["request"]["request_id"] for item in durable.get("check_updates", [])}
    if any(item.get("request_id") not in accepted for item in plan_value["requests"]):
        raise Refusal("custom Architecture checks require a committed durable request")
    checks = []
    for request in plan_value["requests"]:
        validate_request(request, config); current_fence(config, request, provider.pull(request["pr_number"]))
        external_id = "csb-public-v1:" + request["request_id"]
        existing = provider.api(f"{provider.prefix}/commits/{request['proposal']}/check-runs?check_name=CodeShouldBehave%20%2F%20Architecture&per_page=100")
        matches = [item for item in existing.get("check_runs", []) if item.get("external_id") == external_id and item.get("app", {}).get("slug") == "github-actions"]
        if len(matches) > 1:
            raise Refusal("ambiguous Architecture check identity")
        if matches:
            check_id = integer(matches[0]["id"], 1, 2**63 - 1, "check id")
        else:
            created = provider.api(provider.prefix + "/check-runs", method="POST", body={"name": "CodeShouldBehave / Architecture", "head_sha": request["proposal"], "external_id": external_id, "status": "queued",
                           "output": {"title": "Queued · Architecture review", "summary": "Exact public comparison accepted. Static coverage is not available yet; this advisory check does not approve merging."}})
            check_id = integer(created.get("id"), 1, 2**63 - 1, "check id")
        provider.api(f"{provider.prefix}/check-runs/{check_id}", method="PATCH", body={"status": "in_progress", "started_at": timestamp(), "output": {"title": "Running · Analyzing HLD and LLD", "summary": "The trusted controller is preparing the pinned comparison. HLD/LLD coverage will be reported independently of workflow success."}})
        checks.append({"request_id": request["request_id"], "check_id": check_id, "proposal": request["proposal"]})
    return checks


def acknowledge_delivered_checks(config: dict, state: dict, provider: GitHub, *, limit: int = 3) -> None:
    """Forget delivery only in the next signed state after exact provider readback."""
    acknowledged = set()
    for update in state.get("check_updates", [])[:limit]:
        request = validate_ledger_request(update["request"], config)
        value = provider.api(f"{provider.prefix}/commits/{request['proposal']}/check-runs?check_name=CodeShouldBehave%20%2F%20Architecture&per_page=100")
        runs = value.get("check_runs")
        if not isinstance(runs, list) or len(runs) >= 100:
            raise Refusal("check delivery readback unavailable or truncated")
        expected_url = None if update["public_report_id"] is None else config["site"]["origin"] + config["site"]["base_path"] + "workspace/#review=" + update["public_report_id"] + "&bundle=" + update["public_report_id"] + "&layout=architecture&side=diff&design=lld&mode=focus"
        matches = [item for item in runs if item.get("app", {}).get("slug") == "github-actions" and item.get("external_id") == "csb-public-v1:" + request["request_id"] and item.get("head_sha") == request["proposal"]]
        if len(matches) > 1:
            raise Refusal("ambiguous delivered check")
        if matches and matches[0].get("status") == "completed" and matches[0].get("conclusion") in (verdict_conclusion(update), "cancelled") and (expected_url is None or matches[0].get("details_url") == expected_url):
            acknowledged.add(request["request_id"])
    state["check_updates"] = [item for item in state.get("check_updates", []) if item["request"]["request_id"] not in acknowledged]


def repair_checks(config: dict, *, provider: GitHub, state: dict | None = None) -> dict:
    """Retry at most six exact-head updates from verified durable state.

    Acknowledgements are only removed by the next attested cursor/site state.
    A crash before that commit repeats an idempotent PATCH, never loses work.
    """
    if not config["operations"]["checks"] or not provider.allow_writes:
        raise Refusal("check writes have not been activated")
    provider.repository_info()
    verified = provider.restore_state()
    if state is not None and canonical(state) != canonical(verified):
        raise Refusal("check repair state changed")
    acknowledged = []
    for update in verified.get("check_updates", [])[:6]:
        request = validate_ledger_request(update["request"], config)
        fresh = provider.pull(request["pr_number"])
        conclusion = verdict_conclusion(update)
        try:
            validate_request(request, config)
            current_fence(config, request, fresh)
        except Refusal:
            conclusion = "cancelled"
        external_id = "csb-public-v1:" + request["request_id"]
        response = provider.api(f"{provider.prefix}/commits/{request['proposal']}/check-runs?check_name=CodeShouldBehave%20%2F%20Architecture&per_page=100")
        values = response.get("check_runs")
        if not isinstance(values, list) or len(values) >= 100:
            raise Refusal("check discovery unavailable or truncated")
        matches = [item for item in values if item.get("external_id") == external_id and item.get("head_sha") == request["proposal"] and item.get("app", {}).get("slug") == "github-actions"]
        if len(matches) > 1:
            raise Refusal("ambiguous exact-head check repair")
        title = {"success": "Ready · No detected change", "neutral": "Incomplete · Review required", "failure": "Failed · Analysis unavailable", "cancelled": "Superseded · New comparison required"}[conclusion]
        if conclusion == "neutral" and update.get("verdict") == "change_detected":
            title = "Ready · Changes to review"
        output = {"title": title, "summary": (
            "Static evidence within selected scope; runtime effects require review. "
            "This check does not approve merging.\n\n"
            + ("A newer PR head, scope or engine requires another comparison. Any linked report is historical, not the current PR result." if conclusion == "cancelled" else
               "No verified report is available. Check the workflow logs and retry analysis; this is not a no-change result." if conclusion == "failure" or update["public_report_id"] is None else
               "Open Details for Architecture, HLD, LLD and exact source differences. Coverage gaps remain visible in the report.")
            + f"\n\nBaseline: `{request['baseline']}` → Proposal: `{request['proposal']}`")}
        body = {"status": "completed", "conclusion": conclusion, "completed_at": timestamp(), "output": output}
        if update["public_report_id"] is not None:
            body["details_url"] = config["site"]["origin"] + config["site"]["base_path"] + "workspace/#review=" + update["public_report_id"] + "&bundle=" + update["public_report_id"] + "&layout=architecture&side=diff&design=lld&mode=focus"
        if matches:
            check_id = integer(matches[0]["id"], 1, 2**63 - 1, "repair check id")
            provider.api(f"{provider.prefix}/check-runs/{check_id}", method="PATCH", body=body)
        else:
            # A failed queued-check write must not prevent durable completion.
            body.update(name="CodeShouldBehave / Architecture", head_sha=request["proposal"], external_id=external_id)
            provider.api(provider.prefix + "/check-runs", method="POST", body=body)
        acknowledged.append(request["request_id"])
    return {"schema_version": "csb-public-check-acks-v1", "state_sha256": digest(canonical(verified)), "acked": acknowledged}


def cleanup_receipts(config: dict, *, provider: GitHub) -> dict:
    """Retain two verified receipt checkpoints, never delete an unverified record."""
    if not config["operations"]["publication"] or not provider.allow_writes:
        raise Refusal("receipt cleanup writes have not been activated")
    provider.repository_info()
    current = provider.restore_state()
    records = provider.api(f"{provider.prefix}/deployments?task={config['receipt']['task']}&environment={config['receipt']['environment']}&per_page=10")
    if not isinstance(records, list) or len(records) >= 10:
        raise Refusal("receipt cleanup inventory unavailable")
    verified = []
    for record in records:
        envelope = record.get("payload")
        if isinstance(envelope, str):
            try:
                envelope = json.loads(envelope)
            except ValueError as exc:
                raise Refusal("unverified receipt record requires operator recovery") from exc
        object_fields(envelope, {"schema_version", "subject", "subject_sha256", "verification_bundle"}, name="cleanup envelope")
        if envelope["schema_version"] != "csb-public-receipt-envelope-v1" or len(canonical(envelope)) > MAX_PROOF_BYTES or digest(canonical(envelope["subject"])) != envelope["subject_sha256"]:
            raise Refusal("unverified receipt record requires operator recovery")
        subject = envelope["subject"]
        run = provider.trusted_run(subject["run_id"], require_current=False, run_attempt=subject["run_attempt"])
        verify_receipt_with_gh(config, subject, envelope["verification_bundle"], run)
        state = validate_state(subject["state"], config)
        if subject["controller_sha"] != run["head_sha"] or subject["workflow_sha256"] != config["workflow_sha256"] or subject["run_attempt"] != run["run_attempt"] or record.get("sha") != run["head_sha"]:
            raise Refusal("receipt cleanup provenance differs")
        verified.append((state["sequence"], integer(record.get("id"), 1, 2**63 - 1, "receipt record")))
    verified.sort(reverse=True)
    if not verified or verified[0][0] != current["sequence"] or len({sequence for sequence, _ in verified}) != len(verified):
        raise Refusal("ambiguous cleanup checkpoint")
    removed = []
    for _, record_id in verified[2:]:
        provider.api(f"{provider.prefix}/deployments/{record_id}/statuses", method="POST", body={"state": "inactive", "auto_inactive": False})
        provider.api(f"{provider.prefix}/deployments/{record_id}", method="DELETE")
        removed.append(record_id)
    return {"retained_receipts": min(2, len(verified)), "removed_receipts": removed}


def cleanup_artifacts(config: dict, *, provider: GitHub, pre_upload: bool = False) -> dict:
    """Delete only controller-owned artifacts under a verified checkpoint.

    Before another upload, retain the exact last-good Pages artifact; afterward
    retain it and the prior snapshot. Current-run handoffs/control data survive
    preflight, but are removed only after the final receipt is committed.
    """
    if not config["operations"]["publication"] or not provider.allow_writes:
        raise Refusal("artifact cleanup writes have not been activated")
    provider.repository_info()
    state = provider.restore_state()
    if state.get("promotion_intent") is not None:
        raise Refusal("indeterminate promotion blocks artifact cleanup")
    inventory = provider.api(f"{provider.prefix}/actions/artifacts?per_page=100&page=1")
    values = inventory.get("artifacts")
    if not isinstance(values, list) or len(values) >= 100:
        raise Refusal("cleanup artifact inventory truncated")
    candidates, runs = [], {}
    current_run = integer(int(os.environ.get("GITHUB_RUN_ID", "0")), 1, 2**63 - 1, "cleanup current run")
    if state["site_generation"] and state.get("site_artifact_id") is None:
        raise Refusal("last-good artifact identity unavailable; do not guess")
    for item in values:
        if item.get("expired") is not False or not re.fullmatch(r"csb-public-(?:pages-[0-9]+-[0-9]+|handoff-[0-9a-f]{64}|plan-[0-9]+-[0-9]+|checks-[0-9]+-[0-9]+)", str(item.get("name", ""))):
            continue
        run_id = item.get("workflow_run", {}).get("id")
        if not isinstance(run_id, int):
            raise Refusal("cleanup artifact run missing")
        if run_id not in runs:
            runs[run_id] = provider.trusted_run(run_id, require_current=False)
        if item.get("workflow_run", {}).get("head_sha") != runs[run_id]["head_sha"]:
            raise Refusal("cleanup artifact source changed")
        candidates.append((run_id, integer(item.get("id"), 1, 2**63 - 1, "artifact id"), item["name"]))
    protected = {state.get("site_artifact_id")}
    if not pre_upload:
        protected.add(state.get("previous_site_artifact_id"))
    protected.discard(None)
    removed = []
    for run_id, artifact_id, name in candidates:
        active_control = pre_upload and run_id == current_run and not name.startswith("csb-public-pages-")
        if artifact_id not in protected and not active_control and run_id <= current_run:
            provider.api(f"{provider.prefix}/actions/artifacts/{artifact_id}", method="DELETE")
            removed.append(artifact_id)
    return {"removed_artifacts": removed, "protected_site_artifacts": sorted(protected)}


def public_policy_digest(config: dict, trusted_root: Path) -> str:
    path = trusted_root / relative_path(config["policy_path"])
    policy = read_json(path, MAX_CONFIG_BYTES)
    if digest(path.read_bytes()) != config["policy_sha256"]:
        raise Refusal("current base-owned public policy changed")
    object_fields(policy, {"schema_version", "repository", "public", "publication_consent", "include", "exclude", "baseline_mode", "max_details"}, name="public policy")
    if policy["schema_version"] != "csb-public-policy-v1" or policy["repository"] != config["repository"] or policy["public"] is not True or policy["publication_consent"] is not True or policy["baseline_mode"] not in ("exact", "merge_base"):
        raise Refusal("explicit current public policy/consent required")
    integer(policy["max_details"], 0, 100, "public detail limit")
    for key in ("include", "exclude"):
        paths = policy[key]
        if not isinstance(paths, list) or len(paths) > 100 or (key == "include" and not paths):
            raise Refusal("bounded nonempty public include scope required")
        for item in paths:
            if item != ".":
                relative_path(item)
        if len(set(paths)) != len(paths):
            raise Refusal("duplicate public policy path")
        policy[key] = sorted(paths)
    return digest(canonical(policy))


def stage_publication(config: dict, plan_value: dict, handoffs: Path, output: Path, *,
                      provider: GitHub, project_root: Path, trusted_root: Path, verifier: Path, check_acks: dict | None = None, get: Callable = http_bytes) -> dict:
    if not config["operations"]["publication"]:
        raise Refusal("publication activation is disabled")
    provider.repository_info()
    trusted = provider.trusted_run(plan_value["run"]["id"], require_current=True)
    if trusted != plan_value["run"]:
        raise Refusal("publisher plan run differs from current trusted controller")
    previous = provider.restore_state()
    if canonical(previous) != canonical(plan_value["previous_state"]) or previous.get("promotion_intent") is not None:
        raise Refusal("publisher state changed/indeterminate; replan instead of overwriting")
    if output.exists() or output.is_symlink():
        raise Refusal("publication staging must be new")
    output.mkdir(parents=True)
    state = validate_state(plan_value["state"], config)
    if check_acks is not None:
        object_fields(check_acks, {"schema_version", "state_sha256", "acked"}, name="check acknowledgements")
        if check_acks["schema_version"] != "csb-public-check-acks-v1" or check_acks["state_sha256"] != digest(canonical(previous)) or not isinstance(check_acks["acked"], list) or len(check_acks["acked"]) > 6:
            raise Refusal("check acknowledgement state differs")
        available = {item["request"]["request_id"] for item in previous.get("check_updates", [])}
        if len(set(check_acks["acked"])) != len(check_acks["acked"]) or not set(check_acks["acked"]) <= available:
            raise Refusal("unknown check acknowledgement")
        state["check_updates"] = [item for item in state.get("check_updates", []) if item["request"]["request_id"] not in check_acks["acked"]]
    requests = {item["request_id"]: validate_request(item, config) for item in plan_value["requests"]}
    for request in requests.values():
        pending = next((item for item in state["pending"] if item["pr_number"] == request["pr_number"]), None)
        if pending is None or pending["proposal"] != request["proposal"] or pending["selected_baseline"] != request["selected_baseline"] or pending["comparison_key"] != comparison_key(config, pending) or request["controller_sha"] != trusted["head_sha"] or request["run_id"] != trusted["id"] or request["run_attempt"] != trusted["run_attempt"]:
            raise Refusal("publication request differs from its planned exact comparison")
    results, bundles, observations = [], [], []
    expected_policy = public_policy_digest(config, trusted_root)
    restored = restore_public_site(config, previous, output / "previous", get=get)
    if restored is not None:
        old_index = read_json(restored / "index.json", MAX_SITE_BYTES)
        for record in old_index.get("reports", []):
            public_id = text(record.get("public_report_id"), SHA256, "restored report id")
            old_manifest = read_json(restored / "reviews" / public_id / "manifest.json", MIB)
            if old_manifest.get("policy_digest") != expected_policy and public_id not in state["withdrawn"]:
                state["withdrawn"].append(public_id)
                state["consent_epoch"] += 1
        validate_state(state, config)
    for request_id, request in requests.items():
        directory = handoffs / ("csb-public-handoff-" + request_id)
        if not directory.exists():
            result = {"schema_version": "csb-public-analysis-result-v1", "request": request, "public_report_id": None, "archive_sha256": None, "conclusion": "failure", "reason": "analysis_unavailable"}
        else:
            result = validate_analysis_result(read_json(directory / "result.json", 32 * 1024), config, requests)
        fresh = provider.pull(request["pr_number"])
        observations.append({"repository_id": config["repository"]["id"], "pr_number": fresh["number"], "state": "draft" if fresh["draft"] and fresh["state"] == "open" else fresh["state"], "head": fresh["proposal"], "base": fresh["selected_baseline"], "observed_at": timestamp()})
        try:
            current_fence(config, request, fresh)
        except Refusal:
            result = dict(result, public_report_id=None, archive_sha256=None, conclusion="cancelled", reason="superseded")
        if result["public_report_id"] is not None:
            archive = directory / "handoff.tar.gz"
            if archive.is_symlink() or not archive.is_file() or archive.stat().st_size > MAX_REPORT_COMPRESSED or digest(archive.read_bytes()) != result["archive_sha256"]:
                raise Refusal("trusted handoff content/digest mismatch")
            bundle_root = output / "bundles" / request_id
            manifest = unpack_handoff(archive, bundle_root)
            validate_bundle(bundle_root, request)
            if manifest["policy_digest"] != expected_policy:
                raise Refusal("public handoff scope differs from current base-owned policy")
            if manifest["public_report_id"] != result["public_report_id"]:
                raise Refusal("result/bundle immutable identity differs")
            artifact = read_json(bundle_root / manifest["routes"]["artifact"], MAX_BUNDLE_BYTES)
            catalog = read_json(bundle_root / manifest["routes"]["lld_catalog"], MAX_BUNDLE_BYTES) if manifest["routes"]["lld_catalog"] else {}
            verdict = review_verdict(manifest["coverage"], artifact, catalog.get("delta", {}).get("changes", []))
            result = dict(result, verdict=verdict, conclusion="success" if verdict == "no_change_detected" else "neutral")
            bundles.append(bundle_root)
        outcome = "published" if result["public_report_id"] is not None else "cancelled" if result["conclusion"] == "cancelled" else "transient"
        state = finish_head(state, request["pr_number"], request["proposal"], outcome, result["reason"])
        results.append(result)
        if config["operations"]["checks"]:
            updates = [item for item in state.get("check_updates", []) if item["request"]["request_id"] != request_id]
            updates.append({key: result[key] for key in ("request", "public_report_id", "conclusion", "reason")})
            if "verdict" in result:
                updates[-1]["verdict"] = result["verdict"]
            state["check_updates"] = updates
            validate_state(state, config)  # Never truncate repair work on capacity pressure.
    metadata = None
    if bundles or (restored is not None and state["withdrawn"] != previous["withdrawn"]):
        import public_site
        metadata = public_site.assemble_site(bundles, output / "site", timestamp(), previous=restored,
                                              previous_sha256=previous["site_manifest_sha256"] if restored else None,
                                              withdrawn=state["withdrawn"], project_root=project_root, observations=observations,
                                              verifier=verifier, verifier_sha256=config["engine"]["exporter_sha256"])
    staged = {"schema_version": "csb-public-publication-v1", "previous_state": previous, "state": state,
              "run": plan_value["run"], "results": results, "site": metadata}
    write_new_json(output / "publication.json", staged, 512 * 1024)
    return staged


def begin_promotion(config: dict, publication: dict, artifact_id: int, *, now: str) -> dict:
    previous = publication["previous_state"]
    state = json.loads(canonical(previous))
    state["sequence"] += 1; state["previous_receipt_sha256"] = digest(canonical(previous))
    state["budget_activation"] = publication["state"]["budget_activation"]
    state["promotion_intent"] = {"site_generation": previous["site_generation"] + 1,
                                 "site_manifest_sha256": publication["site"]["site_sha256"],
                                 "artifact_id": integer(artifact_id, 1, 2**63 - 1, "site artifact"),
                                 "pages_build_version": f"csb-{publication['run']['id']}-{publication['run']['run_attempt']}-{previous['site_generation'] + 1}",
                                 "run_id": publication["run"]["id"], "run_attempt": publication["run"]["run_attempt"], "created_at": now}
    return receipt_subject(config, previous, state, publication["run"], kind="site_intent")


def commit_receipt(config: dict, subject: dict, proof: dict, *, provider: GitHub) -> dict:
    if not config["operations"]["publication"] or not provider.allow_writes:
        raise Refusal("receipt writes have not been activated")
    provider.repository_info()
    previous = provider.restore_state()
    state = validate_state(subject["state"], config)
    if state["previous_receipt_sha256"] != digest(canonical(previous)) or state["sequence"] != previous["sequence"] + 1:
        raise Refusal("newer receipt already exists; stale commit refused")
    run = provider.trusted_run(subject["run_id"], require_current=True)
    expected = receipt_subject(config, previous, state, run, kind=subject["kind"])
    if expected != subject:
        raise Refusal("receipt subject differs from trusted transition")
    verify_receipt_with_gh(config, subject, proof, run)
    payload = deployment_payload(subject, proof)
    created = provider.api(provider.prefix + "/deployments", method="POST", body={"ref": run["head_sha"], "task": config["receipt"]["task"], "environment": config["receipt"]["environment"], "auto_merge": False, "required_contexts": [], "production_environment": False, "transient_environment": True, "payload": payload})
    record_id = integer(created.get("id"), 1, 2**63 - 1, "state Deployment id")
    if created.get("payload") != payload or created.get("sha") != run["head_sha"]:
        raise Refusal("provider did not retain exact durable attested receipt")
    provider.api(f"{provider.prefix}/deployments/{record_id}/statuses", method="POST", body={"state": "success", "auto_inactive": False, "description": "Verified bounded public-ci-v1 state receipt"})
    return {"state_deployment_id": record_id, "sequence": state["sequence"], "subject_sha256": digest(canonical(subject))}


def github_oidc_token() -> str:
    url, token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"), os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    parsed = urllib.parse.urlsplit(url or "")
    if parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.endswith(".actions.githubusercontent.com") or parsed.username or parsed.password or not token:
        raise Refusal("trusted GitHub Actions OIDC broker is unavailable")
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=15) as response:
        value = response.read(32 * 1024 + 1)
    if len(value) > 32 * 1024:
        raise Refusal("OIDC response exceeds budget")
    result = json.loads(value)
    jwt = result.get("value")
    if not isinstance(jwt, str) or len(jwt) > 16 * 1024 or len(jwt.split(".")) != 3:
        raise Refusal("invalid OIDC broker response")
    return jwt


def deploy_pages(config: dict, intent_subject: dict, *, provider: GitHub, token: Callable = github_oidc_token,
                 sleep: Callable = time.sleep) -> dict:
    if not config["operations"]["publication"] or not provider.allow_writes:
        raise Refusal("Pages writes have not been activated")
    provider.repository_info()
    current = provider.restore_state()
    if canonical(current) != canonical(intent_subject["state"]) or current.get("promotion_intent") is None:
        raise Refusal("Pages requires the exact committed attested intent")
    intent = current["promotion_intent"]
    artifact = provider.api(f"{provider.prefix}/actions/artifacts/{intent['artifact_id']}")
    if artifact.get("workflow_run", {}).get("id") != intent["run_id"] or artifact.get("workflow_run", {}).get("head_sha") != intent_subject["controller_sha"] or artifact.get("expired") is not False or artifact.get("name") != f"csb-public-pages-{intent['run_id']}-{intent['run_attempt']}" or integer(artifact.get("size_in_bytes"), 1, MAX_SITE_ARCHIVE, "Pages artifact bytes") > MAX_SITE_ARCHIVE:
        raise Refusal("Pages artifact is not from this trusted publisher run")
    value = provider.api(provider.prefix + "/pages/deployments", method="POST", body={"artifact_id": intent["artifact_id"], "pages_build_version": intent["pages_build_version"], "environment": "github-pages", "oidc_token": token()})
    deployment_id = text(value.get("id"), PAGES_ID, "actual Pages deployment id")
    for _ in range(30):
        status = provider.api(f"{provider.prefix}/pages/deployments/{deployment_id}")
        if status.get("status") == "succeed":
            return {"pages_deployment_id": deployment_id, "site_sha256": intent["site_manifest_sha256"], "status": "succeed"}
        if status.get("status") in ("deployment_failed", "deployment_content_failed", "deployment_cancelled", "deployment_lost"):
            raise Refusal("Pages deployment failed; committed intent requires recovery")
        sleep(5)
    provider.api(f"{provider.prefix}/pages/deployments/{deployment_id}/cancel", method="POST", body={})
    raise Refusal("Pages deadline exhausted; intent remains indeterminate")


def finalize_publication(config: dict, publication: dict, deployment: dict | None, *,
                         provider: GitHub, get: Callable = http_bytes) -> dict:
    previous = provider.restore_state()
    state = validate_state(publication["state"], config)
    state["sequence"] = previous["sequence"] + 1
    state["previous_receipt_sha256"] = digest(canonical(previous))
    if publication["site"] is None:
        if canonical(previous) != canonical(publication["previous_state"]):
            raise Refusal("cursor publication state changed")
        if previous.get("promotion_intent") is not None:
            raise Refusal("cursor finalization cannot clear an indeterminate intent")
        return receipt_subject(config, previous, state, publication["run"], kind="cursor_only")
    intent = previous.get("promotion_intent")
    if intent is None or deployment is None or deployment.get("status") != "succeed" or deployment.get("site_sha256") != intent["site_manifest_sha256"] or publication["site"]["site_sha256"] != intent["site_manifest_sha256"] or publication["run"]["id"] != intent["run_id"] or publication["run"]["run_attempt"] != intent["run_attempt"]:
        raise Refusal("completed exact Pages deployment is required")
    with tempfile.TemporaryDirectory(prefix="csb-readback-") as temporary:
        proposed = dict(previous, site_generation=intent["site_generation"], site_manifest_sha256=intent["site_manifest_sha256"], pages_deployment_id=deployment["pages_deployment_id"], promotion_intent=None)
        restore_public_site(config, proposed, Path(temporary) / "site", get=get)
    state.update(site_generation=intent["site_generation"], site_manifest_sha256=intent["site_manifest_sha256"], pages_deployment_id=deployment["pages_deployment_id"], promotion_intent=None,
                 previous_site_artifact_id=previous.get("site_artifact_id"), site_artifact_id=intent["artifact_id"])
    provider.repository_info()
    # Current heads are fenced again later before individual check writes. A
    # source report stays immutable historical if a PR advances during deploy.
    return receipt_subject(config, previous, state, publication["run"], kind="site_promotion")


def budget_module():
    # Package-relative fixed helper, never a reviewed repository import.
    name = "csb_public_budget_" + digest(str(Path(__file__).resolve()).encode())[:16]
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name("public_ci_budget.py"))
        if spec is None or spec.loader is None:
            raise Refusal("REST budget helper unavailable")
        module = importlib.util.module_from_spec(spec); sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def stage_budget(config: dict, manifest: dict, directory: Path, role: str, request_id: str | None = None):
    module = budget_module()
    try:
        expected = module.make_manifest(config, manifest["run_id"], manifest["run_attempt"], manifest["analysis_requests"])
        if expected != manifest:
            raise Refusal("REST pass budget differs from current base-owned config")
        return module.Budget(directory, manifest, role, request_id=request_id)
    except (ValueError, KeyError) as exc:
        raise Refusal("REST pass allocation unavailable or mismatched") from exc


def recv_exact(connection: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise Refusal("publisher IPC closed before a complete record")
        result.extend(chunk)
    return bytes(result)


def publisher_call(socket_path: Path, message: dict, *, wait: float = 20) -> dict:
    data = canonical(message)
    if len(data) > 8192:
        raise Refusal("publisher command too large")
    started = time.monotonic()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(600)
        while True:
            try:
                connection.connect(str(socket_path)); break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() - started >= wait:
                    raise Refusal("trusted publisher process unavailable")
                time.sleep(0.05)
        connection.sendall(len(data).to_bytes(4, "big") + data)
        size = int.from_bytes(recv_exact(connection, 4), "big")
        if not 0 < size <= MIB:
            raise Refusal("publisher response exceeds its budget")
        value = json.loads(recv_exact(connection, size))
    if value.get("ok") is not True:
        raise Refusal("publisher command refused: " + value.get("reason", "unavailable"))
    return value["result"]


def publisher_server(config: dict, plan_value: dict, manifest: dict, budget_directory: Path, trusted_root: Path,
                     handoffs: Path, project_root: Path, verifier: Path, work: Path, *, provider: GitHub | None = None) -> None:
    """One trusted job process retains immutable proofs across attestation steps.

    IPC is local-only and0600, with no HTTP listener. The ledger, repo and PR
    remain fresh reads; only exact run-attempt/workflow/verified-proof bytes reuse
    their immutable verification work. Each REST transport consumes one ticket.
    """
    if manifest.get("analysis_requests") != [item.get("request_id") for item in plan_value.get("requests", [])] or manifest.get("run_id") != plan_value.get("run", {}).get("id") or manifest.get("run_attempt") != plan_value.get("run", {}).get("run_attempt"):
        raise Refusal("publisher plan differs from assigned REST pass requests")
    if work.exists() or work.is_symlink():
        raise Refusal("publisher work directory must be new")
    work.mkdir(parents=True, mode=0o700)
    budget = stage_budget(config, manifest, budget_directory, "publish")
    provider = provider or GitHub(config, allow_writes=True, budget=budget)
    phase, publication, intent, deployment, final = "initial", None, None, None, None
    socket_path = work / "control.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(socket_path)); socket_path.chmod(0o600); server.listen(1)
        try:
            while True:
                connection, _ = server.accept()
                with connection:
                    connection.settimeout(600)
                    stop = False
                    try:
                        size = int.from_bytes(recv_exact(connection, 4), "big")
                        if not 0 < size <= 8192:
                            raise Refusal("publisher command exceeds its budget")
                        message = json.loads(recv_exact(connection, size))
                        object_fields(message, {"command"}, {"artifact_id", "proof"}, name="publisher command")
                        command = message["command"]
                        if command == "stage" and phase == "initial":
                            publication = stage_publication(config, plan_value, handoffs, work / "publication", provider=provider,
                                                            project_root=project_root, trusted_root=trusted_root, verifier=verifier)
                            if publication["site"] is not None:
                                cleanup_artifacts(config, provider=provider, pre_upload=True)
                                upload_preflight(config, trusted_root, MAX_SITE_ARCHIVE, provider=provider)
                            phase = "staged"; result = {"site": publication["site"] is not None}
                        elif command == "intent" and phase == "staged" and publication["site"] is not None:
                            intent = begin_promotion(config, publication, message["artifact_id"], now=timestamp())
                            write_subject(work / "intent.json", intent)
                            phase = "intent"; result = {"kind": "site_intent"}
                        elif command == "deploy" and phase == "intent":
                            commit_receipt(config, intent, read_json(Path(message["proof"]), MAX_PROOF_BYTES), provider=provider)
                            deployment = deploy_pages(config, intent, provider=provider)
                            write_new_json(work / "deployment.json", deployment)
                            phase = "deployed"; result = {"status": "succeed"}
                        elif command == "finalize" and ((phase == "staged" and publication["site"] is None) or phase == "deployed"):
                            final = finalize_publication(config, publication, deployment, provider=provider)
                            write_subject(work / "final.json", final)
                            phase = "final"; result = {"kind": final["kind"]}
                        elif command == "commit" and phase == "final":
                            receipt = commit_receipt(config, final, read_json(Path(message["proof"]), MAX_PROOF_BYTES), provider=provider)
                            # Durable state exists before any custom Architecture check.
                            repair_checks(config, provider=provider)
                            cleanup_artifacts(config, provider=provider)
                            cleanup_receipts(config, provider=provider)
                            phase = "complete"; result = receipt
                        elif command == "stop":
                            stop = True; result = {"phase": phase}
                        else:
                            raise Refusal("publisher command is outside its exact phase")
                        response = {"ok": True, "result": result}
                    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as exc:
                        response = {"ok": False, "reason": str(exc) if isinstance(exc, Refusal) else type(exc).__name__}
                    encoded = canonical(response)
                    connection.sendall(len(encoded).to_bytes(4, "big") + encoded)
                if stop:
                    break
        finally:
            write_new_json(work / "budget.json", budget.snapshot(), 32 * 1024)
            socket_path.unlink(missing_ok=True)


def write_subject(path: Path, subject: dict) -> None:
    # The Sigstore subject hash is canonical bytes, with no trailing newline.
    data = canonical(subject)
    if len(data) > MAX_STATE_BYTES:
        raise Refusal("receipt subject exceeds finite contract")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as output:
        output.write(data)


def prepare_matrix(plan_value: dict, output: Path) -> dict:
    if output.exists() or output.is_symlink():
        raise Refusal("request matrix directory must be new")
    requests = plan_value.get("requests")
    if not isinstance(requests, list) or len(requests) > 6:
        raise Refusal("request matrix exceeds six-comparison batch")
    output.mkdir(parents=True)
    matrix = []
    for request in requests:
        request_id = text(request.get("request_id"), SHA256, "matrix request id")
        write_new_json(output / (request_id + ".json"), request, 32 * 1024)
        matrix.append({"request_id": request_id})
    value = {"include": matrix}
    write_new_json(output / "matrix.json", value, 4096)
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("validate-config")
    check.add_argument("--config", type=Path, required=True)
    check.add_argument("--runtime", action="store_true")
    planning = sub.add_parser("plan-offline", help="Synthetic/local planning only; never provider authority")
    planning.add_argument("--config", type=Path, required=True)
    planning.add_argument("--state", type=Path)
    planning.add_argument("--observations", type=Path, required=True)
    planning.add_argument("--observed-at", required=True)
    planning.add_argument("--output", type=Path, required=True)
    bundle = sub.add_parser("validate-bundle")
    bundle.add_argument("--bundle", type=Path, required=True)
    packing = sub.add_parser("pack-handoff")
    packing.add_argument("--bundle", type=Path, required=True); packing.add_argument("--output", type=Path, required=True)
    extracting = sub.add_parser("unpack-handoff")
    extracting.add_argument("--archive", type=Path, required=True); extracting.add_argument("--output", type=Path, required=True)
    matrix = sub.add_parser("prepare-matrix")
    matrix.add_argument("--plan", type=Path, required=True); matrix.add_argument("--output", type=Path, required=True)
    serving = sub.add_parser("publisher-server")
    for name in ("config", "trusted-root", "plan", "budget-manifest", "budget-dir", "handoffs", "project-root", "verifier", "work"):
        serving.add_argument("--" + name, type=Path, required=True)
    serving.add_argument("--allow-remote-writes", action="store_true")
    calling = sub.add_parser("publisher-call")
    calling.add_argument("--socket", type=Path, required=True)
    calling.add_argument("--phase", choices=("stage", "intent", "deploy", "finalize", "commit", "stop"), required=True)
    calling.add_argument("--proof", type=Path)
    calling.add_argument("--artifact-id", type=int)
    calling.add_argument("--output", type=Path, required=True)
    auditing = sub.add_parser("audit-budget")
    for name in ("manifest", "plan-snapshot", "handoffs", "publish-snapshot", "output"):
        auditing.add_argument("--" + name, type=Path, required=True)
    commands = {}
    for name in ("github-plan", "upload-preflight", "analyze-request", "queue-checks", "repair-checks", "stage-publication", "begin-promotion", "commit-receipt", "deploy-pages", "finalize-publication", "cleanup"):
        command = sub.add_parser(name)
        command.add_argument("--config", type=Path, required=True)
        command.add_argument("--trusted-root", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
        command.add_argument("--budget-manifest", type=Path)
        command.add_argument("--budget-dir", type=Path)
        commands[name] = command
    commands["github-plan"].add_argument("--budget-output", type=Path, required=True)
    commands["github-plan"].add_argument("--budget-snapshot", type=Path, required=True)
    commands["upload-preflight"].add_argument("--reserve", type=int, required=True)
    analysis = commands["analyze-request"]
    analysis.add_argument("--request", type=Path, required=True)
    analysis.add_argument("--bin-dir", type=Path, required=True)
    analysis.add_argument("--offline-mirror", type=Path)
    for name in ("queue-checks", "stage-publication"):
        commands[name].add_argument("--plan", type=Path, required=True)
    stage = commands["stage-publication"]
    stage.add_argument("--handoffs", type=Path, required=True)
    stage.add_argument("--project-root", type=Path, required=True)
    stage.add_argument("--verifier", type=Path, required=True)
    stage.add_argument("--check-acks", type=Path)
    for name in ("begin-promotion", "finalize-publication"):
        commands[name].add_argument("--publication", type=Path, required=True)
    commands["begin-promotion"].add_argument("--artifact-id", type=int, required=True)
    commands["finalize-publication"].add_argument("--deployment", type=Path)
    for name in ("commit-receipt", "deploy-pages"):
        commands[name].add_argument("--subject", type=Path, required=True)
    commands["commit-receipt"].add_argument("--proof", type=Path, required=True)
    commands["cleanup"].add_argument("--pre-upload", action="store_true")
    for name in ("queue-checks", "repair-checks", "commit-receipt", "deploy-pages", "cleanup"):
        commands[name].add_argument("--allow-remote-writes", action="store_true")
    args = parser.parse_args(argv)
    try:
        value = None
        if args.command == "validate-config":
            load_config(read_json(args.config, MAX_CONFIG_BYTES), runtime=args.runtime)
            value = {"configuration": "valid", "runtime": args.runtime}
        elif args.command == "plan-offline":
            config = load_config(read_json(args.config, MAX_CONFIG_BYTES))
            previous = read_json(args.state, MAX_STATE_BYTES) if args.state else empty_state(config)
            value = plan(config, previous, read_json(args.observations, MIB), args.observed_at)
            write_new_json(args.output, value, 256 * 1024)
            value = {"offline_plan_written": True, "remote_authority": False}
        elif args.command == "validate-bundle":
            manifest = validate_bundle(args.bundle)
            value = {"public_report_id": manifest["public_report_id"], "coverage": manifest["coverage"]}
        elif args.command == "pack-handoff":
            value = {"archive_sha256": pack_handoff(args.bundle, args.output)}
        elif args.command == "unpack-handoff":
            value = {"public_report_id": unpack_handoff(args.archive, args.output)["public_report_id"]}
        elif args.command == "prepare-matrix":
            value = prepare_matrix(read_json(args.plan, 512 * 1024), args.output)
        elif args.command == "publisher-call":
            message = {"command": args.phase}
            if args.proof is not None: message["proof"] = str(args.proof)
            if args.artifact_id is not None: message["artifact_id"] = args.artifact_id
            value = publisher_call(args.socket, message)
            write_new_json(args.output, value, MIB)
        elif args.command == "audit-budget":
            manifest = read_json(args.manifest, 32 * 1024)
            snapshots = [read_json(args.plan_snapshot, 32 * 1024), read_json(args.publish_snapshot, 32 * 1024)]
            for request_id in manifest["analysis_requests"]:
                snapshots.append(read_json(args.handoffs / ("csb-public-handoff-" + request_id) / "budget.json", 32 * 1024))
            value = budget_module().aggregate(manifest, snapshots)
            write_new_json(args.output, value, 32 * 1024)
        elif args.command == "publisher-server":
            if not args.allow_remote_writes:
                raise Refusal("publisher writes require explicit activation")
            config = load_config(read_json(args.config, MAX_CONFIG_BYTES), runtime=True)
            verify_installed_inputs(config, args.trusted_root)
            publisher_server(config, read_json(args.plan, 512 * 1024), read_json(args.budget_manifest, 32 * 1024), args.budget_dir,
                             args.trusted_root, args.handoffs, args.project_root, args.verifier, args.work)
            value = {"publisher_stopped": True}
        else:
            offline = args.command == "analyze-request" and args.offline_mirror is not None
            config = load_config(read_json(args.config, MAX_CONFIG_BYTES), runtime=not offline)
            verify_installed_inputs(config, args.trusted_root)
            budget, manifest = None, None
            if not offline:
                if args.budget_dir is None:
                    raise Refusal("a fixed durable REST budget directory is required")
                if args.command == "github-plan":
                    manifest = budget_module().make_manifest(config, int(os.environ.get("GITHUB_RUN_ID", "0")), int(os.environ.get("GITHUB_RUN_ATTEMPT", "0")))
                    budget = stage_budget(config, manifest, args.budget_dir, "plan")
                else:
                    if args.budget_manifest is None:
                        raise Refusal("a trusted pass budget manifest is required")
                    manifest = read_json(args.budget_manifest, 32 * 1024)
                    request_id = read_json(args.request, 32 * 1024)["request_id"] if args.command == "analyze-request" else None
                    role = budget_module().analysis_role(manifest, request_id) if request_id is not None else "publish"
                    budget = stage_budget(config, manifest, args.budget_dir, role, request_id=request_id)
            provider = GitHub(config, allow_writes=getattr(args, "allow_remote_writes", False), budget=budget)
            if args.command == "github-plan":
                result = github_plan(config, args.trusted_root, args.output, provider=provider)
                manifest = budget_module().assign_requests(manifest, [request["request_id"] for request in result["requests"]])
                write_new_json(args.budget_output, manifest, 32 * 1024)
                write_new_json(args.budget_snapshot, budget.snapshot(), 32 * 1024)
                value = {"request_count": len(result["requests"]), "deferred": result["deferred"], "provider_calls": result["provider_calls"]}
            elif args.command == "analyze-request":
                value = run_analysis_request(config, read_json(args.request, 32 * 1024), args.trusted_root, args.bin_dir, args.output, mirror=args.offline_mirror, offline=args.offline_mirror is not None, provider=None if args.offline_mirror else provider)
                if budget is not None:
                    write_new_json(args.output / "budget.json", budget.snapshot(), 32 * 1024)
                tree_inventory(args.output, MAX_HANDOFF_BYTES, 4)
                value = {"conclusion": value["conclusion"], "reason": value["reason"], "public_report_id": value["public_report_id"]}
            elif args.command == "stage-publication":
                result = stage_publication(config, read_json(args.plan, 512 * 1024), args.handoffs, args.output, provider=provider, project_root=args.project_root, trusted_root=args.trusted_root, verifier=args.verifier, check_acks=read_json(args.check_acks, 32 * 1024) if args.check_acks else None)
                value = {"report_count": len(result["results"]), "site": result["site"]}
            elif args.command == "begin-promotion":
                value = begin_promotion(config, read_json(args.publication, 512 * 1024), args.artifact_id, now=timestamp())
                write_subject(args.output, value)
                value = {"subject_sha256": digest(canonical(value)), "kind": value["kind"]}
            elif args.command == "finalize-publication":
                value = finalize_publication(config, read_json(args.publication, 512 * 1024), read_json(args.deployment, 16 * 1024) if args.deployment else None, provider=provider)
                write_subject(args.output, value)
                value = {"subject_sha256": digest(canonical(value)), "kind": value["kind"]}
            else:
                if args.command == "upload-preflight":
                    value = upload_preflight(config, args.trusted_root, args.reserve, provider=provider)
                elif args.command == "queue-checks":
                    value = queue_checks(config, read_json(args.plan, 512 * 1024), provider)
                elif args.command == "repair-checks":
                    value = repair_checks(config, provider=provider)
                elif args.command == "commit-receipt":
                    value = commit_receipt(config, read_json(args.subject, MAX_STATE_BYTES), read_json(args.proof, MAX_PROOF_BYTES), provider=provider)
                elif args.command == "deploy-pages":
                    value = deploy_pages(config, read_json(args.subject, MAX_STATE_BYTES), provider=provider)
                elif args.command == "cleanup":
                    value = {"artifacts": cleanup_artifacts(config, provider=provider, pre_upload=args.pre_upload)}
                    if not args.pre_upload:
                        value["receipts"] = cleanup_receipts(config, provider=provider)
                write_new_json(args.output, value, MAX_PROOF_BYTES)
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
        return 0
    except (Refusal, OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as exc:
        # Never print request bodies, source, token-bearing URLs or provider stderr.
        message = str(exc) if isinstance(exc, Refusal) else type(exc).__name__
        print("public_ci_refused: " + message, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
