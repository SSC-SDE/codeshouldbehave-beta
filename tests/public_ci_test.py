"""Local security/control-plane contracts; no real GitHub writes or credential use."""
import copy
from datetime import datetime, timezone, timedelta
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import threading
from types import SimpleNamespace
import urllib.error
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("csb_public_ci", ROOT / "scripts/public_ci.py")
ci = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ci
SPEC.loader.exec_module(ci)


def configuration():
    value = json.loads((ROOT / "config/public-ci.example.json").read_text())
    for key in ("workflow_sha256", "policy_sha256", "context_sha256"):
        value[key] = "d" * 64
    value["engine"] = {"commit": "c" * 40, "flowdiff_sha256": "e" * 64, "exporter_sha256": "f" * 64}
    value["budget"]["proof_mode"] = "organization_api"
    return ci.load_config(value)


def observation(config, number, head=None, state="open", draft=False):
    return {"number": number, "repository": config["repository"], "selected_baseline": "a" * 40,
            "proposal": head or f"{number:040x}", "state": state, "draft": draft, "public": True, "consent": True}


def run(config):
    return {"id": 111, "run_attempt": 2, "event": "workflow_run", "head_sha": "c" * 40,
            "head_branch": "main", "path": config["workflow_path"], "repository": config["repository"]}


def bundle(root):
    root.mkdir()
    payload = {"artifact_version": "csb-public-artifact-v1", "analysis_review_id": "native-review"}
    data = ci.canonical(payload)
    (root / "artifact.json").write_bytes(data)
    manifest = {"schema_version": "csb-public-report-v1", "analysis_review_id": "native-review",
                "repository": configuration()["repository"], "pr_number": 1, "selected_baseline": "a" * 40,
                "baseline": "a" * 40, "proposal": "b" * 40, "scope_version": "scope-1", "policy_digest": "e" * 64,
                "engine": {"package": "flowdiff", "version": "0.1.0", "hld_generator": "test-v1", "lld_generator": "test-v1", "lld_parser": "rust-test", "public_projection": "csb-public-report-v1"},
                "files": [{"path": "artifact.json", "sha256": ci.digest(data), "bytes": len(data), "kind": "json"}],
                "routes": {"artifact": "artifact.json", "hld": None, "lld_catalog": None, "lld_details": [], "sources": [], "file_sources": [], "exports": []},
                "coverage": {"complete": False, "gaps": ["unavailable"], "deferred_details": 0},
                "capabilities": {"hld": False, "lld": False, "source": False, "export": True, "confirmation": False}}
    public_id = ci.digest(ci.canonical(manifest))
    manifest["public_report_id"] = manifest["review_id"] = public_id
    (root / "manifest.json").write_bytes(ci.canonical(manifest))
    return manifest


class ConfigurationTests(unittest.TestCase):
    def test_active_monitor_tolerates_removed_temp_files_but_final_inventory_is_strict(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transient = root / "temporary"
            transient.write_text("data")
            original = Path.lstat
            def vanished(path):
                if path == transient:
                    raise FileNotFoundError("temporary file removed")
                return original(path)
            with patch.object(Path, "lstat", vanished):
                ci.tree_inventory(root, 1024, 10, allow_disappeared=True)
                with self.assertRaises(FileNotFoundError):
                    ci.tree_inventory(root, 1024, 10)
            transient.unlink()
            (root / "linked").symlink_to(root / "absent")
            with self.assertRaises(ci.Refusal):
                ci.tree_inventory(root, 1024, 10, allow_disappeared=True)

    def test_unconfigured_example_is_parseable_but_not_runtime_ready(self):
        value = json.loads((ROOT / "config/public-ci.example.json").read_text())
        ci.load_config(value)
        with self.assertRaisesRegex(ci.Refusal, "verified billing/trust"):
            ci.load_config(value, runtime=True)

    def test_unknown_config_and_insecure_origins_are_denied(self):
        for mutation in ({"untrusted": True}, {"site": {"origin": "https://attacker.example", "base_path": "/codeshouldbehave/"}}, {"context_path": "../secret"}):
            value = configuration(); value.update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(ci.Refusal):
                ci.load_config(value)

    def test_json_duplicate_keys_and_linked_input_are_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            path.write_text('{"x":1,"x":2}')
            with self.assertRaisesRegex(ci.Refusal, "duplicate"):
                ci.read_json(path, 100)
            linked = Path(directory) / "linked.json"; linked.symlink_to(path)
            with self.assertRaises(ci.Refusal):
                ci.read_json(linked, 100)

    def test_default_branch_and_workflow_content_are_independent_trust_checks(self):
        config = configuration(); config["workflow_sha256"] = ci.digest(b"trusted")
        ci.verify_run(config, run(config), "c" * 40, b"trusted")
        for key, value in (("event", "pull_request"), ("head_branch", "feature"), ("head_sha", "b" * 40), ("path", ".github/workflows/other.yml")):
            forged = run(config); forged[key] = value
            with self.subTest(key=key), self.assertRaises(ci.Refusal):
                ci.verify_run(config, forged, "c" * 40, b"trusted")
        with self.assertRaises(ci.Refusal):
            ci.verify_run(config, run(config), "c" * 40, b"edited")

    def test_paths_reject_encoding_traversal_and_git_metadata(self):
        for path in ("../x", "/x", "a//b", "a/%2e%2e/b", "a\\b", "a/.git/config", "a?x", "a\nx"):
            with self.subTest(path=path), self.assertRaises(ci.Refusal):
                ci.relative_path(path)


class FairnessTests(unittest.TestCase):
    def setUp(self):
        self.config = configuration(); self.state = ci.empty_state(self.config)

    def test_six_comparisons_reserved_then_two_parallel_not_twenty_hidden_jobs(self):
        result = ci.plan(self.config, self.state, [observation(self.config, n) for n in range(1, 26)], "2026-10-17T06:00:00Z")
        self.assertEqual([x["pr_number"] for x in result["admitted"]], list(range(1, 7)))
        self.assertEqual(result["max_parallel"], 2)
        self.assertEqual(result["handoff_reservation_bytes"], 30 * ci.MIB)
        self.assertEqual(len(result["state"]["pending"]), 25)

    def test_terminal_unsupported_heads_do_not_starve_later_work(self):
        observations = [observation(self.config, n) for n in range(1, 101)]
        state = self.state; reached = set()
        for _ in range(17):
            result = ci.plan(self.config, state, observations, "2026-10-17T06:00:00Z")
            state = result["state"]
            for item in result["admitted"]:
                reached.add(item["pr_number"])
                state = ci.finish_head(state, item["pr_number"], item["proposal"], "unsupported")
        self.assertEqual(reached, set(range(1, 101)))
        self.assertFalse(ci.plan(self.config, state, observations, "2026-10-17T06:00:00Z")["admitted"])

    def test_head_replacement_preserves_position_and_old_completion_cannot_write(self):
        result = ci.plan(self.config, self.state, [observation(self.config, 1), observation(self.config, 2)], "2026-10-17T06:00:00Z")
        original = result["state"]["pending"][0]
        next_result = ci.plan(self.config, result["state"], [observation(self.config, 1, "f" * 40)], "2026-10-17T06:01:00Z")
        current = next_result["state"]["pending"][0]
        self.assertEqual(current["queue_sequence"], original["queue_sequence"])
        with self.assertRaisesRegex(ci.Refusal, "superseded"):
            ci.finish_head(next_result["state"], 1, original["proposal"], "published")

    def test_changed_policy_reanalyzes_unchanged_head(self):
        observed = [observation(self.config, 1)]
        result = ci.plan(self.config, self.state, observed, "2026-10-17T06:00:00Z")
        state = ci.finish_head(result["state"], 1, observed[0]["proposal"], "published")
        self.config["policy_sha256"] = "b" * 64
        self.assertEqual(len(ci.plan(self.config, state, observed, "2026-10-17T06:01:00Z")["admitted"]), 1)

    def test_retries_are_bounded_and_no_report_still_advances_state(self):
        result = ci.plan(self.config, self.state, [observation(self.config, 1)], "2026-10-17T06:00:00Z", existing_handoff_bytes=32 * ci.MIB)
        self.assertFalse(result["admitted"])
        self.assertEqual(result["state"]["sequence"], 1)
        state = result["state"]; head = state["pending"][0]["proposal"]
        state = ci.finish_head(state, 1, head, "transient", "provider_throttled")
        state = ci.finish_head(state, 1, head, "transient", "provider_throttled")
        self.assertFalse(state["pending"])
        self.assertEqual(state["completed"][0]["outcome"], "failure")

    def test_unknown_or_duplicate_provider_identity_denies_without_mutating_input(self):
        previous = copy.deepcopy(self.state)
        bad = observation(self.config, 1); bad["public"] = False
        with self.assertRaises(ci.Refusal):
            ci.plan(self.config, self.state, [bad], "2026-10-17T06:00:00Z")
        self.assertEqual(previous, self.state)
        with self.assertRaises(ci.Refusal):
            ci.plan(self.config, self.state, [observation(self.config, 1)] * 2, "2026-10-17T06:00:00Z")


class BudgetTests(unittest.TestCase):
    def test_existing_verified_operator_observation_and_expiry(self):
        config = configuration()
        synthetic = {"schema_version": "csb-public-operator-budget-v1", "account": "SSC-SDE",
                     "source": "https://github.com/settings/billing/budgets", "observed_at": "2026-10-17T05:47:00Z",
                     "expires_at": "2026-10-18T05:47:00Z", "plan": "free", "products": [
                         {"product": product, "budget_amount_usd": 0, "prevent_further_usage": True, "status": "usage_blocked"}
                         for product in ("actions", "packages")]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); evidence = root / "budget.json"
            evidence.write_bytes(ci.canonical(synthetic))
            config["budget"].update(proof_mode="operator_observation", evidence_path="budget.json", evidence_sha256=ci.digest(evidence.read_bytes()))
            at = datetime(2026, 10, 17, 6, tzinfo=timezone.utc)
            value = ci.verify_operator_budget(config, root, at)
            self.assertEqual(value["account"], "SSC-SDE")
            with self.assertRaisesRegex(ci.Refusal, "expired"):
                ci.verify_operator_budget(config, root, datetime(2026, 10, 19, tzinfo=timezone.utc))
            previous = ci.empty_state(config)
            previous["budget_activation"] = ci.budget_activation(config, root, previous, at)
            # Only a previously verified attested activation can outlive evidence;
            # this unit fixture is not a claim about an actual account setting.
            ci.budget_activation(config, root, previous, datetime(2026, 10, 19, tzinfo=timezone.utc))
            config["budget"]["repository_byte_limit"] -= 1
            with self.assertRaisesRegex(ci.Refusal, "changed"):
                ci.budget_activation(config, root, previous, at)

    def test_current_repository_reservation_does_not_pretend_to_observe_account_storage(self):
        config = configuration()
        seen = []
        def transport(method, path, body):
            seen.append(path)
            return 200, {"artifacts": [{"name": "site-current", "size_in_bytes": 70 * ci.MIB, "expired": False},
                                      {"name": "csb-public-handoff-one", "size_in_bytes": 5 * ci.MIB, "expired": False}]}
        provider = ci.GitHub(config, transport=transport)
        self.assertEqual(provider.artifact_inventory(70 * ci.MIB), 75 * ci.MIB)
        self.assertEqual(provider.handoff_bytes, 5 * ci.MIB)
        with self.assertRaisesRegex(ci.Refusal, "172 MiB"):
            provider.artifact_inventory(100 * ci.MIB)
        self.assertTrue(all("/actions/artifacts" in path for path in seen))

    def test_unimplemented_account_api_mode_cannot_enable_runtime_or_paid_fallback(self):
        config = configuration()
        with self.assertRaisesRegex(ci.Refusal, "verified billing/trust"):
            ci.load_config(config, runtime=True)
        config["budget"]["repository_byte_limit"] += 1
        with self.assertRaisesRegex(ci.Refusal, "172 MiB"):
            ci.load_config(config)


class BundleTests(unittest.TestCase):
    def test_round_trip_is_deterministic_and_tampered_payload_is_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); original = bundle(root / "bundle")
            ci.validate_bundle(root / "bundle")
            first = ci.pack_handoff(root / "bundle", root / "one.tar.gz")
            second = ci.pack_handoff(root / "bundle", root / "two.tar.gz")
            self.assertEqual(first, second)
            self.assertEqual(ci.unpack_handoff(root / "one.tar.gz", root / "restored")["public_report_id"], original["public_report_id"])
            (root / "bundle/artifact.json").write_text("{}")
            with self.assertRaisesRegex(ci.Refusal, "integrity"):
                ci.validate_bundle(root / "bundle")

    def test_recomputed_manifest_cannot_bind_nonallowlisted_route(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"; value = bundle(root)
            value["routes"]["hld"] = "../../private.json"
            identity = {key: item for key, item in value.items() if key not in ("review_id", "public_report_id")}
            value["review_id"] = value["public_report_id"] = ci.digest(ci.canonical(identity))
            (root / "manifest.json").write_bytes(ci.canonical(value))
            with self.assertRaises(ci.Refusal):
                ci.validate_bundle(root)

    def test_extra_private_file_and_links_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"; bundle(root)
            (root / "private.json").write_text('{"retained_source":"excluded"}')
            with self.assertRaisesRegex(ci.Refusal, "unexpected"):
                ci.validate_bundle(root)
            (root / "private.json").unlink(); (root / "linked.json").symlink_to(root / "artifact.json")
            with self.assertRaisesRegex(ci.Refusal, "linked"):
                ci.validate_bundle(root)

    def test_archive_traversal_symlink_duplicates_and_expansion_bomb_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for kind in ("traversal", "symlink", "duplicate", "bomb"):
                archive_path = root / (kind + ".tar.gz")
                if kind == "bomb":
                    archive_path.write_bytes(gzip.compress(b"\0" * (ci.MAX_BUNDLE_BYTES + 4 * ci.MIB + 1)))
                else:
                    with tarfile.open(archive_path, "w:gz") as archive:
                        info = tarfile.TarInfo("../escaped" if kind == "traversal" else "file.json")
                        if kind == "symlink":
                            info.type = tarfile.SYMTYPE; info.linkname = "/tmp/other"
                        archive.addfile(info)
                        if kind == "duplicate":
                            archive.addfile(info)
                with self.subTest(kind=kind), self.assertRaises(ci.Refusal):
                    ci.unpack_handoff(archive_path, root / (kind + "-output"))
                self.assertFalse((root / (kind + "-output")).exists())
            self.assertFalse((root / "escaped").exists())


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.config = configuration(); self.run = run(self.config)
        self.previous = ci.empty_state(self.config)
        self.state = ci.plan(self.config, self.previous, [], "2026-10-17T06:00:00Z")["state"]
        self.subject = ci.receipt_subject(self.config, self.previous, self.state, self.run, kind="cursor_only")

    def verified(self):
        prefix = "https://github.com/SSC-SDE/codeshouldbehave"
        certificate = {"issuer": "https://token.actions.githubusercontent.com", "sourceRepositoryIdentifier": str(self.config["repository"]["id"]),
                       "sourceRepositoryURI": prefix, "sourceRepositoryVisibilityAtSigning": "public", "sourceRepositoryDigest": self.run["head_sha"], "sourceRepositoryRef": "refs/heads/main",
                       "buildSignerURI": prefix + "/" + self.config["workflow_path"] + "@refs/heads/main", "buildSignerDigest": self.run["head_sha"],
                       "runInvocationURI": prefix + "/actions/runs/111/attempts/2", "runnerEnvironment": "github-hosted"}
        return [{"verificationResult": {"signature": {"certificate": certificate}, "verifiedTimestamps": [{"type": "Tlog"}],
                                         "statement": {"subject": [{"name": "receipt.json", "digest": {"sha256": ci.digest(ci.canonical(self.subject))}}],
                                                       "predicateType": ci.PREDICATE_TYPE, "predicate": self.subject}}}]

    def test_cursor_only_generation_zero_and_whole_subject_digest(self):
        self.assertEqual(self.subject["state"]["site_generation"], 0)
        ci.verify_attestation(self.config, self.subject, self.verified(), expected_run=self.run)
        changed = copy.deepcopy(self.subject); changed["state"]["cursor"] = 10
        with self.assertRaises(ci.Refusal):
            ci.verify_attestation(self.config, changed, self.verified(), expected_run=self.run)

    def test_claiming_real_run_in_predicate_cannot_replace_certificate_authority(self):
        for key, value in (("runInvocationURI", "https://github.com/SSC-SDE/codeshouldbehave/actions/runs/111/attempts/1"),
                           ("sourceRepositoryIdentifier", "999"), ("sourceRepositoryRef", "refs/heads/feature"),
                           ("runnerEnvironment", "self-hosted"), ("sourceRepositoryVisibilityAtSigning", "private"),
                           ("buildSignerDigest", "b" * 40)):
            forged = self.verified(); forged[0]["verificationResult"]["signature"]["certificate"][key] = value
            with self.subTest(key=key), self.assertRaises(ci.Refusal):
                ci.verify_attestation(self.config, self.subject, forged, expected_run=self.run)

    def test_signer_cli_enforces_workflow_digest_and_nonzero_exit_denies(self):
        calls = []
        def successful(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, stdout=ci.canonical(self.verified()), stderr=b"")
        ci.verify_receipt_with_gh(self.config, self.subject, {}, self.run, runner=successful)
        self.assertIn("--signer-digest", calls[0]); self.assertIn("--deny-self-hosted-runners", calls[0])
        def failed(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 1, stdout=b"[]", stderr=b"do not surface provider internals")
        with self.assertRaisesRegex(ci.Refusal, "cryptographic verification failed"):
            ci.verify_receipt_with_gh(self.config, self.subject, {}, self.run, runner=failed)

    def test_cursor_cannot_promote_and_withdrawal_ledger_cannot_roll_back(self):
        changed = copy.deepcopy(self.state)
        changed.update(site_generation=1, site_manifest_sha256="a" * 64, pages_deployment_id="12")
        with self.assertRaisesRegex(ci.Refusal, "cursor receipt"):
            ci.receipt_subject(self.config, self.previous, changed, self.run, kind="cursor_only")
        previous = copy.deepcopy(self.previous); previous["withdrawn"] = ["a" * 64]
        changed = copy.deepcopy(self.state); changed["previous_receipt_sha256"] = ci.digest(ci.canonical(previous))
        with self.assertRaisesRegex(ci.Refusal, "withdrawal"):
            ci.receipt_subject(self.config, previous, changed, self.run, kind="cursor_only")

    def test_receipt_proof_has_finite_storage_contract(self):
        with self.assertRaisesRegex(ci.Refusal, "finite storage"):
            ci.deployment_payload(self.subject, {"oversized": "x" * ci.MAX_PROOF_BYTES})


class ExecutionTests(unittest.TestCase):
    def test_fetch_is_bare_public_pinned_without_credentials_hooks_or_redirects(self):
        config = configuration(); requested = ci.request_for(config, {"pr_number": 3, "selected_baseline": "a" * 40, "proposal": "b" * 40}, run(config), "a" * 40, "2026-10-17T06:00:00Z")
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "mirror"
            def runner(argv, **kwargs):
                calls.append((argv, kwargs))
                if "init" in argv:
                    output.mkdir()
                value = (argv[-1][:-9] + "\n").encode() if "rev-parse" in argv else (b"a" * 40 + b"\n") if "merge-base" in argv else b""
                return subprocess.CompletedProcess(argv, 0, stdout=value)
            with patch.dict(os.environ, {"GH_TOKEN": "synthetic-never-worker", "GIT_CONFIG_PARAMETERS": "malicious"}):
                ci.fetch_public_objects(config, requested, output, runner=runner)
            self.assertTrue(all("GH_TOKEN" not in kwargs["env"] and "GIT_CONFIG_PARAMETERS" not in kwargs["env"] for _, kwargs in calls))
            flattened = [value for argv, _ in calls for value in argv]
            self.assertIn("--bare", flattened); self.assertIn("http.followRedirects=false", flattened)
            self.assertIn("https://github.com/SSC-SDE/codeshouldbehave.git", flattened)
            self.assertNotIn("checkout", flattened); self.assertNotIn("submodule", flattened)

    def test_sandbox_is_mandatory_and_does_not_mount_home_or_pass_tokens(self):
        config = configuration(); requested = ci.request_for(config, {"pr_number": 3, "selected_baseline": "a" * 40, "proposal": "b" * 40}, run(config), "a" * 40, "2026-10-17T06:00:00Z")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("flowdiff", "exporter", "policy", "context"):
                (root / name).write_text("trusted")
            (root / "mirror").mkdir(); (root / "output").mkdir()
            args = [root / name for name in ("flowdiff", "exporter", "mirror", "policy", "context", "output")]
            with patch.object(ci.sys, "platform", "linux"), patch.object(ci.shutil, "which", return_value="/usr/bin/bwrap"):
                argv = ci.sandbox_argv(*args, requested)
                self.assertIn("--unshare-all", argv); self.assertIn("--clearenv", argv)
                self.assertNotIn("--share-net", argv); self.assertNotIn("GH_TOKEN", argv)
                self.assertFalse(any(value.startswith("/home/") for value in argv))
            with patch.object(ci.shutil, "which", return_value=None):
                with self.assertRaisesRegex(ci.Refusal, "sandbox"):
                    ci.sandbox_argv(*args, requested)

    def test_provider_defaults_to_read_only_and_has_finite_call_budget(self):
        provider = ci.GitHub(configuration(), max_calls=1, transport=lambda *args: (200, {}))
        with self.assertRaisesRegex(ci.Refusal, "writes"):
            provider.api(provider.prefix + "/check-runs", method="POST", body={})
        provider.api(provider.prefix)
        with self.assertRaisesRegex(ci.Refusal, "call budget"):
            provider.api(provider.prefix)

    def test_wrong_provider_repo_or_nonpublic_visibility_is_not_eligible(self):
        config = configuration()
        raw = {"id": config["repository"]["id"], "owner": {"login": "SSC-SDE"}, "name": "codeshouldbehave", "default_branch": "main", "private": True, "visibility": "private"}
        provider = ci.GitHub(config, transport=lambda *args: (200, raw))
        with self.assertRaisesRegex(ci.Refusal, "visibility"):
            provider.repository_info()

    def test_neutral_is_never_green_and_stale_publication_cannot_update_new_head(self):
        self.assertEqual(ci.check_outcome(complete=True, gaps=["unknown"]), "neutral")
        self.assertEqual(ci.check_outcome(complete=True, deferred=True), "neutral")
        self.assertEqual(ci.check_outcome(complete=True), "success")
        config = configuration(); fresh = observation(config, 1, "b" * 40)
        request = {"pr_number": 1, "selected_baseline": "a" * 40, "proposal": "c" * 40}
        with self.assertRaisesRegex(ci.Refusal, "superseded"):
            ci.current_fence(config, request, fresh)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.config = configuration()
        self.config["operations"] = {"analysis": True, "publication": True, "checks": True}
        self.previous = ci.empty_state(self.config)
        self.plan = ci.plan(self.config, self.previous, [observation(self.config, 1, "b" * 40)], "2026-10-17T06:00:00Z")
        self.request = ci.request_for(self.config, self.plan["admitted"][0], run(self.config), "a" * 40, "2026-10-17T06:00:00Z", baseline_mode="exact")
        self.plan.update(requests=[self.request], previous_state=self.previous, run=run(self.config))
        self.calls = []
        self.provider = SimpleNamespace(allow_writes=True, prefix="repos/SSC-SDE/codeshouldbehave",
                                        repository_info=lambda: {}, restore_state=lambda: self.previous,
                                        trusted_run=lambda *args, **kwargs: run(self.config),
                                        pull=lambda number: observation(self.config, number, "b" * 40),
                                        api=self.api)

    def api(self, path, **kwargs):
        self.calls.append((path, kwargs))
        if "/check-runs?" in path:
            return {"check_runs": [{"id": 7, "head_sha": "b" * 40, "external_id": "csb-public-v1:" + self.request["request_id"], "app": {"slug": "github-actions"}}]}
        return {"id": 7}

    def policy(self, root):
        value = {"schema_version": "csb-public-policy-v1", "repository": self.config["repository"], "public": True, "publication_consent": True,
                 "include": ["src"], "exclude": [], "baseline_mode": "exact", "max_details": 10}
        path = root / self.config["policy_path"]; path.parent.mkdir(parents=True)
        path.write_bytes(ci.canonical(value)); self.config["policy_sha256"] = ci.digest(path.read_bytes())
        # The provider plan and request bind this actual policy, not the setup stub.
        for pending in self.plan["state"]["pending"]:
            pending["comparison_key"] = ci.comparison_key(self.config, pending)
        self.request = ci.request_for(self.config, self.plan["admitted"][0], run(self.config), "a" * 40, "2026-10-17T06:00:00Z", baseline_mode="exact")
        self.plan["requests"] = [self.request]
        return ci.public_policy_digest(self.config, root)

    def test_stage_uses_actual_policy_and_required_native_semantic_verifier(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); policy_hash = self.policy(root)
            original = root / "bundle"; manifest = bundle(original)
            manifest["policy_digest"] = policy_hash
            identity = {key: value for key, value in manifest.items() if key not in ("review_id", "public_report_id")}
            manifest["review_id"] = manifest["public_report_id"] = ci.digest(ci.canonical(identity))
            (original / "manifest.json").write_bytes(ci.canonical(manifest))
            handoff = root / "handoffs" / ("csb-public-handoff-" + self.request["request_id"]); handoff.mkdir(parents=True)
            archive_hash = ci.pack_handoff(original, handoff / "handoff.tar.gz")
            ci.write_new_json(handoff / "result.json", {"schema_version": "csb-public-analysis-result-v1", "request": self.request,
                              "public_report_id": manifest["public_report_id"], "archive_sha256": archive_hash, "conclusion": "success", "reason": ""})
            site = SimpleNamespace(assemble_site=lambda *args, **kwargs: self.assert_site_kwargs(kwargs))
            with patch.object(ci, "restore_public_site", return_value=None), patch.dict(sys.modules, public_site=site):
                result = ci.stage_publication(self.config, self.plan, root / "handoffs", root / "staged", provider=self.provider,
                                              project_root=root, trusted_root=root, verifier=root / "trusted-exporter")
            # The worker cannot turn incomplete coverage into a green check.
            self.assertEqual(result["results"][0]["conclusion"], "neutral")
            self.assertEqual(result["state"]["check_updates"][0]["conclusion"], "neutral")
            self.assertEqual(self.site_verifier, root / "trusted-exporter")

    def assert_site_kwargs(self, kwargs):
        self.site_verifier = kwargs["verifier"]
        self.assertEqual(kwargs["verifier_sha256"], self.config["engine"]["exporter_sha256"])
        return {"site_sha256": "a" * 64, "bytes": 100, "index_sha256": "b" * 64, "report_count": 1}

    def test_wrong_scope_bundle_refuses_even_after_recomputing_its_content_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.policy(root)
            original = root / "bundle"; manifest = bundle(original)
            handoff = root / "handoffs" / ("csb-public-handoff-" + self.request["request_id"]); handoff.mkdir(parents=True)
            archive_hash = ci.pack_handoff(original, handoff / "handoff.tar.gz")
            ci.write_new_json(handoff / "result.json", {"schema_version": "csb-public-analysis-result-v1", "request": self.request,
                              "public_report_id": manifest["public_report_id"], "archive_sha256": archive_hash, "conclusion": "neutral", "reason": ""})
            with patch.object(ci, "restore_public_site", return_value=None), self.assertRaisesRegex(ci.Refusal, "scope differs"):
                ci.stage_publication(self.config, self.plan, root / "handoffs", root / "staged", provider=self.provider, project_root=root, trusted_root=root, verifier=root / "trusted")

    def test_scope_change_withdraws_prior_reports_before_site_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.policy(root)
            previous = root / "previous"; original = previous / "reviews"; original.mkdir(parents=True)
            manifest = bundle(original / ("f" * 64))
            (previous / "index.json").write_bytes(ci.canonical({"reports": [{"public_report_id": "f" * 64}]}))
            self.plan["requests"] = []
            self.plan["state"]["pending"] = []
            captured = {}
            def assemble(*args, **kwargs):
                captured.update(kwargs); return {"site_sha256": "a" * 64}
            with patch.object(ci, "restore_public_site", return_value=previous), patch.dict(sys.modules, public_site=SimpleNamespace(assemble_site=assemble)):
                result = ci.stage_publication(self.config, self.plan, root / "handoffs", root / "staged", provider=self.provider, project_root=root, trusted_root=root, verifier=root / "trusted")
            self.assertEqual(captured["withdrawn"], ["f" * 64])
            self.assertEqual(result["state"]["consent_epoch"], 2)

    def test_signed_intent_is_required_before_pages_and_string_id_is_retained(self):
        activation = {"schema_version": "csb-public-budget-activation-v1", "account": "SSC-SDE", "evidence_sha256": "e" * 64,
                      "budget_policy_sha256": "f" * 64, "activated_at": "2026-10-17T06:00:00Z"}
        state = dict(self.plan["state"], budget_activation=activation)
        publication = {"previous_state": self.previous, "state": state, "run": run(self.config), "site": {"site_sha256": "e" * 64}}
        subject = ci.begin_promotion(self.config, publication, 44, now="2026-10-17T06:00:00Z")
        self.assertEqual(subject["kind"], "site_intent")
        with self.assertRaisesRegex(ci.Refusal, "committed attested intent"):
            ci.deploy_pages(self.config, subject, provider=self.provider)
        self.provider.restore_state = lambda: subject["state"]
        def pages(path, **kwargs):
            self.calls.append((path, kwargs))
            if "/actions/artifacts/" in path:
                return {"name": "csb-public-pages-111-2", "expired": False, "size_in_bytes": 100, "workflow_run": {"id": 111, "head_sha": "c" * 40}}
            return {"id": "pages-actual-id"} if kwargs.get("method") == "POST" else {"status": "succeed"}
        self.provider.api = pages
        deployed = ci.deploy_pages(self.config, subject, provider=self.provider, token=lambda: "in-memory-only", sleep=lambda _: None)
        self.assertEqual(deployed["pages_deployment_id"], "pages-actual-id")
        with patch.object(ci, "restore_public_site", return_value=Path("unused")):
            final = ci.finalize_publication(self.config, publication, deployed, provider=self.provider)
        self.assertEqual(final["state"]["site_artifact_id"], 44)
        self.assertIsNone(final["state"]["promotion_intent"])
        self.assertEqual(final["state"]["pages_deployment_id"], "pages-actual-id")

    def test_missing_receipt_or_readback_mismatch_cannot_finalize(self):
        publication = {"previous_state": self.previous, "state": self.plan["state"], "run": run(self.config), "site": {"site_sha256": "e" * 64}}
        with self.assertRaisesRegex(ci.Refusal, "exact Pages"):
            ci.finalize_publication(self.config, publication, {"status": "succeed", "site_sha256": "e" * 64}, provider=self.provider)
        state = dict(self.previous, sequence=1, previous_receipt_sha256="f" * 64)
        self.provider.restore_state = lambda: state
        with self.assertRaisesRegex(ci.Refusal, "cursor publication state changed"):
            ci.finalize_publication(self.config, dict(publication, site=None), None, provider=self.provider)

    def test_lost_check_patch_is_retained_and_retry_uses_only_old_exact_head(self):
        self.previous["check_updates"] = [{"request": self.request, "public_report_id": "e" * 64, "conclusion": "neutral", "reason": ""}]
        self.provider.api = lambda *args, **kwargs: (_ for _ in ()).throw(ci.Refusal("provider operation refused"))
        with self.assertRaises(ci.Refusal):
            ci.repair_checks(self.config, provider=self.provider)
        self.assertEqual(len(self.previous["check_updates"]), 1)
        self.provider.api = self.api
        self.provider.pull = lambda _: observation(self.config, 1, "f" * 40)
        acks = ci.repair_checks(self.config, provider=self.provider)
        patches = [value[1]["body"] for value in self.calls if value[1].get("method") == "PATCH"]
        self.assertEqual(patches[-1]["conclusion"], "cancelled")
        self.assertEqual(acks["acked"], [self.request["request_id"]])
        self.assertEqual(len(self.previous["check_updates"]), 1)  # only a later signed state removes it
        self.assertIn("/commits/" + "b" * 40 + "/", self.calls[0][0])

    def test_failed_check_does_not_offer_nonexistent_report(self):
        self.previous["check_updates"] = [{"request": self.request, "public_report_id": None,
            "conclusion": "failure", "reason": "analysis_unavailable"}]
        ci.repair_checks(self.config, provider=self.provider)
        body = [call[1]["body"] for call in self.calls if call[1].get("method") in ("PATCH", "POST")][-1]
        self.assertEqual(body["output"]["title"], "Failed · Analysis unavailable")
        self.assertNotIn("details_url", body)
        self.assertNotIn("Open Details", body["output"]["summary"])
        self.assertIn("not a no-change result", body["output"]["summary"])

    def test_stale_ready_report_is_cancelled_and_explicitly_historical(self):
        self.previous["check_updates"] = [{"request": self.request, "public_report_id": "e" * 64,
            "conclusion": "success", "reason": "", "verdict": "no_change_detected"}]
        self.provider.pull = lambda number: observation(self.config, number, "c" * 40)
        ci.repair_checks(self.config, provider=self.provider)
        body = [call[1]["body"] for call in self.calls if call[1].get("method") in ("PATCH", "POST")][-1]
        self.assertEqual(body["conclusion"], "cancelled")
        self.assertEqual(body["output"]["title"], "Superseded · New comparison required")
        self.assertIn("historical, not the current PR result", body["output"]["summary"])

    def test_repaired_check_carries_verdict_and_exact_behavior_link(self):
        for verdict, conclusion, title in (
            ("no_change_detected", "success", "Ready · No detected change"),
            ("change_detected", "neutral", "Ready · Changes to review"),
            ("incomplete", "neutral", "Incomplete · Review required"),
        ):
            self.previous["check_updates"] = [{"request": self.request, "public_report_id": "e" * 64,
                "conclusion": conclusion, "reason": "", "verdict": verdict}]
            ci.validate_state(self.previous, self.config)
            ci.repair_checks(self.config, provider=self.provider)
            writes = [call[1]["body"] for call in self.calls if call[1].get("method") in ("PATCH", "POST")]
            body = writes[-1]
            self.assertEqual(body["conclusion"], conclusion)
            self.assertEqual(body["output"]["title"], title)
            self.assertIn("&design=lld", body["details_url"])
            self.assertIn("&mode=focus", body["details_url"])
            self.assertIn(self.request["proposal"], body["output"]["summary"])

    def test_repair_limits_six_and_does_not_assume_neutral_is_merge_approval(self):
        for number in range(1, 8):
            result = ci.plan(self.config, ci.empty_state(self.config), [observation(self.config, number, "b" * 40)], "2026-10-17T06:00:00Z")
            request = ci.request_for(self.config, result["admitted"][0], run(self.config), "a" * 40, "2026-10-17T06:00:00Z", baseline_mode="exact")
            self.previous["check_updates"].append({"request": request, "public_report_id": "e" * 64, "conclusion": "neutral", "reason": ""})
        self.provider.api = lambda *args, **kwargs: {"check_runs": []} if "check-runs?" in args[0] else self.api(*args, **kwargs)
        acks = ci.repair_checks(self.config, provider=self.provider)
        self.assertEqual(len(acks["acked"]), 6)
        writes = [item[1]["body"] for item in self.calls if item[1].get("method") == "POST"]
        self.assertTrue(all(item["conclusion"] == "neutral" and "does not approve" in item["output"]["summary"] for item in writes))

    def test_receipt_subject_bytes_match_the_attested_file_exactly(self):
        state = dict(self.previous, sequence=1, previous_receipt_sha256=ci.digest(ci.canonical(self.previous)))
        subject = ci.receipt_subject(self.config, self.previous, state, run(self.config), kind="cursor_only")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "subject.json"; ci.write_subject(path, subject)
            self.assertEqual(ci.digest(path.read_bytes()), ci.digest(ci.canonical(subject)))
            self.assertFalse(path.read_bytes().endswith(b"\n"))

    def test_unreceipted_existing_site_and_changed_live_manifest_refuse_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ci.Refusal, "existing/indeterminate"):
                ci.restore_public_site(self.config, self.previous, Path(directory) / "restore", get=lambda *args: b"{}")
            state = dict(self.previous, site_generation=1, site_manifest_sha256="a" * 64, pages_deployment_id="pages-id")
            with self.assertRaisesRegex(ci.Refusal, "indeterminate live"):
                ci.restore_public_site(self.config, state, Path(directory) / "restore", get=lambda *args: b"{}")
            self.assertIsNone(ci.restore_public_site(self.config, self.previous, Path(directory) / "restore", get=lambda *args: (_ for _ in ()).throw(urllib.error.HTTPError("not-logged", 404, "missing", {}, None))))

    def test_newer_unverifiable_receipt_cannot_restore_an_older_site(self):
        config = self.config
        payload = {"schema_version": "csb-public-receipt-envelope-v1", "subject": {"not": "a valid signed intent"}, "subject_sha256": "0" * 64, "verification_bundle": {}}
        records = [{"id": 99, "payload": payload, "sha": "c" * 40}]
        provider = ci.GitHub(config, transport=lambda *args: (200, records))
        with self.assertRaisesRegex(ci.Refusal, "unverifiable receipt"):
            provider.restore_state()

    def test_historical_receipt_queries_its_exact_run_attempt(self):
        config = self.config; seen = []
        raw = {"id": 111, "run_attempt": 1, "event": "workflow_run", "head_sha": "c" * 40,
               "head_branch": "main", "path": config["workflow_path"], "repository": {"id": config["repository"]["id"], "owner": {"login": "SSC-SDE"}, "name": "codeshouldbehave"}}
        def transport(method, path, body):
            seen.append(path); return 200, raw
        provider = ci.GitHub(config, transport=transport)
        with patch.object(provider, "workflow_bytes", return_value=b"trusted"):
            config["workflow_sha256"] = ci.digest(b"trusted")
            actual = provider.trusted_run(111, require_current=False, run_attempt=1)
        self.assertEqual(actual["run_attempt"], 1)
        self.assertTrue(seen[0].endswith("/actions/runs/111/attempts/1"))

    def test_fast_successful_subprocess_cannot_skip_final_stderr_budget(self):
        with self.assertRaisesRegex(ci.Refusal, "output exhausted"):
            ci.bounded_process([sys.executable, "-c", "import os; os.write(2,b'x'*(2*1024*1024))"], timeout=2)

    def test_cleanup_keeps_exact_last_good_artifact_and_never_deletes_user_artifacts(self):
        self.previous.update(site_generation=2, site_manifest_sha256="a" * 64, pages_deployment_id="actual", site_artifact_id=21, previous_site_artifact_id=20)
        artifacts = [{"id": number, "name": f"csb-public-pages-{number}-1", "expired": False,
                      "workflow_run": {"id": number, "head_sha": "c" * 40}} for number in (19, 20, 21)]
        artifacts += [{"id": 99, "name": "user-owned-build", "expired": False, "workflow_run": {"id": 19}}]
        def api(path, **kwargs):
            self.calls.append((path, kwargs)); return {"artifacts": artifacts} if "/actions/artifacts?" in path else None
        self.provider.api = api
        with patch.dict(os.environ, GITHUB_RUN_ID="111"):
            result = ci.cleanup_artifacts(self.config, provider=self.provider, pre_upload=True)
        self.assertEqual(result["protected_site_artifacts"], [21])
        self.assertEqual(result["removed_artifacts"], [19, 20])
        self.assertFalse(any(item[0].endswith("/99") for item in self.calls))
        self.previous["promotion_intent"] = {"indeterminate": True}
        with patch.dict(os.environ, GITHUB_RUN_ID="111"), self.assertRaisesRegex(ci.Refusal, "indeterminate"):
            ci.cleanup_artifacts(self.config, provider=self.provider)

    def test_two_missing_worker_attempts_become_explicit_terminal_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.policy(root)
            with patch.object(ci, "restore_public_site", return_value=None):
                first = ci.stage_publication(self.config, self.plan, root / "missing", root / "first", provider=self.provider, project_root=root, trusted_root=root, verifier=root / "trusted")
            self.assertEqual(first["state"]["pending"][0]["attempts"], 1)
            next_plan = ci.plan(self.config, first["state"], [observation(self.config, 1, "b" * 40)], "2026-10-17T06:10:00Z")
            self.previous = first["state"]
            next_plan.update(previous_state=self.previous, run=run(self.config), requests=[self.request])
            with patch.object(ci, "restore_public_site", return_value=None):
                final = ci.stage_publication(self.config, next_plan, root / "missing", root / "second", provider=self.provider, project_root=root, trusted_root=root, verifier=root / "trusted")
            self.assertFalse(final["state"]["pending"])
            self.assertEqual(final["state"]["completed"][0]["outcome"], "failure")

    def test_custom_queued_check_refuses_before_its_request_is_durable(self):
        with self.assertRaisesRegex(ci.Refusal, "committed durable request"):
            ci.queue_checks(self.config, self.plan, self.provider)
        self.assertFalse(self.calls)


class BudgetedPipelineTests(unittest.TestCase):
    """Exercise actual API/budget/phase code; authority/Pages/native are explicit fakes."""
    def test_three_request_pipeline_and_steady_state_share100_rest_tickets(self):
        # Every synthetic ticket, including the first and capacity-only pass,
        # must be created inside its local fake profile even on hosted CI.
        with patch.dict(os.environ, GITHUB_ACTIONS="false"), tempfile.TemporaryDirectory(prefix="csb-budget-", dir="/tmp") as directory:
            root = Path(directory).resolve(); config = configuration()
            config["operations"] = {"analysis": True, "publication": True, "checks": True}
            policy = {"schema_version": "csb-public-policy-v1", "repository": config["repository"], "public": True, "publication_consent": True,
                      "include": ["src"], "exclude": [], "baseline_mode": "exact", "max_details": 10}
            for path_key, hash_key, data in (("workflow_path", "workflow_sha256", b"trusted controller"), ("policy_path", "policy_sha256", ci.canonical(policy)), ("context_path", "context_sha256", b"{}")):
                path = root / config[path_key]; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data); config[hash_key] = ci.digest(data)
            now = datetime.now(timezone.utc)
            evidence = {"schema_version": "csb-public-operator-budget-v1", "account": "SSC-SDE", "source": "https://github.com/settings/billing/budgets",
                        "observed_at": ci.timestamp(now - timedelta(seconds=1)), "expires_at": ci.timestamp(now + timedelta(hours=23)), "plan": "free",
                        "products": [{"product": product, "budget_amount_usd": 0, "prevent_further_usage": True, "status": "usage_blocked"} for product in ("actions", "packages")]}
            (root / "budget-proof.json").write_bytes(ci.canonical(evidence))
            config["budget"].update(proof_mode="operator_observation", evidence_path="budget-proof.json", evidence_sha256=ci.digest(ci.canonical(evidence)))
            module = ci.budget_module()
            prefix = "repos/SSC-SDE/codeshouldbehave"
            records, artifacts, checks, runs = [], [], [], {}
            current = {"run": 0, "head": "", "iteration": 0}
            all_calls, snapshots_by_pass = [], []

            def transport(method, path, body):
                all_calls.append((method, path))
                if path == prefix:
                    return 200, {"id": config["repository"]["id"], "owner": {"login": "SSC-SDE"}, "name": "codeshouldbehave", "private": False, "visibility": "public", "default_branch": "main"}
                if path == "rate_limit": return 200, {"resources": {"core": {"remaining": 5000, "limit": 5000}}}
                if path.startswith(prefix + "/git/ref/"): return 200, {"object": {"sha": current["head"]}}
                if path.startswith(prefix + "/contents/"):
                    return 200, {"type": "file", "encoding": "base64", "size": len(b"trusted controller"), "content": ci.base64.b64encode(b"trusted controller").decode()}
                if path.startswith(prefix + "/actions/runs/"):
                    identifier = int(path.split("/actions/runs/", 1)[1].split("/")[0]); return 200, runs[identifier]
                if path.startswith(prefix + "/pulls"):
                    def raw(number):
                        return {"number": number, "state": "open", "draft": False, "base": {"sha": "a" * 40, "repo": {"id": config["repository"]["id"]}},
                                "head": {"sha": f"{current['iteration'] * 100 + number:040x}"}}
                    suffix = path.split("/pulls", 1)[1]
                    return 200, [raw(number) for number in range(1, 4)] if suffix.startswith("?") else raw(int(suffix[1:]))
                if path.startswith(prefix + "/actions/artifacts?"): return 200, {"artifacts": list(artifacts)}
                if path.startswith(prefix + "/actions/artifacts/"):
                    identifier = int(path.rsplit("/", 1)[1])
                    if method == "DELETE":
                        artifacts[:] = [item for item in artifacts if item["id"] != identifier]; return 204, None
                    return 200, next(item for item in artifacts if item["id"] == identifier)
                if path.startswith(prefix + "/deployments?"): return 200, list(reversed(records))
                if path == prefix + "/deployments" and method == "POST":
                    item = {"id": 5000 + len(all_calls), "payload": body["payload"], "sha": body["ref"]}; records.append(item); return 201, item
                if path.startswith(prefix + "/deployments/"):
                    if method == "DELETE":
                        identifier = int(path.rsplit("/", 1)[1]); records[:] = [item for item in records if item["id"] != identifier]
                    return 200, {}
                if path == prefix + "/pages/deployments": return 201, {"id": "actual-pages-" + str(current["run"])}
                if path.startswith(prefix + "/pages/deployments/"): return 200, {"status": "succeed"}
                if "/commits/" in path and "/check-runs?" in path:
                    head = path.split("/commits/", 1)[1].split("/", 1)[0]
                    return 200, {"check_runs": [item for item in checks if item["head_sha"] == head]}
                if path == prefix + "/check-runs" and method == "POST":
                    self.assertTrue(records, "no custom check may precede durable state")
                    self.assertEqual(records[-1]["payload"]["subject"]["kind"], "site_promotion")
                    item = dict(body, id=9000 + len(checks), app={"slug": "github-actions"}); checks.append(item); return 201, item
                if "/check-runs/" in path and method == "PATCH":
                    identifier = int(path.rsplit("/", 1)[1]); item = next(item for item in checks if item["id"] == identifier); item.update(body); return 200, item
                raise AssertionError((method, path))

            def projection(output, request):
                manifest = bundle(output)
                manifest.update(pr_number=request["pr_number"], selected_baseline=request["selected_baseline"], baseline=request["baseline"], proposal=request["proposal"], policy_digest=ci.public_policy_digest(config, root))
                identity = {key: value for key, value in manifest.items() if key not in ("review_id", "public_report_id")}
                manifest["review_id"] = manifest["public_report_id"] = ci.digest(ci.canonical(identity))
                (output / "manifest.json").write_bytes(ci.canonical(manifest)); return manifest

            def fake_analyze(config_value, request, trusted, binaries, mirror, output):
                output.mkdir(); manifest = projection(output / "public", request)
                return {"public_report_id": manifest["public_report_id"], "conclusion": "neutral"}

            def site(bundles, output, observed, **kwargs):
                self.assertEqual(kwargs["verifier_sha256"], config["engine"]["exporter_sha256"])
                output.mkdir(parents=True)
                return {"site_sha256": "e" * 64, "index_sha256": "f" * 64, "bytes": 100, "report_count": len(bundles)}

            for iteration in (1, 2):
                current.update(run=110 + iteration, head=f"{900 + iteration:040x}", iteration=iteration)
                raw_run = {"id": current["run"], "run_attempt": 1, "event": "workflow_run", "head_sha": current["head"], "head_branch": "main", "path": config["workflow_path"],
                           "repository": {"id": config["repository"]["id"], "owner": {"login": "SSC-SDE"}, "name": "codeshouldbehave"}}
                runs[current["run"]] = raw_run
                pass_root = root / str(iteration); pass_root.mkdir()
                manifest = module.make_manifest(config, current["run"], 1)
                plan_budget = ci.stage_budget(config, manifest, pass_root / "budget", "plan")
                provider = ci.GitHub(config, transport=transport, budget=plan_budget)
                env = {"GITHUB_ACTIONS": "false", "GITHUB_RUN_ID": str(current["run"]), "GITHUB_RUN_ATTEMPT": "1"}
                with patch.dict(os.environ, env), patch.object(ci, "verify_receipt_with_gh", return_value=[]):
                    planned = ci.github_plan(config, root, pass_root / "plan.json", provider=provider)
                    self.assertEqual(len(planned["requests"]), 3)
                    manifest = module.assign_requests(manifest, [request["request_id"] for request in planned["requests"]])
                    snapshots = [plan_budget.snapshot()]
                    handoffs = pass_root / "handoffs"; handoffs.mkdir()
                    for request in planned["requests"]:
                        role = module.analysis_role(manifest, request["request_id"])
                        budget = ci.stage_budget(config, manifest, pass_root / "budget", role, request["request_id"])
                        analysis_provider = ci.GitHub(config, transport=transport, budget=budget)
                        with patch.object(ci, "analyze", side_effect=fake_analyze):
                            output = handoffs / ("csb-public-handoff-" + request["request_id"])
                            ci.run_analysis_request(config, request, root, root / "bin", output, mirror=root, provider=analysis_provider)
                        self.assertEqual(budget.snapshot()["used"], 4)
                        snapshots.append(budget.snapshot())
                        artifacts.append({"id": 1000 + len(all_calls), "name": "csb-public-handoff-" + request["request_id"], "expired": False, "size_in_bytes": ci.MIB,
                                          "workflow_run": {"id": current["run"], "head_sha": current["head"]}})
                    publish_budget = ci.stage_budget(config, manifest, pass_root / "budget", "publish")
                    publisher = ci.GitHub(config, transport=transport, budget=publish_budget, allow_writes=True)
                    work = pass_root / "pub"
                    # The phase machine and actual transport code run in one IPC
                    # server. Native projection, authority crypto and Pages are
                    # faked explicitly; this is not live-provider acceptance.
                    thread_errors = []
                    def serve():
                        try:
                            ci.publisher_server(config, planned, manifest, pass_root / "budget", root, handoffs, root, root / "exporter", work, provider=publisher)
                        except BaseException as exc: thread_errors.append(exc)
                    with patch.object(ci, "restore_public_site", return_value=None), patch.object(ci, "github_oidc_token", return_value="unit-only"), patch.dict(sys.modules, public_site=SimpleNamespace(assemble_site=site)):
                        # Default token callback was bound at definition; replace
                        # only that provider boundary without changing lifecycle.
                        original_deploy = ci.deploy_pages
                        with patch.object(ci, "deploy_pages", side_effect=lambda cfg, subject, **kwargs: original_deploy(cfg, subject, token=lambda: "unit-only", sleep=lambda _: None, **kwargs)):
                            thread = threading.Thread(target=serve, daemon=True); thread.start()
                            try:
                                staged = ci.publisher_call(work / "control.sock", {"command": "stage"})
                                self.assertTrue(staged["site"])
                                artifact_id = 2000 + iteration
                                artifacts.append({"id": artifact_id, "name": f"csb-public-pages-{current['run']}-1", "expired": False, "size_in_bytes": ci.MIB,
                                                  "workflow_run": {"id": current["run"], "head_sha": current["head"]}})
                                ci.publisher_call(work / "control.sock", {"command": "intent", "artifact_id": artifact_id})
                                proof = pass_root / "fake-proof.json"; proof.write_text("{}")
                                ci.publisher_call(work / "control.sock", {"command": "deploy", "proof": str(proof)})
                                ci.publisher_call(work / "control.sock", {"command": "finalize"})
                                ci.publisher_call(work / "control.sock", {"command": "commit", "proof": str(proof)})
                            finally:
                                if (work / "control.sock").exists():
                                    ci.publisher_call(work / "control.sock", {"command": "stop"})
                                thread.join(5)
                    self.assertFalse(thread_errors)
                    self.assertFalse(thread.is_alive())
                    snapshots.append(ci.read_json(work / "budget.json", 32 * 1024))
                    aggregate = module.aggregate(manifest, snapshots)
                    self.assertLessEqual(aggregate["application_rest_calls"], 100)
                    self.assertEqual(len(checks), iteration * 3)
                    self.assertTrue(all(check["conclusion"] == "neutral" and check["status"] == "completed" for check in checks))
                    snapshots_by_pass.append(aggregate["application_rest_calls"])
            self.assertEqual(len(records), 2)
            self.assertLessEqual(max(snapshots_by_pass), 100)
            self.__class__.fake_pipeline_call_counts = snapshots_by_pass
            # Near the repository cap, reserve the entire batch before workers
            # overlap: two uploads must not each spend the same remaining bytes.
            current.update(run=113, head=f"{903:040x}", iteration=3)
            runs[113] = dict(runs[112], id=113, head_sha=current["head"])
            target_usage = 164 * ci.MIB + ci.MIB // 2
            artifacts.append({"id": 99999, "name": "unrelated-user-build", "expired": False,
                              "size_in_bytes": target_usage - sum(item["size_in_bytes"] for item in artifacts)})
            manifest = module.make_manifest(config, 113, 1)
            budget = ci.stage_budget(config, manifest, root / "capacity-budget", "plan")
            capacity_provider = ci.GitHub(config, transport=transport, budget=budget)
            with patch.dict(os.environ, GITHUB_ACTIONS="false", GITHUB_RUN_ID="113", GITHUB_RUN_ATTEMPT="1"), patch.object(ci, "verify_receipt_with_gh", return_value=[]):
                constrained = ci.github_plan(config, root, root / "capacity-plan.json", provider=capacity_provider)
            self.assertEqual(len(constrained["requests"]), 1)
            reservation = constrained["repository_reservation"]
            self.assertEqual(reservation["observed_bytes"], target_usage)
            self.assertLessEqual(reservation["observed_bytes"] + reservation["handoff_bytes"] + reservation["control_bytes"], ci.MAX_REPOSITORY_ARTIFACT_BYTES)

    def test_api_reserves_before_transport_and_never_restarts_its_stage_counter(self):
        config = configuration(); module = ci.budget_module()
        request_id = "e" * 64; manifest = module.make_manifest(config, 111, 1, [request_id]); seen = []
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, GITHUB_ACTIONS="false"):
            budget = ci.stage_budget(config, manifest, Path(directory) / "role", "analyze-0", request_id)
            provider = ci.GitHub(config, budget=budget, transport=lambda *args: (seen.append(args) or (200, {})))
            for _ in range(4): provider.api(provider.prefix)
            # A new provider/session cannot reset the durable role allocation.
            reloaded = ci.stage_budget(config, manifest, Path(directory) / "role", "analyze-0", request_id)
            again = ci.GitHub(config, budget=reloaded, transport=lambda *args: (seen.append(args) or (200, {})))
            with self.assertRaisesRegex(ci.Refusal, "ticket exhausted"):
                again.api(again.prefix)
            self.assertEqual(len(seen), 4)

    def test_synthetic_plan_ticket_cannot_bind_to_a_real_validate_job(self):
        config = configuration(); module = ci.budget_module()
        manifest = module.make_manifest(config, 111, 1)
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, GITHUB_ACTIONS="true", GITHUB_JOB="validate", GITHUB_RUN_ID="111", GITHUB_RUN_ATTEMPT="1"):
            destination = Path(directory) / "budget"
            with self.assertRaisesRegex(ci.Refusal, "allocation unavailable"):
                ci.stage_budget(config, manifest, destination, "plan")
            self.assertFalse(destination.exists())

    def test_live_actions_transport_without_a_ticket_fails_before_token_or_network(self):
        provider = ci.GitHub(configuration())
        with patch.dict(os.environ, GITHUB_ACTIONS="true"), patch.object(ci.subprocess, "Popen", side_effect=AssertionError("no transport")):
            with self.assertRaisesRegex(ci.Refusal, "durable stage ticket"):
                provider.api(provider.prefix)

    def test_immutable_run_cache_never_reuses_mutable_default_branch_authority(self):
        config = configuration(); config["workflow_sha256"] = ci.digest(b"trusted")
        seen, changed = [], {"value": False}
        raw = {"id": 111, "run_attempt": 1, "event": "workflow_run", "head_sha": "c" * 40, "head_branch": "main", "path": config["workflow_path"],
               "repository": {"id": config["repository"]["id"], "owner": {"login": "SSC-SDE"}, "name": "codeshouldbehave"}}
        def transport(method, path, body):
            seen.append(path)
            if "/git/ref/" in path: return 200, {"object": {"sha": ("d" if changed["value"] else "c") * 40}}
            if "/contents/" in path: return 200, {"type": "file", "encoding": "base64", "size": 7, "content": ci.base64.b64encode(b"trusted").decode()}
            return 200, raw
        provider = ci.GitHub(config, transport=transport)
        provider.trusted_run(111, require_current=True, run_attempt=1)
        changed["value"] = True
        with self.assertRaisesRegex(ci.Refusal, "current default"):
            provider.trusted_run(111, require_current=True, run_attempt=1)
        self.assertEqual(len([path for path in seen if "/contents/" in path]), 1)
        self.assertEqual(len([path for path in seen if "/actions/runs/" in path]), 1)
        self.assertEqual(len([path for path in seen if "/git/ref/" in path]), 2)


class TemplateTests(unittest.TestCase):
    def test_templates_are_inactive_and_use_exact_current_action_pins(self):
        templates = ROOT / "templates/public-ci"
        pins = json.loads((templates / "action-pins.json").read_bytes())
        controller = (templates / "controller.yml").read_text()
        nudge = (templates / "nudge.yml").read_text()
        self.assertNotIn("pull_request_target", controller)
        self.assertNotIn("checkout", nudge)
        self.assertIn("permissions: {}", nudge)
        self.assertNotIn("github.event.workflow_run.id", controller)
        self.assertIn("max-parallel: 2", controller)
        self.assertIn("cancel-in-progress: false", controller)
        self.assertIn("digest-mismatch: error", controller)
        for line in controller.splitlines():
            if "uses: actions/" in line:
                reference = line.split("uses: ", 1)[1].split(" #", 1)[0].strip()
                repository, commit = reference.split("@")
                self.assertTrue(any(pin["repository"] == repository and pin["commit"] == commit for pin in pins["actions"]))

    def test_installer_loads_budget_from_its_package_before_writing_anything(self):
        spec = importlib.util.spec_from_file_location("csb_installer_test", ROOT / "templates/public-ci/install.py")
        installer = importlib.util.module_from_spec(spec); spec.loader.exec_module(installer)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); package = root / "package"; (package / "scripts").mkdir(parents=True)
            for name in ("public_ci.py", "public_ci_budget.py"):
                (package / "scripts" / name).write_bytes((ROOT / "scripts" / name).read_bytes())
            repo = root / "repo"; repo.mkdir()
            config = root / "config.json"; config.write_bytes((ROOT / "config/public-ci.example.json").read_bytes())
            with self.assertRaisesRegex(ValueError, "explicit analysis/publication"):
                installer.install(config, repo, package)
            self.assertEqual(list(repo.iterdir()), [])
            self.assertTrue(any(getattr(module, "__file__", "") == str((package / "scripts/public_ci_budget.py").resolve()) for module in list(sys.modules.values())))

    def test_bootstrap_refuses_unresolved_release_before_network_or_extraction(self):
        spec = importlib.util.spec_from_file_location("csb_bootstrap_test", ROOT / "templates/public-ci/bootstrap.py")
        bootstrap = importlib.util.module_from_spec(spec); spec.loader.exec_module(bootstrap)
        with tempfile.TemporaryDirectory() as directory, patch.object(bootstrap.urllib.request, "build_opener", side_effect=AssertionError("must not fetch")):
            with self.assertRaisesRegex(bootstrap.Refusal, "real fixed release"):
                bootstrap.fetch(json.loads((ROOT / "config/public-ci.example.json").read_bytes()), Path(directory) / "package")

    def test_bootstrap_rejects_unsigned_archive_before_extracting_trusted_code(self):
        spec = importlib.util.spec_from_file_location("csb_bootstrap_unsigned_test", ROOT / "templates/public-ci/bootstrap.py")
        bootstrap = importlib.util.module_from_spec(spec); spec.loader.exec_module(bootstrap)
        data = b"not-an-archive"
        config = configuration()
        config["engine"].update(package_url="https://github.com/example/engine/releases/download/v1/linux.tar.gz", package_sha256=ci.digest(data), package_signer_workflow="example/engine/.github/workflows/release.yml",
                                package_attestation_url="https://github.com/example/engine/releases/download/v1/linux.sigstore.json", package_attestation_sha256=ci.digest(data))
        client = SimpleNamespace(open=lambda *args, **kwargs: io.BytesIO(data))
        verifier_calls = []
        def verify(argv, **kwargs):
            verifier_calls.append(argv)
            return subprocess.CompletedProcess(argv, 1, stdout=b"", stderr=b"")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "package"
            with self.assertRaisesRegex(bootstrap.Refusal, "provenance"):
                bootstrap.fetch(config, output, opener=client, verifier=verify)
            self.assertFalse(output.exists())
            self.assertEqual(verifier_calls[0][verifier_calls[0].index("--predicate-type") + 1], "https://github.com/SSC-SDE/codeshouldbehave/attestations/native-build/v1")
            self.assertIn("--bundle", verifier_calls[0])


if __name__ == "__main__":
    unittest.main()

class ReviewerVerdictTests(unittest.TestCase):
    def test_green_requires_both_designs_unchanged_and_complete(self):
        coverage = dict(complete=True, gaps=[], deferred_details=0)
        artifact = dict(hld_status='no_change_detected_within_scope', lld_status='no_change_detected_within_scope')
        self.assertEqual(ci.review_verdict(coverage, artifact), 'no_change_detected')
        for missing in ({}, dict(artifact, hld_status='unavailable'), dict(artifact, lld_status='incomplete')):
            self.assertEqual(ci.review_verdict(coverage, missing), 'incomplete')
        for gap in (dict(coverage, complete=False), dict(coverage, gaps=['unresolved']), dict(coverage, deferred_details=1)):
            self.assertEqual(ci.review_verdict(gap, artifact), 'incomplete')
        for key in ('hld_status', 'lld_status'):
            changed = dict(artifact, **{key: 'change_detected'})
            self.assertEqual(ci.review_verdict(coverage, changed), 'change_detected')
            self.assertEqual(ci.review_verdict(dict(coverage, complete=False), changed), 'change_detected')

    def test_observed_call_change_survives_incomplete_aggregate(self):
        changes = [{"kind": "call_observation_changed", "resolution": "observed_structure"}]
        self.assertEqual(ci.review_verdict({}, {}, changes), "change_detected")
        self.assertEqual(ci.review_verdict({}, {}, [{"kind": "call_observation_changed", "resolution": "uncertain"}]), "incomplete")

    def test_legacy_and_changed_checks_cannot_claim_green(self):
        self.assertEqual(ci.verdict_conclusion(dict(conclusion='success')), 'neutral')
        self.assertEqual(ci.verdict_conclusion(dict(conclusion='success', verdict='change_detected')), 'neutral')
        self.assertEqual(ci.verdict_conclusion(dict(conclusion='success', verdict='no_change_detected')), 'success')
        self.assertEqual(ci.verdict_conclusion(dict(conclusion='cancelled', verdict='no_change_detected')), 'cancelled')
