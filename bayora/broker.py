"""Isolation Broker - the ONLY component shared by red team, blue team and the
client LLM. Every cross-tenant interaction goes through here.

Isolation guarantees (each maps to a requirement in the problem statement):

 R1  Red payloads are not observable by blue before the test concludes
       -> payloads live sealed in a red-only vault; blue sees commitments only.
 R2  Blue defensive logic is not exposed/inferable by red tooling
       -> policy is sealed in a blue-only vault and executed *inside* the broker
          ("execute, don't reveal"); red gets normalized outcomes + constant-time
          responses so a block is indistinguishable from a model refusal.
 R3  Client LLM stays clean
       -> a brand-new model session per test case + canary tokens to detect leaks.
 R4  Findings can't be invalidated by environmental leakage
       -> an attestation that is only `valid` if every invariant above held and
          the hash-chained audit log verifies.
"""
from __future__ import annotations

import re
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

from .audit import AuditLog
from .crypto import Sealer, commit, sha256, verify_commitment
from .llm import REFUSAL, ToyLLM, is_unsafe

TIMING_BUCKET_S = 0.060          # every response takes a multiple of this
MAX_RULES = 50                   # bound blue policy size (ReDoS / abuse guard)
MAX_PATTERN_LEN = 200
PRISTINE_STATE = ToyLLM().state_hash()   # hash of a never-used model session


class Role(str, Enum):
    RED = "red"
    BLUE = "blue"
    AUDITOR = "auditor"          # orchestrator that triggers runs + reads attestations


class IsolationError(PermissionError):
    """Raised whenever a tenant tries something its role does not allow."""


class TestState(str, Enum):
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"


@dataclass
class TestRecord:
    test_id: str
    state: TestState
    commitments: list[str]
    # --- broker-private, never returned to tenants while the test is live ---
    truth: list[dict] = field(default_factory=list)
    attestation: dict | None = None


class Broker:
    def __init__(self, llm_factory: Callable[[str], ToyLLM] | None = None,
                 timing_bucket_s: float = TIMING_BUCKET_S) -> None:
        self._lock = threading.RLock()
        self._tokens: dict[str, Role] = {}
        # One vault + one key per tenant: tenants never share storage.
        self._sealers = {Role.RED: Sealer(), Role.BLUE: Sealer()}
        self._vault: dict[Role, dict[str, bytes]] = {Role.RED: {}, Role.BLUE: {}}
        self._policy_version = 0
        self._tests: dict[str, TestRecord] = {}
        self._llm_factory = llm_factory or (lambda canary: ToyLLM(canary))
        self._bucket = timing_bucket_s
        self.audit = AuditLog()

    # ------------------------------------------------------------------ auth
    def bootstrap(self) -> dict[str, str]:
        """Issue one capability token per role (demo bootstrap)."""
        with self._lock:
            self._tokens.clear()
            out = {}
            for role in Role:
                tok = f"{role.value}-{secrets.token_urlsafe(18)}"
                self._tokens[tok] = role
                out[role.value] = tok
            self.audit.record("broker", "bootstrap")
            return out

    def _auth(self, token: str, *allowed: Role, action: str, test_id: str | None = None) -> Role:
        role = self._tokens.get(token)
        if role is None:
            self.audit.record("unknown", action, test_id, allowed=False)
            raise IsolationError("invalid token")
        if role not in allowed:
            self.audit.record(role.value, action, test_id, allowed=False)
            raise IsolationError(f"role '{role.value}' may not perform '{action}'")
        return role

    def _get_test(self, test_id: str) -> TestRecord:
        t = self._tests.get(test_id)
        if t is None:
            raise KeyError(f"unknown test {test_id}")
        return t

    # ------------------------------------------------------------------- red
    def red_create_test(self, token: str, payloads: list[str]) -> dict:
        """Red submits attack payloads. They are sealed in red's vault; only
        commitments (hashes) leave the red namespace."""
        with self._lock:
            self._auth(token, Role.RED, action="red.create_test")
            if not payloads:
                raise ValueError("at least one payload required")
            test_id = f"t-{uuid.uuid4().hex[:8]}"
            commitments = []
            for i, payload in enumerate(payloads):
                c, nonce = commit(payload)
                commitments.append(c)
                blob = self._sealers[Role.RED].seal(f"{nonce}\x00{payload}")
                self._vault[Role.RED][f"{test_id}/{i}"] = blob
            self._tests[test_id] = TestRecord(test_id, TestState.CREATED, commitments)
            self.audit.record("red", "red.create_test", test_id,
                              detail_hash=sha256("".join(commitments)))
            return {"test_id": test_id, "commitments": commitments}

    def red_results(self, token: str, test_id: str) -> list[dict]:
        """Red's live view: NORMALIZED. A defense block looks exactly like a
        model refusal, so red learns 'attack failed', never *why* (R2)."""
        with self._lock:
            self._auth(token, Role.RED, action="red.results", test_id=test_id)
            t = self._get_test(test_id)
            self.audit.record("red", "red.results", test_id)
            return [{"index": r["index"], "attack_succeeded": r["attack_succeeded"],
                     "response": r["visible_response"]} for r in t.truth]

    def red_report(self, token: str, test_id: str) -> dict:
        """Post-conclusion debrief for red. Shows which payloads the defense
        stopped, but never the defense's rules."""
        with self._lock:
            self._auth(token, Role.RED, action="red.report", test_id=test_id)
            t = self._require_completed(test_id, "red")
            self.audit.record("red", "red.report", test_id)
            return {"test_id": test_id, "cases": [
                {"index": r["index"], "outcome": r["outcome"]} for r in t.truth]}

    # ------------------------------------------------------------------ blue
    def blue_set_policy(self, token: str, input_block: list[str], output_block: list[str]) -> dict:
        """Blue registers a defense policy. It is sealed; only the broker's
        evaluator ever reads it."""
        with self._lock:
            self._auth(token, Role.BLUE, action="blue.set_policy")
            rules = list(input_block) + list(output_block)
            if len(rules) > MAX_RULES or any(len(r) > MAX_PATTERN_LEN for r in rules):
                raise ValueError("policy too large")
            for r in rules:
                re.compile(r)                      # reject invalid regexes early
            self._policy_version += 1
            blob = self._sealers[Role.BLUE].seal(
                repr({"input": list(input_block), "output": list(output_block)}))
            self._vault[Role.BLUE]["policy"] = blob
            self.audit.record("blue", "blue.set_policy", detail_hash=sha256(blob.decode()))
            return {"version": self._policy_version}

    def blue_get_test(self, token: str, test_id: str) -> dict:
        """Blue's live view of a test: state + commitments. NOT payloads (R1)."""
        with self._lock:
            self._auth(token, Role.BLUE, action="blue.get_test", test_id=test_id)
            t = self._get_test(test_id)
            self.audit.record("blue", "blue.get_test", test_id)
            return {"test_id": test_id, "state": t.state.value, "commitments": t.commitments}

    def blue_report(self, token: str, test_id: str) -> dict:
        """Post-conclusion: payloads are revealed to blue, who can verify them
        against the commitments published at creation time."""
        with self._lock:
            self._auth(token, Role.BLUE, action="blue.report", test_id=test_id)
            t = self._require_completed(test_id, "blue")
            self.audit.record("blue", "blue.report", test_id)
            cases = []
            for r in t.truth:
                nonce, payload = self._red_unseal(test_id, r["index"])
                cases.append({
                    "index": r["index"], "payload": payload, "outcome": r["outcome"],
                    "rule_hit": r["rule_hit"],
                    "commitment_verified": verify_commitment(t.commitments[r["index"]], nonce, payload),
                })
            return {"test_id": test_id, "cases": cases}

    # --------------------------------------------------------------- auditor
    def run_test(self, token: str, test_id: str) -> dict:
        """Execute a test: each payload goes through blue's sealed defense and
        into a FRESH client-LLM session. Returns only the attestation."""
        with self._lock:
            self._auth(token, Role.AUDITOR, action="auditor.run_test", test_id=test_id)
            t = self._get_test(test_id)
            if t.state != TestState.CREATED:
                raise ValueError(f"test already {t.state.value}")
            t.state = TestState.RUNNING
            self.audit.record("auditor", "auditor.run_test", test_id)

            policy = self._load_policy()
            canaries: list[str] = []
            fresh_ok = True
            leaked_canary = False

            for i in range(len(t.commitments)):
                _, payload = self._red_unseal(test_id, i)
                canary = f"CANARY-{secrets.token_hex(6)}"
                llm = self._llm_factory(canary)          # R3: brand-new session per case
                if llm.state_hash() != PRISTINE_STATE:
                    fresh_ok = False
                started = time.perf_counter()
                result = self._evaluate(payload, llm, policy, canary)
                # Cross-session contamination check: does THIS response contain
                # a canary that belongs to a DIFFERENT session?
                if any(c in result["raw_response"] for c in canaries):
                    leaked_canary = True
                canaries.append(canary)
                self._pad_to_bucket(started)             # R2: constant-time response
                result["index"] = i
                result.pop("raw_response")
                t.truth.append(result)

            t.state = TestState.COMPLETED
            self.audit.record("broker", "test.completed", test_id)
            t.attestation = self._attest(t, fresh_ok, leaked_canary)
            return t.attestation

    def attestation(self, token: str, test_id: str) -> dict:
        with self._lock:
            self._auth(token, Role.AUDITOR, Role.RED, Role.BLUE, action="attestation", test_id=test_id)
            t = self._require_completed(test_id, "caller")
            return t.attestation  # type: ignore[return-value]

    def audit_view(self, token: str) -> dict:
        with self._lock:
            self._auth(token, Role.AUDITOR, action="audit.view")
            return {"chain_valid": self.audit.verify_chain(),
                    "denied_attempts": self.audit.denied_count(),
                    "entries": list(self.audit.entries)}

    # ----------------------------------------------------- tenant vault reads
    def read_own_vault(self, token: str, owner: str, key: str) -> str:
        """Generic vault read. A tenant may read ONLY its own namespace."""
        with self._lock:
            role = self._auth(token, Role.RED, Role.BLUE, action=f"vault.read:{owner}")
            if role.value != owner:
                self.audit.record(role.value, f"vault.read:{owner}", allowed=False)
                raise IsolationError(f"{role.value} cannot read {owner}'s namespace")
            blob = self._vault[Role(owner)].get(key)
            if blob is None:
                raise KeyError(key)
            return self._sealers[Role(owner)].unseal(blob)

    # --------------------------------------------------------------- internals
    def _require_completed(self, test_id: str, who: str) -> TestRecord:
        t = self._get_test(test_id)
        if t.state != TestState.COMPLETED:
            self.audit.record(who, "premature_access", test_id, allowed=False)
            raise IsolationError("test still in progress - results are sealed until it concludes")
        return t

    def _red_unseal(self, test_id: str, idx: int) -> tuple[str, str]:
        nonce, payload = self._sealers[Role.RED].unseal(self._vault[Role.RED][f"{test_id}/{idx}"]).split("\x00", 1)
        return nonce, payload

    def _load_policy(self) -> dict:
        blob = self._vault[Role.BLUE].get("policy")
        if blob is None:
            return {"input": [], "output": []}
        import ast
        return ast.literal_eval(self._sealers[Role.BLUE].unseal(blob))

    def _evaluate(self, payload: str, llm: ToyLLM, policy: dict, canary: str) -> dict:
        """Run one payload through [blue input filter] -> LLM -> [blue output filter]."""
        for n, pat in enumerate(policy["input"]):
            if re.search(pat, payload, re.IGNORECASE):
                return self._result("blocked_by_defense", False, REFUSAL, REFUSAL, f"input:{n}")
        raw = llm.respond(payload)
        for n, pat in enumerate(policy["output"]):
            if re.search(pat, raw, re.IGNORECASE):
                return self._result("blocked_by_defense", False, REFUSAL, REFUSAL, f"output:{n}")
        succeeded = is_unsafe(raw, canary)
        outcome = "attack_succeeded" if succeeded else ("model_refused" if raw == REFUSAL else "safe")
        return self._result(outcome, succeeded, raw, raw, None)

    @staticmethod
    def _result(outcome: str, succeeded: bool, visible: str, raw: str, rule: str | None) -> dict:
        return {"outcome": outcome, "attack_succeeded": succeeded,
                "visible_response": visible, "raw_response": raw, "rule_hit": rule}

    def _pad_to_bucket(self, started: float) -> None:
        elapsed = time.perf_counter() - started
        target = (int(elapsed / self._bucket) + 1) * self._bucket
        time.sleep(max(0.0, target - elapsed))

    def _attest(self, t: TestRecord, fresh_ok: bool, leaked_canary: bool) -> dict:
        commitments_ok = True
        for i, c in enumerate(t.commitments):
            nonce, payload = self._red_unseal(t.test_id, i)
            commitments_ok &= verify_commitment(c, nonce, payload)
        chain_ok = self.audit.verify_chain()
        checks = {
            "fresh_llm_session_per_case": fresh_ok,
            "no_cross_session_canary_leak": not leaked_canary,
            "red_commitments_intact": commitments_ok,
            "audit_chain_intact": chain_ok,
        }
        return {
            "test_id": t.test_id,
            "valid": all(checks.values()),
            "checks": checks,
            "cases": len(t.truth),
            "attacks_succeeded": sum(1 for r in t.truth if r["attack_succeeded"]),
            "denied_cross_tenant_attempts": self.audit.denied_count(),
            "audit_head": self.audit.entries[-1]["hash"],
        }
