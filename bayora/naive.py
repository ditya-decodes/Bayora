"""BASELINE: a naive shared sandbox that mirrors the problem statement's
current setup - everyone shares one state dict and one LLM session.
It exists only so the probe suite can show what goes wrong."""
import re
import time

from .llm import REFUSAL, ToyLLM, is_unsafe


class NaiveSandbox:
    def __init__(self) -> None:
        self.shared = {"red_payloads": [], "blue_policy": {"input": [], "output": []}}
        self.llm = ToyLLM()                  # ONE session reused by every test

    # Anyone can read/write shared state - no tenant boundaries.
    def red_submit(self, payloads: list[str]) -> None:
        self.shared["red_payloads"] = list(payloads)

    def blue_set_policy(self, input_block: list[str], output_block: list[str]) -> None:
        self.shared["blue_policy"] = {"input": input_block, "output": output_block}

    def run(self) -> list[dict]:
        results = []
        for p in self.shared["red_payloads"]:
            t0 = time.perf_counter()
            blocked_by = next((pat for pat in self.shared["blue_policy"]["input"]
                               if re.search(pat, p, re.IGNORECASE)), None)
            if blocked_by:   # fast path (no LLM call) + verbose, rule-revealing message
                resp = f"BLOCKED by blue rule: {blocked_by}"
                ok = False
            else:
                resp = self.llm.respond(p)
                ok = is_unsafe(resp, self.llm.canary)
            results.append({"payload": p, "response": resp, "attack_succeeded": ok,
                            "latency_s": time.perf_counter() - t0})
        return results

    def amend_payloads(self, payloads: list[str]) -> None:   # no commitments -> can rewrite history
        self.shared["red_payloads"] = list(payloads)
