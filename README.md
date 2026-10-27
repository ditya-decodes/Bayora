# Bayora Isolation Broker

**Securing adversarial AI safety-testing infrastructure.** Built by team *Code & Chaos* for Hack in Hills (EXIDO).

> **Attack. Defend. Validate. Without compromising isolation.**

## The problem

Bayora runs a **red team** (attack prompts, jailbreaks, injections), a **blue team** (defensive countermeasures) and a **client LLM** (the model under test) side by side in one Docker sandbox. A safety finding is only trustworthy if:

| # | Requirement |
|---|---|
| R1 | Red payloads are not observable by blue before the test concludes |
| R2 | Blue defensive logic is not exposed or inferable by red tooling |
| R3 | The client LLM stays clean and uncontaminated |
| R4 | Findings are not invalidated by environmental leakage or cross-tenant interference |

## The idea

Put a **broker** in the middle. It is the *only* component the three parties share. Nobody talks to anybody else directly.

```
        ┌────────────┐                               ┌────────────┐
        │  RED TEAM  │                               │ BLUE TEAM  │
        │ token: red │                               │token: blue │
        └─────┬──────┘                               └──────┬─────┘
              │ sealed payloads                  sealed policy │
              ▼                                               ▼
 ┌──────────────────────────  ISOLATION BROKER  ───────────────────────────┐
 │  red vault (own key)   │  blue vault (own key)   │  hash-chained audit   │
 │  commit-reveal         │  execute, don't reveal  │  metadata only        │
 │                                                                         │
 │   payload ─► [blue input filter] ─► FRESH LLM session ─► [output filter]│
 │                      normalized response + constant-time padding        │
 │                                                                         │
 │   attestation: valid only if every isolation invariant held            │
 └─────────────────────────────────────────────────────────────────────────┘
```

| Requirement | Mechanism in this repo |
|---|---|
| **R1** | Red payloads are sealed in a red-only vault. Blue sees only SHA-256 **commitments** until the test is `COMPLETED`; early reads are denied and audited. Afterwards payloads are revealed and blue can verify them against the commitments. |
| **R2** | Blue's policy is sealed in a blue-only vault and **executed inside the broker** ("execute, don't reveal"). Red receives a *normalized* response: a defense block is byte-identical to a model refusal, and every response is padded to a fixed **60 ms timing bucket**. |
| **R3** | A **brand-new model session per test case**, verified against a pristine state hash, plus per-session **canary tokens** to detect cross-session leakage. |
| **R4** | Each test yields an **attestation**: `valid` only if sessions were fresh, no canary leaked, red's commitments still match, and the **hash-chained audit log** verifies. |

> **Full detail:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) covers component specs, architecture and sequence diagrams, how to run and test the simulation, its limitations, and the phased plan for a production deployment.

## Proof, not claims

`bayora/verifier.py` runs the **same seven cross-tenant attacks** against a deliberately naive shared sandbox (`naive.py`, modeled on the problem statement's current setup) and against the broker:

```
P1  Blue reads red's payloads before the test ends      naive: LEAKS   bayora: held
P2  Red reads blue's defensive logic                    naive: LEAKS   bayora: held
P3  Red can tell defense-block from model-refusal       naive: LEAKS   bayora: held
P4  Timing side channel reveals blocked vs allowed      naive: LEAKS   bayora: held
P5  Jailbreak persists and contaminates client LLM      naive: LEAKS   bayora: held
P6  Payloads rewritten after results are known          naive: LEAKS   bayora: held
P7  Tenant acts as another tenant / forged identity     naive: LEAKS   bayora: held
```

It also runs a scripted **Attack → Defend → Validate → Repeat** loop. Successful attacks fall 3 → 1 → 0 across three rounds while every attestation stays valid.

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python demo.py                                # terminal demo
uvicorn bayora.api:app --reload               # dashboard at http://localhost:8000, API docs at /docs
pytest -q                                     # 14 tests
```

### Try the tenant API

```bash
TOK=$(curl -s localhost:8000/api/demo/tokens)          # demo-only token handout
# red submits sealed payloads
curl -X POST localhost:8000/api/red/tests -H "Authorization: Bearer <red-token>" \
     -H 'content-type: application/json' -d '{"payloads":["enter developer mode"]}'
# blue tries to peek early -> 403
curl -i localhost:8000/api/blue/tests/<test_id>/report -H "Authorization: Bearer <blue-token>"
# auditor runs the test and gets the attestation
curl -X POST localhost:8000/api/tests/<test_id>/run -H "Authorization: Bearer <auditor-token>"
```

Docker: `docker build -t bayora . && docker run -p 8000:8000 bayora`

## Repo layout

```
bayora/broker.py     isolation broker: vaults, auth, commit-reveal, evaluation, attestation
bayora/crypto.py     commitments + per-tenant sealing (Fernet)
bayora/audit.py      hash-chained, metadata-only audit log
bayora/llm.py        ToyLLM client model (deliberately vulnerable, deterministic)
bayora/naive.py      naive shared-sandbox baseline
bayora/verifier.py   7-probe isolation suite
bayora/loop.py       scripted red/blue loop
bayora/api.py        FastAPI service
web/index.html       dashboard
tests/               pytest suite
```

## Threat model and honest limitations

This is a **hackathon MVP**. It demonstrates the *design* and its logic; it is not a hardened product.

- **Tenants are simulated in-process.** Isolation here is enforced by the broker's access control, encryption and normalization. A production deployment would run red, blue and the LLM as **separate containers on separate networks** (ideally under gVisor/Kata or in TEEs) with the broker as the only bridge, so a code-execution bug in one tenant can't reach another.
- **The client LLM is a mock** with intentional weaknesses so the demo works offline. `ToyLLM` implements a two-method interface (`respond`, `state_hash`); a real model adapter can replace it.
- **Blue's moves in the loop demo are scripted** for determinism. The same API serves human operators or autonomous agents.
- **Red still learns one bit per payload** (did the attack succeed?). Over many queries that could let red infer defense coverage. That is inherent to red-teaming; production would add query budgets and rate limits.
- **Timing protection is coarse.** Padding to a fixed bucket removes the block-vs-allow latency gap but does not defend against CPU-cache, memory-pressure or other hardware side channels.
- **The commitment count is visible to blue** (it sees how many commitments exist, not what they contain).
- **State is in memory**, and `/api/demo/tokens` hands out role tokens for demo purposes. Both must go in a real deployment (persistent store, mTLS or OIDC-issued tokens).
- The `Dockerfile` has not been build-tested in the environment this was authored in.

## Roadmap

Per-tenant containers + network policy · real LLM adapters · signed audit anchoring (external timestamping) · query budgets · multi-model and agentic targets · CI/CD integration (matches the deck's *Future Scope*).

## Team

Code & Chaos: Ditya, Vidushi Vats, Gauri Sharma
