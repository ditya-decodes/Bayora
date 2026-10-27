"""FastAPI surface for the Isolation Broker.

Tenant endpoints take a bearer token (capability per role). The /api/demo/*
endpoints run the self-contained showcase used by the dashboard.
"""
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .broker import Broker, IsolationError
from .loop import run_loop_demo
from .verifier import run_probe_suite

app = FastAPI(title="Bayora Isolation Broker", version="0.1.0")
broker = Broker()
tokens = broker.bootstrap()
WEB = Path(__file__).resolve().parent.parent / "web"


def bearer(authorization: str = Header(default="")) -> str:
    return authorization.removeprefix("Bearer ").strip()


def guarded(fn, *args):
    """Translate broker errors into HTTP codes."""
    try:
        return fn(*args)
    except IsolationError as e:
        raise HTTPException(403, str(e))
    except KeyError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))


class Payloads(BaseModel):
    payloads: list[str] = Field(min_length=1, max_length=200)


class Policy(BaseModel):
    input_block: list[str] = []
    output_block: list[str] = []


# ------------------------------------------------------------------ tenants
@app.get("/api/demo/tokens")
def demo_tokens():
    """DEMO ONLY: hands out the role tokens so you can try the API with curl."""
    return tokens


@app.post("/api/red/tests")
def red_create(body: Payloads, tok: str = Depends(bearer)):
    return guarded(broker.red_create_test, tok, body.payloads)


@app.get("/api/red/tests/{test_id}/results")
def red_results(test_id: str, tok: str = Depends(bearer)):
    return guarded(broker.red_results, tok, test_id)


@app.get("/api/red/tests/{test_id}/report")
def red_report(test_id: str, tok: str = Depends(bearer)):
    return guarded(broker.red_report, tok, test_id)


@app.put("/api/blue/policy")
def blue_policy(body: Policy, tok: str = Depends(bearer)):
    return guarded(broker.blue_set_policy, tok, body.input_block, body.output_block)


@app.get("/api/blue/tests/{test_id}")
def blue_test(test_id: str, tok: str = Depends(bearer)):
    return guarded(broker.blue_get_test, tok, test_id)


@app.get("/api/blue/tests/{test_id}/report")
def blue_report(test_id: str, tok: str = Depends(bearer)):
    return guarded(broker.blue_report, tok, test_id)


@app.post("/api/tests/{test_id}/run")
def run(test_id: str, tok: str = Depends(bearer)):
    return guarded(broker.run_test, tok, test_id)


@app.get("/api/tests/{test_id}/attestation")
def attestation(test_id: str, tok: str = Depends(bearer)):
    return guarded(broker.attestation, tok, test_id)


@app.get("/api/audit")
def audit(tok: str = Depends(bearer)):
    return guarded(broker.audit_view, tok)


# --------------------------------------------------------------------- demo
@app.get("/api/demo/probes")
def demo_probes():
    return run_probe_suite()


@app.get("/api/demo/loop")
def demo_loop():
    return run_loop_demo()


@app.get("/")
def index():
    return FileResponse(WEB / "index.html")
