"""Terminal demo: python demo.py"""
from bayora.loop import run_loop_demo
from bayora.verifier import run_probe_suite

print("=== Isolation probes: naive shared sandbox vs Bayora broker ===\n")
r = run_probe_suite()
for p in r["probes"]:
    n = "LEAKS" if p["naive"]["leaks"] else "held "
    b = "LEAKS" if p["bayora"]["leaks"] else "held "
    print(f'{p["id"]}  naive: {n}  bayora: {b}   {p["title"]}')
print(f'\nNaive sandbox broke {r["naive_leaks"]}/{r["total"]} boundaries; Bayora broke {r["bayora_leaks"]}/{r["total"]}.\n')

print("=== Attack -> Defend -> Validate -> Repeat ===\n")
d = run_loop_demo()
for rd in d["rounds"]:
    status = "valid" if rd["valid"] else "INVALID"
    print(f'{rd["round"]}: {rd["attacks_succeeded"]}/{rd["total"]} attacks succeeded (attestation {status})')
print(f'\nAudit log: {d["audit_entries"]} entries, chain verified = {d["audit_chain_valid"]}')
