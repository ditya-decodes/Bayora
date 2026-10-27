"""Hash-chained audit log. Records METADATA only (never payload or policy
content), so the log itself cannot become a side channel."""
import json
import time

from .crypto import sha256


class AuditLog:
    def __init__(self) -> None:
        self.entries: list[dict] = []

    def record(self, tenant: str, action: str, test_id: str | None = None,
               allowed: bool = True, detail_hash: str | None = None) -> dict:
        prev = self.entries[-1]["hash"] if self.entries else "GENESIS"
        body = {
            "seq": len(self.entries),
            "ts": round(time.time(), 3),
            "tenant": tenant,
            "action": action,
            "test_id": test_id,
            "allowed": allowed,
            "detail_hash": detail_hash,
            "prev": prev,
        }
        body["hash"] = sha256(json.dumps(body, sort_keys=True))
        self.entries.append(body)
        return body

    def verify_chain(self) -> bool:
        prev = "GENESIS"
        for e in self.entries:
            body = {k: v for k, v in e.items() if k != "hash"}
            if e["prev"] != prev or sha256(json.dumps(body, sort_keys=True)) != e["hash"]:
                return False
            prev = e["hash"]
        return True

    def denied_count(self) -> int:
        return sum(1 for e in self.entries if not e["allowed"])
