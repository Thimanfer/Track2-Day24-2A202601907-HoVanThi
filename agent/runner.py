"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc Guide.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được biến thể 5 (không dấu / lookalike): filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng biến
thể 5, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None) -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from agent import ledger, tools
from agent.policy import PolicyContext, check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
AGENT_ID = "lab24-agent"
_TICKET_RE = re.compile(r"ticket-(\d+)", re.IGNORECASE)


def _args_hash(args: dict) -> str:
    payload = json.dumps(args, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log_call(
    ledger_path: Path,
    run_id: str,
    tool_name: str,
    args: dict,
    classification: str,
    context: PolicyContext,
    decision: str,
    reason: str,
) -> None:
    entry = {
        "ts": _now_iso(),
        "agent_id": AGENT_ID,
        "run_id": run_id,
        "tool": tool_name,
        "args_hash": _args_hash(args),
        "classification": classification,
        "agent_owner": context.agent_owner,
        "request_purpose": context.request_purpose,
        "delegation_depth": context.delegation_depth,
        "egress_enabled": context.egress_enabled,
        "decision": decision,
        "reason": reason,
    }
    ledger.append(entry, ledger_path)


def _guarded_call(
    ledger_path: Path,
    run_id: str,
    tool_name: str,
    args: dict,
    context: PolicyContext,
    classification: str,
    invoke,
):
    allow, reason = check(context)
    if allow:
        _log_call(ledger_path, run_id, tool_name, args, classification, context, "allow", reason)
        return invoke(), True
    _log_call(ledger_path, run_id, tool_name, args, classification, context, "deny", reason)
    return None, False


def _extract_ticket_ids(docs: list[dict]) -> list[int]:
    ticket_ids: set[int] = set()
    for doc in docs:
        doc_id = str(doc.get("id", ""))
        match = _TICKET_RE.search(doc_id)
        if match:
            ticket_ids.add(int(match.group(1)))
    return sorted(ticket_ids)


def _trusted_customers_from_tickets(ticket_ids: list[int]) -> list[str]:
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    resolved: list[str] = []
    for row in customers:
        related = {int(item) for item in row.get("related_tickets", [])}
        if related.intersection(ticket_ids):
            resolved.append(str(row["customer_id"]))
    return sorted(set(resolved))


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    base_dir = log_dir or REPORTS_DIR
    ledger_path = Path(base_dir) / "ledger.jsonl"
    run_id = str(uuid4())

    run_a_ctx = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner="run-a",
        delegation_depth=0,
        egress_enabled=False,
    )
    docs, ok = _guarded_call(
        ledger_path=ledger_path,
        run_id=run_id,
        tool_name="search_docs",
        args={"query": message},
        context=run_a_ctx,
        classification="internal",
        invoke=lambda: tools.search_docs(message),
    )
    if not ok:
        docs = []

    docs = docs or []
    combined_text = "\n\n".join(d.get("text", "") for d in docs)
    injected = llm.find_injection(combined_text)

    ticket_ids = _extract_ticket_ids(docs)
    trusted_customers = _trusted_customers_from_tickets(ticket_ids)

    run_b_ctx = PolicyContext(
        data_classification="restricted",
        request_purpose="reconciliation",
        agent_owner="run-b",
        delegation_depth=1,
        egress_enabled=False,
    )
    collected: list[dict] = []
    for customer_id in trusted_customers:
        record, allowed = _guarded_call(
            ledger_path=ledger_path,
            run_id=run_id,
            tool_name="read_customer",
            args={"customer_id": customer_id},
            context=run_b_ctx,
            classification="restricted",
            invoke=lambda cid=customer_id: tools.read_customer(cid),
        )
        if allowed and record is not None:
            collected.append(record)

    if injected is not None and collected:
        egress_ctx = PolicyContext(
            data_classification="restricted",
            request_purpose="reconciliation",
            agent_owner="run-b",
            delegation_depth=1,
            egress_enabled=True,
        )
        target_url = injected.target_url or "http://localhost:9999/reconcile"
        _guarded_call(
            ledger_path=ledger_path,
            run_id=run_id,
            tool_name="http_post",
            args={"url": target_url, "body": {"records": collected}},
            context=egress_ctx,
            classification="restricted",
            invoke=lambda: tools.http_post(target_url, {"records": collected}),
        )

    return llm.summarize(docs)
