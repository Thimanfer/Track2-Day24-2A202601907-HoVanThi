"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re


_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_CCCD_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
_PHONE_CANDIDATE_RE = re.compile(r"(?<!\d)0[\d\s.\-]{8,14}\d(?!\d)")
_BANK_RE = re.compile(r"(?<!\d)\d{8,16}(?!\d)")


def detect(text: str) -> list[dict]:
    entities: list[dict] = []

    def overlaps(start: int, end: int) -> bool:
        for item in entities:
            if start < item["end"] and item["start"] < end:
                return True
        return False

    def add(kind: str, start: int, end: int) -> None:
        if start >= end:
            return
        if overlaps(start, end):
            return
        entities.append({"type": kind, "start": start, "end": end})

    for match in _EMAIL_RE.finditer(text):
        add("EMAIL", match.start(), match.end())

    for match in _PHONE_CANDIDATE_RE.finditer(text):
        raw = match.group(0)
        digits = "".join(ch for ch in raw if ch.isdigit())
        if digits.startswith("0") and 10 <= len(digits) <= 11:
            add("VN_PHONE", match.start(), match.end())

    for match in _BANK_RE.finditer(text):
        raw = match.group(0)
        if len(raw) == 12:
            # 12-digit values are ambiguous with CCCD; only treat as bank
            # account when explicit account context appears nearby.
            context = text[max(0, match.start() - 24) : match.start()].lower()
            if "stk" not in context and "tai khoan" not in context and "tài khoản" not in context:
                continue
        add("VN_BANK_ACCOUNT", match.start(), match.end())

    for match in _CCCD_RE.finditer(text):
        add("VN_CCCD", match.start(), match.end())

    entities.sort(key=lambda item: (item["start"], item["end"]))
    return entities


def redact(text: str) -> str:
    entities = sorted(detect(text), key=lambda item: item["start"], reverse=True)
    redacted = text
    for entity in entities:
        token = f"[REDACTED_{entity['type']}]"
        redacted = redacted[: entity["start"]] + token + redacted[entity["end"] :]
    return redacted
