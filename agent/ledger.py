"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc Guide.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu bất kỳ dòng nào bị sửa/xoá/chèn giữa file, hoặc
        thiếu reason.

Sinh viên phải tự tay chứng minh được: sửa 1 ký tự trong 1 dòng giữa file
rồi gọi verify() phải trả về False.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


_GENESIS = "0" * 64


def _canonical_hash_payload(entry: dict) -> str:
    payload = json.dumps(entry, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _read_last_hash(path: Path) -> str:
    if not path.exists():
        return _GENESIS
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return _GENESIS
    try:
        last = json.loads(lines[-1])
    except json.JSONDecodeError:
        return _GENESIS
    return str(last.get("hash", _GENESIS))


def append(entry: dict, path: Path) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    prev_hash = _read_last_hash(path)

    payload = dict(entry)
    payload["prev_hash"] = prev_hash
    payload_hash = _canonical_hash_payload(payload)
    payload["hash"] = payload_hash

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    return payload


def verify(path: Path) -> bool:
    if not path.exists():
        return True

    prev = _GENESIS
    with path.open(encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if not raw:
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError:
                return False

            reason = row.get("reason")
            if not isinstance(reason, str) or not reason.strip():
                return False

            if row.get("prev_hash") != prev:
                return False

            stored_hash = row.get("hash")
            if not isinstance(stored_hash, str) or len(stored_hash) != 64:
                return False

            payload = dict(row)
            payload.pop("hash", None)
            recomputed = _canonical_hash_payload(payload)
            if recomputed != stored_hash:
                return False

            prev = stored_hash

    return True
