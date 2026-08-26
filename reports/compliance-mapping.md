# Compliance mapping

Trong bài này, em đối chiếu các control em đã làm với từng yêu cầu. Phần nào
chưa nằm trong phạm vi lab thì em ghi rõ, thay vì coi như đã hoàn thành.

| Requirement | Control em áp dụng | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | Em chưa làm delete-cascade cho dữ liệu khách hàng. Phần em làm trong lab là chặn egress và giữ audit trail để dễ kiểm tra sự cố. | — |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Em lập inventory luồng dữ liệu và tách rõ `--mock` với `--model`. Khi dùng model thật, em coi việc gửi nội dung ticket sang model provider là một luồng cần được ghi nhận. | `reports/dpia-lite.md:46-49`, `agent/loop.py:86-93` |
| ASI03 — privilege abuse | Em đặt PEP trước tool call. Dữ liệu `restricted` không được egress; mỗi lần allow/deny đều có `run_id`, `agent_owner`, `decision` và `reason` trong ledger. TTL credential riêng chưa được triển khai trong phạm vi lab này. | `agent/policy.py:39-60`, `agent/runner.py:91-105`, `agent/runner.py:201-213`, `reports/ledger.jsonl` |
| ASI01 — goal hijack | Em tách Run A và Run B. Run B chỉ lấy customer từ ánh xạ đáng tin cậy `related_tickets`, không lấy customer ID từ nội dung tự do do attacker chèn vào. | `agent/runner.py:125-142`, `agent/runner.py:163-175`, `tests/test_split.py` |
| ISO 42001 Clause 5-6 | Em viết policy thành code có thể chạy test và kiểm tra lại bằng ledger. Phần review qua 4 commit riêng vẫn cần được bổ sung trước khi nộp repo Git. | `agent/policy.py:39-60`, `tests/test_policy.py`, `tests/test_ledger.py`, `reports/ledger.jsonl` |
