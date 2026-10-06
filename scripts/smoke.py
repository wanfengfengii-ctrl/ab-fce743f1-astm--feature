"""针对运行中的服务执行 API 冒烟。

用法::

    python scripts/smoke.py [BASE_URL]

覆盖：健康检查、跨块（每块 1 字节）合法会话且含 NAK 重传、校验失败、
方向越权、非原样重传、坏 Base64，以及 recordAudit=result_set 的默认兼容、
跨帧结果集成功与语义失败。全部通过则以退出码 0 结束。
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"

STX, ETX, EOT, ENQ, ACK, NAK, CR, LF = 0x02, 0x03, 0x04, 0x05, 0x06, 0x15, 0x0D, 0x0A
ETB = 0x17


def make_frame(fn: int, payload: bytes, terminator: int = ETB) -> bytes:
    body = bytes([ord(str(fn))]) + payload
    checksum = (sum(body) + terminator) & 0xFF
    return bytes([STX]) + body + bytes([terminator]) + f"{checksum:02X}".encode() + bytes([CR, LF])


def request(method: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        BASE_URL + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def wait_for_health(timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            status, body = request("GET", "/health")
            if status == 200 and body.get("status") == "ok":
                return
        except OSError as exc:  # 服务尚未就绪
            last_error = exc
        time.sleep(0.5)
    raise SystemExit(f"健康检查在 {timeout}s 内未通过：{last_error}")


def to_chunks(events, piece: int = 1) -> list[dict]:
    chunks: list[dict] = []
    for direction, raw in events:
        for i in range(0, len(raw), piece):
            chunks.append(
                {
                    "direction": direction,
                    "data": base64.b64encode(raw[i : i + piece]).decode(),
                }
            )
    return chunks


RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail and not ok else ""))


def main() -> int:
    wait_for_health()
    check("健康检查 GET /health", True)

    f1 = make_frame(1, b"H|\\^&|||analyzer^1.0")
    f2 = make_frame(2, b"O|1||^^^ASTM^M|||", terminator=ETX)
    expected_payload = b"H|\\^&|||analyzer^1.0" + b"O|1||^^^ASTM^M|||"
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", f1),
        ("receiver", bytes([NAK])),
        ("sender", f1),  # 原样重传
        ("receiver", bytes([ACK])),
        ("sender", f2),
        ("receiver", bytes([ACK])),
        ("sender", bytes([EOT])),
    ]

    # 1) 合法会话：跨块（1 字节/块）+ 重传
    status, body = request(
        "POST",
        "/api/astm/sessions/audit",
        {"sender": "analyzer-A", "chunks": to_chunks(events, piece=1)},
    )
    ok = (
        status == 200
        and body.get("frame_count") == 2
        and body.get("retransmissions") == 1
        and body.get("sha256") == hashlib.sha256(expected_payload).hexdigest()
        and body.get("payload_bytes") == len(expected_payload)
    )
    check("跨块合法会话（含 1 次重传）返回重组结果", ok, f"status={status}, body={body}")

    # 2) 校验失败：破坏 f2 的校验和，且跨块提交
    bad_f2 = bytearray(f2)
    bad_f2[-3] = ord("0") if bad_f2[-3] != ord("0") else ord("1")
    bad_events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", make_frame(1, b"abc")),
        ("receiver", bytes([ACK])),
        ("sender", bytes(bad_f2)),
    ]
    status, body = request(
        "POST",
        "/api/astm/sessions/audit",
        {"sender": "analyzer-A", "chunks": to_chunks(bad_events, piece=3)},
    )
    ok = (
        status == 422
        and body.get("code") == "CHECKSUM_FAILED"
        and isinstance(body.get("block_index"), int)
        and isinstance(body.get("position"), int)
    )
    check("校验失败被拒绝并定位首个出错块位置", ok, f"status={status}, body={body}")

    # 3) 方向越权：会话由 receiver 发起
    status, body = request(
        "POST",
        "/api/astm/sessions/audit",
        {
            "sender": "analyzer-A",
            "chunks": to_chunks(
                [("receiver", bytes([ENQ]))],
                piece=1,
            ),
        },
    )
    check(
        "方向越权被拒绝（DIRECTION_VIOLATION）",
        status == 422 and body.get("code") == "DIRECTION_VIOLATION",
        f"status={status}, body={body}",
    )

    # 4) 非原样重传：NAK 后帧内容被改动
    f_good = make_frame(1, b"abc")
    f_changed = make_frame(1, b"abd")
    rt_events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", f_good),
        ("receiver", bytes([NAK])),
        ("sender", f_changed),
    ]
    status, body = request(
        "POST",
        "/api/astm/sessions/audit",
        {"sender": "analyzer-A", "chunks": to_chunks(rt_events, piece=2)},
    )
    check(
        "非原样重传被拒绝（NON_IDENTICAL_RETRANSMISSION）",
        status == 422 and body.get("code") == "NON_IDENTICAL_RETRANSMISSION",
        f"status={status}, body={body}",
    )

    # 5) 坏 Base64 → 400
    status, body = request(
        "POST",
        "/api/astm/sessions/audit",
        {"sender": "analyzer-A", "chunks": [{"direction": "sender", "data": "@@@"}]},
    )
    check(
        "坏 Base64 返回 400（BAD_BASE64）",
        status == 400 and body.get("code") == "BAD_BASE64",
        f"status={status}, body={body}",
    )

    # 6) recordAudit 省略：响应结构保持原样（无结果集字段）
    result_body = (
        b"H|\\^&|||analyzer^1.0\r"
        b"P|1||PAT001\r"
        b"O|1||SAMP01||||\r"
        b"R|1||GLU||5.0\r"
        b"R|2||HGB||130\r"
        b"P|2||PAT002\r"
        b"O|1||SAMP02||||\r"
        b"R|1||GLU||6.1\r"
        b"L|1"
    )

    def result_events(data: bytes, piece: int = 3) -> list:
        evts = [
            ("sender", bytes([ENQ])),
            ("receiver", bytes([ACK])),
        ]
        frame_no = 1
        first = True
        for i in range(0, len(data), piece):
            frame = make_frame(frame_no, data[i : i + piece])
            evts.append(("sender", frame))
            if first:
                # 首帧经历一次 NAK 原样重传
                evts.append(("receiver", bytes([NAK])))
                evts.append(("sender", frame))
            evts.append(("receiver", bytes([ACK])))
            first = False
            frame_no = 1 if frame_no == 0 else (frame_no + 1 if frame_no < 7 else 0)
        evts.append(("sender", bytes([EOT])))
        return evts

    status, body = request(
        "POST",
        "/api/astm/sessions/audit",
        {"sender": "analyzer-A", "chunks": to_chunks(result_events(result_body), piece=1)},
    )
    old_keys = {"ok", "sender", "payload", "payload_bytes", "frame_count", "retransmissions", "sha256"}
    check(
        "省略 recordAudit 时响应与旧版完全兼容",
        status == 200 and set(body.keys()) == old_keys,
        f"status={status}, keys={set(body.keys()) if isinstance(body, dict) else body}",
    )

    # 7) recordAudit=result_set：跨帧记录（3 字节/帧）+ 重传，返回计数与标识
    status, body = request(
        "POST",
        "/api/astm/sessions/audit",
        {
            "sender": "analyzer-A",
            "recordAudit": "result_set",
            "chunks": to_chunks(result_events(result_body), piece=1),
        },
    )
    ok = (
        status == 200
        and body.get("patient_count") == 2
        and body.get("order_count") == 2
        and body.get("result_count") == 3
        and body.get("patient_ids") == ["PAT001", "PAT002"]
        and body.get("sample_ids") == ["SAMP01", "SAMP02"]
        and body.get("result_counts") == [2, 1]
        and body.get("retransmissions") == 1
    )
    check("结果集复核成功（跨帧 + 重传）返回计数与标识", ok, f"status={status}, body={body}")

    # 8) recordAudit=result_set：语义失败（同患者重复样本号）→ 422 稳定错误码
    dup_body = (
        b"H|\\^&\rP|1||P1\r"
        b"O|1||S1\rR|1||T1||1\r"
        b"O|2||S1\rR|1||T2||2\rL|1"
    )
    status, body = request(
        "POST",
        "/api/astm/sessions/audit",
        {
            "sender": "analyzer-A",
            "recordAudit": "result_set",
            "chunks": to_chunks(result_events(dup_body, piece=2), piece=1),
        },
    )
    check(
        "结果集语义失败返回 422（DUPLICATE_SAMPLE_ID）并定位块",
        status == 422
        and body.get("code") == "DUPLICATE_SAMPLE_ID"
        and isinstance(body.get("block_index"), int)
        and isinstance(body.get("position"), int),
        f"status={status}, body={body}",
    )

    # 9) 非法 recordAudit 取值 → 400
    status, body = request(
        "POST",
        "/api/astm/sessions/audit",
        {
            "sender": "analyzer-A",
            "recordAudit": "full",
            "chunks": to_chunks(result_events(result_body), piece=1),
        },
    )
    check(
        "非法 recordAudit 取值返回 400（INVALID_REQUEST）",
        status == 400 and body.get("code") == "INVALID_REQUEST",
        f"status={status}, body={body}",
    )

    failed = [name for name, ok, _ in RESULTS if not ok]
    print(f"\n冒烟结果：{len(RESULTS) - len(failed)}/{len(RESULTS)} 通过")
    if failed:
        print("失败项：" + ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
