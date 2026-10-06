"""针对运行中的服务执行 API 冒烟。

用法::

    python scripts/smoke.py [BASE_URL]

覆盖：健康检查、跨块（每块 1 字节）合法会话且含 NAK 重传、校验失败、
方向越权、非原样重传、坏 Base64。全部通过则以退出码 0 结束。
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


def result_set_events(payload: bytes, fsize: int = 240, nak_frames=()) -> list:
    """把结果集正文按 fsize 切成多帧会话（帧边界可落在记录/字段任意位置）。"""
    pieces = [payload[i : i + fsize] for i in range(0, len(payload), fsize)]
    events = [("sender", bytes([ENQ])), ("receiver", bytes([ACK]))]
    for i, piece in enumerate(pieces):
        fn_num = (i % 8) + 1  # 1..8，其中 8 对应循环帧号 0
        if fn_num == 8:
            fn_num = 0
        term = ETB if i < len(pieces) - 1 else ETX
        frame = make_frame(fn_num, piece, terminator=term)
        events.append(("sender", frame))
        if i in nak_frames:
            events.extend(
                [
                    ("receiver", bytes([NAK])),
                    ("sender", frame),  # 原样重传
                    ("receiver", bytes([ACK])),
                ]
            )
        else:
            events.append(("receiver", bytes([ACK])))
    events.append(("sender", bytes([EOT])))
    return events


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

    # 6) recordAudit=result_set：默认省略时响应语义不变
    status, body = request(
        "POST",
        "/api/astm/sessions/audit",
        {"sender": "analyzer-A", "chunks": to_chunks(events, piece=1)},
    )
    check(
        "省略 recordAudit 时响应不含结果集字段（默认兼容）",
        status == 200 and "patients" not in body and "record_audit" not in body,
        f"status={status}, body={body}",
    )

    # 7) recordAudit=result_set：跨帧记录的合法结果集
    result_set = (
        b"H|\\^&|||analyzer^1.0\r"
        b"P|1||P123\r"
        b"O|1||S1^^^ASTM^M|||\r"
        b"R|1||^^^GLU^M|5.1\r"
        b"R|2||^^^NA^M|140\r"
        b"P|2||P124\r"
        b"O|1||S2^^^ASTM^M|||\r"
        b"R|1||^^^K^M|4.0\r"
        b"L|"
    )
    rs_events = result_set_events(result_set, fsize=13)
    status, body = request(
        "POST",
        "/api/astm/sessions/audit",
        {
            "sender": "analyzer-A",
            "recordAudit": "result_set",
            "chunks": to_chunks(rs_events, piece=2),
        },
    )
    ok = (
        status == 200
        and body.get("record_audit") == "result_set"
        and (body.get("patients"), body.get("orders"), body.get("results")) == (2, 2, 3)
        and body.get("patient_ids") == ["P123", "P124"]
        and body.get("sample_ids") == ["S1^^^ASTM^M", "S2^^^ASTM^M"]
        and body.get("result_counts") == [2, 1]
    )
    check("结果集审计（跨帧记录）返回计数与标识", ok, f"status={status}, body={body}")

    # 8) recordAudit=result_set：语义失败（患者 2 序号跳变）→ 422 稳定错误码
    bad_rs = result_set.replace(b"P|2||P124", b"P|3||P124")
    status, body = request(
        "POST",
        "/api/astm/sessions/audit",
        {
            "sender": "analyzer-A",
            "recordAudit": "result_set",
            "chunks": to_chunks(result_set_events(bad_rs, fsize=11), piece=3),
        },
    )
    ok = (
        status == 422
        and body.get("code") == "RESULT_SEQUENCE_SKIP"
        and isinstance(body.get("block_index"), int)
        and isinstance(body.get("position"), int)
    )
    check("结果集语义失败返回 422 稳定错误码并定位", ok, f"status={status}, body={body}")

    # 9) recordAudit 非法取值 → 400
    status, body = request(
        "POST",
        "/api/astm/sessions/audit",
        {
            "sender": "analyzer-A",
            "recordAudit": "full",
            "chunks": [{"direction": "sender", "data": ""}],
        },
    )
    check(
        "非法 recordAudit 返回 400（INVALID_REQUEST）",
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
