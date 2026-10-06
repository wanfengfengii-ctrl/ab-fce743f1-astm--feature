"""ASTM 复核引擎与 API 的测试。"""

from __future__ import annotations

import base64
import hashlib

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.protocol import (
    ACK,
    CR,
    ENQ,
    EOT,
    ETB,
    ETX,
    LF,
    NAK,
    STX,
    ProtocolViolation,
    audit,
    parse_request,
)

client = TestClient(app)


def make_frame(fn: int, payload: bytes, terminator: int = ETB) -> bytes:
    """按线路格式构造一帧。"""
    body = bytes([ord(str(fn))]) + payload
    checksum = (sum(body) + terminator) & 0xFF
    return bytes([STX]) + body + bytes([terminator]) + f"{checksum:02X}".encode() + bytes([CR, LF])


def chunks_for(events, piece: int):
    """把 [(direction, bytes), ...] 按固定小块再切分（同方向段内部切）。"""
    out = []
    for direction, data in events:
        for i in range(0, len(data), piece):
            out.append((direction, data[i : i + piece]))
    return out


def valid_events():
    """ENQ/ACK -> 帧1 -> NAK -> 原样重传帧1 -> ACK -> 帧2(ETX) -> ACK -> EOT。"""
    f1 = make_frame(1, b"H|\\^&|||analyzer^1.0")
    f2 = make_frame(2, b"O|1||^^^ASTM^M|||", terminator=ETX)
    return [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", f1),
        ("receiver", bytes([NAK])),
        ("sender", f1),
        ("receiver", bytes([ACK])),
        ("sender", f2),
        ("receiver", bytes([ACK])),
        ("sender", bytes([EOT])),
    ]


EXPECTED_PAYLOAD = b"H|\\^&|||analyzer^1.0" + b"O|1||^^^ASTM^M|||"


def test_valid_session_with_retransmission():
    result = audit("analyzer-A", valid_events())
    assert result["ok"] is True
    assert result["frame_count"] == 2
    assert result["retransmissions"] == 1
    assert result["payload_bytes"] == len(EXPECTED_PAYLOAD)
    assert result["sha256"] == hashlib.sha256(EXPECTED_PAYLOAD).hexdigest()


@pytest.mark.parametrize("piece", [1, 2, 3, 5, 7, 13, 64, 4096])
def test_chunking_invariance(piece):
    result = audit("x", chunks_for(valid_events(), piece))
    assert result["frame_count"] == 2
    assert result["retransmissions"] == 1
    assert result["sha256"] == hashlib.sha256(EXPECTED_PAYLOAD).hexdigest()


def test_frame_number_cycles_1_to_7_then_0():
    events = [("sender", bytes([ENQ])), ("receiver", bytes([ACK]))]
    payloads = []
    for fn in [1, 2, 3, 4, 5, 6, 7, 0, 1]:
        data = f"P{fn}".encode()
        payloads.append(data)
        events += [
            ("sender", make_frame(fn, data)),
            ("receiver", bytes([ACK])),
        ]
    events.append(("sender", bytes([EOT])))
    result = audit("x", events)
    assert result["frame_count"] == 9
    assert result["sha256"] == hashlib.sha256(b"".join(payloads)).hexdigest()


def expect_violation(events, code):
    with pytest.raises(ProtocolViolation) as exc:
        audit("x", events)
    assert exc.value.code == code
    return exc.value


def test_must_start_with_enq():
    events = list(valid_events())
    events[0] = ("sender", bytes([ACK]))
    expect_violation(events, "STAGE_ORDER")


def test_first_byte_direction_must_be_sender():
    events = list(valid_events())
    events[0] = ("receiver", bytes([ENQ]))
    expect_violation(events, "DIRECTION_VIOLATION")


def test_enq_requires_ack():
    events = list(valid_events())
    events[1] = ("receiver", bytes([NAK]))
    expect_violation(events, "STAGE_ORDER")


def test_frame_number_skip_rejected():
    events = [("sender", bytes([ENQ])), ("receiver", bytes([ACK]))]
    events += [("sender", make_frame(2, b"x")), ("receiver", bytes([ACK]))]
    events.append(("sender", bytes([EOT])))
    expect_violation(events, "FRAME_NUMBER_SKIP")


def test_frame_number_skip_after_wrap_rejected():
    # 0 之后必须是 1，发 2 即跳变
    events = [("sender", bytes([ENQ])), ("receiver", bytes([ACK]))]
    for fn in [1, 2, 3, 4, 5, 6, 7, 0]:
        events += [("sender", make_frame(fn, b"x")), ("receiver", bytes([ACK]))]
    events += [("sender", make_frame(2, b"y")), ("receiver", bytes([ACK]))]
    events.append(("sender", bytes([EOT])))
    expect_violation(events, "FRAME_NUMBER_SKIP")


def test_bad_checksum_rejected_and_position_points_into_block():
    good = make_frame(1, b"abc")
    bad = bytearray(good)
    bad[-3] = ord("0")  # 第 2 个校验和十六进制位改错
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", bytes(bad)),
    ]
    exc = expect_violation(events, "CHECKSUM_FAILED")
    assert exc.block_index == 2
    assert exc.position == len(bad) - 3  # 0 基位置，指向出错的校验和字节


def test_lowercase_checksum_rejected():
    good = make_frame(1, b"abc")  # 校验和为 6E
    bad = good[:-3] + good[-3:].replace(b"E", b"e")
    assert bad != good
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", bad),
        ("receiver", bytes([ACK])),
        ("sender", bytes([EOT])),
    ]
    expect_violation(events, "CHECKSUM_FAILED")


def test_missing_crlf_rejected():
    good = make_frame(1, b"abc")
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", good[:-2] + bytes([CR, CR])),
    ]
    expect_violation(events, "INVALID_TERMINATOR")


def test_non_identical_retransmission_rejected():
    f1 = make_frame(1, b"abc")
    f1_alt = make_frame(1, b"abd")  # 仅正文最后一个字节不同
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", f1),
        ("receiver", bytes([NAK])),
        ("sender", f1_alt),
    ]
    exc = expect_violation(events, "NON_IDENTICAL_RETRANSMISSION")
    # f1_alt 布局：STX '1' a b [d] ETX cs cs CR LF，差异字节下标为 4
    assert exc.position == 4


def test_nak_must_be_followed_by_retransmission_not_eot():
    f1 = make_frame(1, b"abc")
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", f1),
        ("receiver", bytes([NAK])),
        ("sender", bytes([EOT])),
    ]
    expect_violation(events, "STAGE_ORDER")


def test_more_than_two_retransmissions_rejected():
    f1 = make_frame(1, b"abc")
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", f1),
        ("receiver", bytes([NAK])),
        ("sender", f1),
        ("receiver", bytes([NAK])),
        ("sender", f1),
        ("receiver", bytes([NAK])),  # 第 3 个 NAK
    ]
    expect_violation(events, "RETRANSMISSION_LIMIT")


def test_two_retransmissions_then_ack_ok():
    f1 = make_frame(1, b"abc")
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", f1),
        ("receiver", bytes([NAK])),
        ("sender", f1),
        ("receiver", bytes([NAK])),
        ("sender", f1),
        ("receiver", bytes([ACK])),
        ("sender", bytes([EOT])),
    ]
    result = audit("x", events)
    assert result["frame_count"] == 1
    assert result["retransmissions"] == 2


def test_receiver_may_only_ack_or_nak():
    f1 = make_frame(1, b"abc")
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", f1),
        ("receiver", bytes([ENQ])),
    ]
    expect_violation(events, "UNEXPECTED_REPLY")


def test_direction_violation_frame_from_receiver():
    f1 = make_frame(1, b"abc")
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("receiver", f1),
    ]
    expect_violation(events, "DIRECTION_VIOLATION")


def test_incomplete_without_eot():
    f1 = make_frame(1, b"abc")
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", f1),
        ("receiver", bytes([ACK])),
    ]
    expect_violation(events, "INCOMPLETE_SESSION")


def test_truncated_mid_frame_rejected():
    # 最后一个块在帧内部截断 —— 不能被当作完整结果
    f1 = make_frame(1, b"abc")
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", f1[:4]),
    ]
    expect_violation(events, "INCOMPLETE_SESSION")


def test_trailing_data_after_eot_rejected():
    events = valid_events() + [("receiver", bytes([ACK]))]
    expect_violation(events, "TRAILING_DATA")


def test_payload_length_bounds():
    # 0 字节正文不合法
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", make_frame(1, b"")),
    ]
    expect_violation(events, "INVALID_FRAME")

    # 241 字节正文不合法
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", make_frame(1, b"A" * 241)),
    ]
    expect_violation(events, "FRAME_TOO_LONG")


def test_control_byte_in_payload_rejected():
    f = make_frame(1, b"ab\x01cd")
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", f),
    ]
    expect_violation(events, "INVALID_BODY")


def test_cr_allowed_inside_payload():
    payload = b"line1\rline2"
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", make_frame(1, payload, terminator=ETX)),
        ("receiver", bytes([ACK])),
        ("sender", bytes([EOT])),
    ]
    result = audit("x", events)
    assert result["sha256"] == hashlib.sha256(payload).hexdigest()


# ---- 结果集复核（recordAudit=result_set）----------------------------------

RESULT_BODY = (
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


def result_events(body: bytes, piece: int = 50, retransmit_first: bool = False):
    """把结果集正文按 piece 大小切成多帧，构造完整会话。"""
    events = [("sender", bytes([ENQ])), ("receiver", bytes([ACK]))]
    fn = 1
    first = True
    for i in range(0, len(body), piece):
        frame = make_frame(fn, body[i : i + piece], terminator=ETB)
        events.append(("sender", frame))
        if first and retransmit_first:
            events.append(("receiver", bytes([NAK])))
            events.append(("sender", frame))
        events.append(("receiver", bytes([ACK])))
        first = False
        fn = 1 if fn == 0 else (fn + 1 if fn < 7 else 0)
    events.append(("sender", bytes([EOT])))
    return events


def expect_result_violation(body_or_events, code):
    events = (
        body_or_events
        if isinstance(body_or_events, list)
        else result_events(body_or_events)
    )
    with pytest.raises(ProtocolViolation) as exc:
        audit("x", events, "result_set")
    assert exc.value.code == code, exc.value.message
    return exc.value


def test_result_audit_default_omitted_keeps_old_shape():
    result = audit("x", result_events(RESULT_BODY))
    assert set(result) == {
        "ok",
        "sender",
        "payload",
        "payload_bytes",
        "frame_count",
        "retransmissions",
        "sha256",
    }


def test_result_audit_counts_and_ordering():
    result = audit("x", result_events(RESULT_BODY, piece=7), "result_set")
    assert result["patient_count"] == 2
    assert result["order_count"] == 2
    assert result["result_count"] == 3
    assert result["patient_ids"] == ["PAT001", "PAT002"]
    assert result["sample_ids"] == ["SAMP01", "SAMP02"]
    assert result["result_counts"] == [2, 1]
    # 原传输字段保持不变
    assert result["frame_count"] == -(-len(RESULT_BODY) // 7)  # ceil 向上取整


def test_result_audit_cross_frame_records_with_retransmission():
    # 每帧 3 字节：所有记录都跨帧；首帧还经历一次 NAK 重传
    events = result_events(RESULT_BODY, piece=3, retransmit_first=True)
    result = audit("x", events, "result_set")
    assert result["patient_count"] == 2
    assert result["order_count"] == 2
    assert result["result_count"] == 3
    assert result["patient_ids"] == ["PAT001", "PAT002"]
    assert result["sample_ids"] == ["SAMP01", "SAMP02"]
    assert result["result_counts"] == [2, 1]
    # 重传不影响帧计数
    assert result["frame_count"] == -(-len(RESULT_BODY) // 3)
    assert result["retransmissions"] == 1


def test_result_audit_minimal_valid_set():
    body = b"H|\\^&\rP|1||P1\rO|1||S1||||\rR|1||T1||1\rL|1"
    result = audit("x", result_events(body, piece=4), "result_set")
    assert result["patient_count"] == 1
    assert result["order_count"] == 1
    assert result["result_count"] == 1
    assert result["result_counts"] == [1]


def test_result_audit_non_ascii_rejected():
    bad = b"GL\xff"
    body = RESULT_BODY.replace(b"GLU", bad)
    events = result_events(body, piece=50)
    exc = expect_result_violation(events, "NON_ASCII_BODY")
    # 位置指向出错的 sender 帧块，且块内该字节就是 0xFF
    direction, raw = events[exc.block_index]
    assert direction == "sender"
    assert raw[exc.position] == 0xFF
    # 默认模式（省略 recordAudit）同一字节仍走旧的 INVALID_BODY
    with pytest.raises(ProtocolViolation) as default_exc:
        audit("x", events)
    assert default_exc.value.code == "INVALID_BODY"


def test_result_audit_invalid_delimiters():
    # 少于四个分隔符
    expect_result_violation(
        b"H|\\^\rP|1||P1\rO|1||S1\rR|1||T1\rL|1", "INVALID_DELIMITER"
    )
    # 分隔符重复
    expect_result_violation(
        b"H|\\|\\\rP|1||P1\rO|1||S1\rR|1||T1\rL|1", "INVALID_DELIMITER"
    )


def test_result_audit_custom_field_delimiter():
    body = b"H:\\^&\rP:1::P1\rO:1::S1::::\rR:1::T1::1\rL:1"
    result = audit("x", result_events(body, piece=5), "result_set")
    assert result["patient_ids"] == ["P1"]
    assert result["sample_ids"] == ["S1"]
    assert result["result_counts"] == [1]


def test_result_audit_hierarchy():
    # H 不是首条
    expect_result_violation(b"P|1||P1\rH|\\^&\rL|1", "RECORD_ORDER")
    # L 不是末条
    expect_result_violation(
        b"H|\\^&\rP|1||P1\rO|1||S1\rR|1||T1||1\rP|2||P2", "RECORD_ORDER"
    )
    # O 没有上级 P
    expect_result_violation(
        b"H|\\^&\rO|1||S1\rR|1||T1||1\rL|1", "RECORD_ORDER"
    )
    # R 没有上级 O
    expect_result_violation(
        b"H|\\^&\rP|1||P1\rR|1||T1||1\rO|1||S1\rL|1", "RECORD_ORDER"
    )
    # 患者缺医嘱
    expect_result_violation(
        b"H|\\^&\rP|1||P1\rL|1", "RECORD_ORDER"
    )
    # 医嘱缺结果（收尾）
    expect_result_violation(
        b"H|\\^&\rP|1||P1\rO|1||S1\rL|1", "RECORD_ORDER"
    )
    # 医嘱缺结果（下一个患者出现）
    expect_result_violation(
        b"H|\\^&\rP|1||P1\rO|1||S1\rP|2||P2\rO|1||S2\rR|1||T1||1\rL|1",
        "RECORD_ORDER",
    )
    # 空记录（连续 CR）
    expect_result_violation(
        b"H|\\^&\r\rP|1||P1\rO|1||S1\rR|1||T1||1\rL|1", "RECORD_ORDER"
    )
    # 未知记录类型
    expect_result_violation(
        b"H|\\^&\rX|1\rL|1", "RECORD_ORDER"
    )


def test_result_audit_sequence_skips():
    expect_result_violation(
        b"H|\\^&\rP|2||P1\rO|1||S1\rR|1||T1||1\rL|1", "SEQUENCE_SKIP"
    )
    expect_result_violation(
        b"H|\\^&\rP|1||P1\rO|2||S1\rR|1||T1||1\rL|1", "SEQUENCE_SKIP"
    )
    expect_result_violation(
        b"H|\\^&\rP|1||P1\rO|1||S1\rR|2||T1||1\rL|1", "SEQUENCE_SKIP"
    )
    # 序号在新作用域内重新从 1 开始：合法
    body = (
        b"H|\\^&\rP|1||P1\rO|1||S1\rR|1||A||1\rR|2||B||2\r"
        b"O|2||S2\rR|1||C||3\r"
        b"P|2||P2\rO|1||S3\rR|1||D||4\rL|1"
    )
    result = audit("x", result_events(body, piece=6), "result_set")
    assert result["result_counts"] == [2, 1, 1]


def test_result_audit_missing_identifiers():
    expect_result_violation(
        b"H|\\^&\rP|1||\rO|1||S1\rR|1||T1||1\rL|1", "MISSING_IDENTIFIER"
    )
    expect_result_violation(
        b"H|\\^&\rP|1||P1\rO|1||\rR|1||T1||1\rL|1", "MISSING_IDENTIFIER"
    )
    expect_result_violation(
        b"H|\\^&\rP|1||P1\rO|1||S1\rR|1||\rL|1", "MISSING_IDENTIFIER"
    )


def test_result_audit_duplicate_sample_within_patient():
    body = (
        b"H|\\^&\rP|1||P1\r"
        b"O|1||S1\rR|1||T1||1\r"
        b"O|2||S1\rR|1||T2||2\rL|1"
    )
    expect_result_violation(body, "DUPLICATE_SAMPLE_ID")


def test_result_audit_same_sample_id_across_patients_allowed():
    body = (
        b"H|\\^&\rP|1||P1\rO|1||S1\rR|1||T1||1\r"
        b"P|2||P2\rO|1||S1\rR|1||T2||2\rL|1"
    )
    result = audit("x", result_events(body, piece=5), "result_set")
    assert result["sample_ids"] == ["S1", "S1"]


def test_result_audit_position_points_to_original_non_retransmitted_block():
    # 缺陷位于首帧（分隔符重复），首帧经历一次 NAK 重传；
    # 报错块必须是首个（原始）发送块，而不是重传块。
    f1 = make_frame(1, b"H|\\|\\\r")
    f2 = make_frame(2, b"P|1||P1\rO|1||S1\rR|1||T1||1\rL|1", terminator=ETX)
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", f1),                      # 块 2：原始传输
        ("receiver", bytes([NAK])),          # 块 3
        ("sender", f1),                      # 块 4：重传
        ("receiver", bytes([ACK])),          # 块 5
        ("sender", f2),
        ("receiver", bytes([ACK])),
        ("sender", bytes([EOT])),
    ]
    exc = expect_result_violation(events, "INVALID_DELIMITER")
    assert exc.block_index == 2
    # 位置落在原始帧的正文字节上（STX+帧号之后）
    assert 2 <= exc.position < len(f1) - 5


def test_result_audit_position_maps_into_cross_frame_byte():
    # 跨帧（每帧 4 字节）时，重复样本号在第二患者段；块/位置应命中 'S1'
    body = (
        b"H|\\^&\rP|1||P1\rO|1||S1\rR|1||T1||1\r"
        b"O|2||S1\rR|1||T2||2\rL|1"
    )
    events = result_events(body, piece=4)
    exc = expect_result_violation(events, "DUPLICATE_SAMPLE_ID")
    direction, raw = events[exc.block_index]
    assert direction == "sender"
    assert chr(raw[exc.position]) == "S"


# ---- 请求解析与 HTTP 层 ----------------------------------------------------

def _post(events, piece=None, sender="analyzer-A", record_audit=None):
    decoded = chunks_for(events, piece) if piece else events
    body = {
        "sender": sender,
        "chunks": [
            {"direction": d, "data": base64.b64encode(raw).decode()}
            for d, raw in decoded
        ],
    }
    if record_audit is not None:
        body["recordAudit"] = record_audit
    return client.post("/api/astm/sessions/audit", json=body)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_api_valid_cross_chunk_with_retransmission():
    resp = _post(valid_events(), piece=1)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["frame_count"] == 2
    assert data["retransmissions"] == 1
    assert data["sha256"] == hashlib.sha256(EXPECTED_PAYLOAD).hexdigest()


def test_api_default_response_unchanged_when_record_audit_absent():
    resp = _post(result_events(RESULT_BODY, piece=3))
    assert resp.status_code == 200, resp.text
    assert set(resp.json()) == {
        "ok",
        "sender",
        "payload",
        "payload_bytes",
        "frame_count",
        "retransmissions",
        "sha256",
    }


def test_api_result_set_audit_success():
    resp = _post(result_events(RESULT_BODY, piece=3, retransmit_first=True), record_audit="result_set")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["patient_count"] == 2
    assert data["order_count"] == 2
    assert data["result_count"] == 3
    assert data["patient_ids"] == ["PAT001", "PAT002"]
    assert data["sample_ids"] == ["SAMP01", "SAMP02"]
    assert data["result_counts"] == [2, 1]


def test_api_result_set_audit_semantic_failure_is_422():
    bad = RESULT_BODY.replace(b"GLU", b"GL\xff")
    resp = _post(result_events(bad, piece=3), record_audit="result_set")
    assert resp.status_code == 422
    err = resp.json()
    assert err["code"] == "NON_ASCII_BODY"
    assert isinstance(err["block_index"], int)
    assert isinstance(err["position"], int)
    assert isinstance(err["global_offset"], int)


def test_api_invalid_record_audit_value_is_400():
    resp = _post(
        result_events(RESULT_BODY),
        record_audit="full",
    )
    assert resp.status_code == 400
    assert resp.json()["code"] == "INVALID_REQUEST"


def test_api_violation_reports_block_and_position():
    # 逐字节分块，块下标即出错字节所在块，position 恒为 0
    events = [
        ("sender", bytes([ENQ])),
        ("receiver", bytes([ACK])),
        ("sender", bytes([STX, ord("2"), ord("x"), ETX])),
    ]
    resp = _post(events, piece=1)
    assert resp.status_code == 422
    err = resp.json()
    assert err["ok"] is False
    assert err["code"] == "FRAME_NUMBER_SKIP"
    assert err["block_index"] == 3  # ENQ,ACK,STX 之后是帧号字节
    assert err["position"] == 0
    assert "global_offset" in err


def test_api_bad_base64_is_400():
    resp = client.post(
        "/api/astm/sessions/audit",
        json={"sender": "x", "chunks": [{"direction": "sender", "data": "@@@@"}]},
    )
    assert resp.status_code == 400
    assert resp.json()["code"] == "BAD_BASE64"


def test_api_bad_direction_is_400():
    resp = client.post(
        "/api/astm/sessions/audit",
        json={"sender": "x", "chunks": [{"direction": "bus", "data": ""}]},
    )
    assert resp.status_code == 400
    assert resp.json()["code"] == "INVALID_DIRECTION"


def test_api_empty_chunks_is_400():
    resp = client.post(
        "/api/astm/sessions/audit",
        json={"sender": "x", "chunks": []},
    )
    assert resp.status_code == 400


def test_parse_request_size_limit():
    big = base64.b64encode(b"\x00" * (1024 * 1024 + 1)).decode()
    with pytest.raises(Exception):
        parse_request({"sender": "x", "chunks": [{"direction": "sender", "data": big}]})


def test_parse_request_size_limit_code():
    big = base64.b64encode(b"\x00" * (1024 * 1024 + 1)).decode()
    from app.protocol import RequestError

    with pytest.raises(RequestError) as exc:
        parse_request({"sender": "x", "chunks": [{"direction": "sender", "data": big}]})
    assert exc.value.code == "SIZE_EXCEEDED"


def test_too_many_chunks_rejected():
    from app.protocol import MAX_CHUNKS, RequestError

    body = {
        "sender": "x",
        "chunks": [
            {"direction": "sender", "data": ""} for _ in range(MAX_CHUNKS + 1)
        ],
    }
    with pytest.raises(RequestError) as exc:
        parse_request(body)
    assert exc.value.code == "INVALID_REQUEST"


def test_max_size_valid_session_accepted():
    # 每帧 240 字节正文，拼到恰好接近 1 MiB 且合法
    target = 1024 * 1024 - 100
    events = [("sender", bytes([ENQ])), ("receiver", bytes([ACK]))]
    payloads = []
    remaining = target
    fn = 1
    while remaining > 0:
        size = min(240, remaining)
        data = bytes(0x41 + (i % 26) for i in range(size))
        payloads.append(data)
        events += [
            ("sender", make_frame(fn, data, terminator=ETB if remaining > 240 else ETX)),
            ("receiver", bytes([ACK])),
        ]
        fn = 1 if fn == 0 else (fn + 1 if fn < 7 else 0)
        remaining -= size
    events.append(("sender", bytes([EOT])))
    result = audit("x", events)
    assert result["payload_bytes"] == target
    assert result["sha256"] == hashlib.sha256(b"".join(payloads)).hexdigest()

