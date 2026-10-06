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
    RequestError,
    audit,
    audit_result_set,
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


# ---- recordAudit=result_set 结果集记录审计 ---------------------------------

HEADER = b"H|\\^&|||analyzer^1.0"
PATIENT1 = b"P|1||P123"
ORDER1 = b"O|1||S1^^^ASTM^M|||"
RESULT1 = b"R|1||^^^GLU^M|5.1"
RESULT2 = b"R|2||^^^NA^M|140"
ORDER2 = b"O|2||S2^^^ASTM^M|||"
RESULT3 = b"R|1||^^^K^M|4.0"
PATIENT2 = b"P|2||P124"
ORDER3 = b"O|1||S3^^^ASTM^M|||"
RESULT4 = b"R|1||^^^HGB^M|13"
TERMINATOR = b"L|"


def result_payload(*records: bytes) -> bytes:
    return bytes([CR]).join(records)


VALID_RESULT_SET = result_payload(
    HEADER,
    PATIENT1,
    ORDER1,
    RESULT1,
    RESULT2,
    ORDER2,
    RESULT3,
    PATIENT2,
    ORDER3,
    RESULT4,
    TERMINATOR,
)


def result_events(payload: bytes, fsize: int = 240, nak_frames=()):
    """把结果集正文按 fsize 切成多帧（帧边界可落在记录/字段任意位置）。

    nak_frames 中的帧下标会经历一次 NAK 原样重传。
    """
    pieces = [payload[i : i + fsize] for i in range(0, len(payload), fsize)]
    events = [("sender", bytes([ENQ])), ("receiver", bytes([ACK]))]
    for i, piece in enumerate(pieces):
        fn_num = (i % 8) + 1  # 1..8，其中 8 对应循环中的帧号 0
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


# -- 默认行为保持兼容 --------------------------------------------------------

def test_default_audit_unchanged_without_record_audit():
    result = audit("x", result_events(VALID_RESULT_SET))
    assert "record_audit" not in result
    assert "patients" not in result
    assert "patient_ids" not in result
    assert set(result) == {
        "ok", "sender", "payload", "payload_bytes",
        "frame_count", "retransmissions", "sha256",
    }


def test_api_default_response_unchanged():
    resp = _post(result_events(VALID_RESULT_SET))
    assert resp.status_code == 200
    data = resp.json()
    assert "patients" not in data
    assert "record_audit" not in data


def test_api_explicit_null_record_audit_is_default():
    decoded = result_events(VALID_RESULT_SET)
    body = {
        "sender": "x",
        "recordAudit": None,
        "chunks": [
            {"direction": d, "data": base64.b64encode(raw).decode()}
            for d, raw in decoded
        ],
    }
    resp = client.post("/api/astm/sessions/audit", json=body)
    assert resp.status_code == 200
    assert "patients" not in resp.json()


def test_invalid_record_audit_value_is_400():
    body = {
        "sender": "x",
        "recordAudit": "full",
        "chunks": [{"direction": "sender", "data": ""}],
    }
    resp = client.post("/api/astm/sessions/audit", json=body)
    assert resp.status_code == 400
    assert resp.json()["code"] == "INVALID_REQUEST"


def test_parse_request_returns_record_audit():
    sender, decoded, record_audit = parse_request(
        {"sender": "x", "recordAudit": "result_set",
         "chunks": [{"direction": "sender", "data": ""}]}
    )
    assert record_audit == "result_set"
    sender, decoded, record_audit = parse_request(
        {"sender": "x", "chunks": [{"direction": "sender", "data": ""}]}
    )
    assert record_audit is None


# -- 成功路径：计数与按正文顺序的标识列表 ------------------------------------

def test_valid_result_set_counts_and_identifiers():
    result = audit("x", result_events(VALID_RESULT_SET), "result_set")
    assert result["record_audit"] == "result_set"
    assert result["patients"] == 2
    assert result["orders"] == 3
    assert result["results"] == 4
    assert result["patient_ids"] == ["P123", "P124"]
    assert result["sample_ids"] == [
        "S1^^^ASTM^M", "S2^^^ASTM^M", "S3^^^ASTM^M",
    ]
    assert result["result_counts"] == [3, 1]


@pytest.mark.parametrize("fsize", [1, 2, 3, 5, 11, 64, 240])
def test_result_set_cross_frame_records(fsize):
    # 记录跨帧切分，重组结果与切分方式无关。
    result = audit("x", result_events(VALID_RESULT_SET, fsize=fsize), "result_set")
    assert result["patients"] == 2
    assert result["orders"] == 3
    assert result["results"] == 4
    assert result["result_counts"] == [3, 1]


@pytest.mark.parametrize("piece", [1, 3, 7, 1000])
def test_result_set_cross_chunk_with_retransmission(piece):
    # 帧 0、最后一帧均经历一次 NAK 原样重传，且捕获按小块切分。
    events = result_events(VALID_RESULT_SET, fsize=17, nak_frames={0, 3})
    result = audit("x", chunks_for(events, piece), "result_set")
    assert result["results"] == 4
    assert result["retransmissions"] == 2


def test_api_result_set_success_cross_chunk():
    resp = _post(result_events(VALID_RESULT_SET, fsize=13), piece=2,
                 record_audit="result_set")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["patients"] == 2
    assert data["orders"] == 3
    assert data["results"] == 4
    assert data["patient_ids"] == ["P123", "P124"]
    assert data["result_counts"] == [3, 1]


def test_health_still_ok():
    resp = client.get("/health")
    assert resp.status_code == 200


# -- 语义失败：稳定错误码 ----------------------------------------------------

def expect_result_violation(payload: bytes, code: str, fsize: int = 240):
    with pytest.raises(ProtocolViolation) as exc:
        audit("x", result_events(payload, fsize=fsize), "result_set")
    assert exc.value.code == code
    return exc.value


def test_non_ascii_payload_rejected():
    # 线路层不允许非 ASCII 字节，故直接对重组器验证该防御分支。
    bad = VALID_RESULT_SET.replace(b"P123", b"P1\xff3")
    origins = [(0, i, i) for i in range(len(bad))]
    with pytest.raises(ProtocolViolation) as exc:
        audit_result_set(bad, origins)
    assert exc.value.code == "RESULT_NON_ASCII"
    assert exc.value.position == VALID_RESULT_SET.index(b"P1") + 2


def test_delimiter_must_be_four_distinct():
    bad = result_payload(
        b"H|\\"+b"\\"+b"^&|||a",  # 字段分隔符与重复分隔符相同
        PATIENT1, ORDER1, RESULT1, TERMINATOR,
    )
    expect_result_violation(bad, "RESULT_INVALID_DELIMITERS")


def test_delimiter_declaration_too_short():
    bad = result_payload(b"H|\\^", PATIENT1, ORDER1, RESULT1, TERMINATOR)
    expect_result_violation(bad, "RESULT_INVALID_DELIMITERS")


def test_first_record_must_be_h():
    records = VALID_RESULT_SET.split(bytes([CR]))
    records[0] = b"X|\\^&|||a"
    expect_result_violation(result_payload(*records), "RESULT_HIERARCHY")


def test_last_record_must_be_l():
    bad = VALID_RESULT_SET[: -len(TERMINATOR)] + b"X|"
    expect_result_violation(bad, "RESULT_HIERARCHY")


def test_order_without_patient_rejected():
    bad = result_payload(HEADER, ORDER1, RESULT1, TERMINATOR)
    expect_result_violation(bad, "RESULT_HIERARCHY")


def test_result_without_order_rejected():
    bad = result_payload(HEADER, PATIENT1, RESULT1, TERMINATOR)
    expect_result_violation(bad, "RESULT_HIERARCHY")


def test_unknown_middle_record_rejected():
    bad = result_payload(HEADER, PATIENT1, b"Q|1", ORDER1, RESULT1, TERMINATOR)
    expect_result_violation(bad, "RESULT_HIERARCHY")


def test_no_patient_between_h_and_l_rejected():
    bad = result_payload(HEADER, TERMINATOR)
    expect_result_violation(bad, "RESULT_HIERARCHY")


def test_patient_sequence_skip_rejected():
    bad = VALID_RESULT_SET.replace(b"P|2||P124", b"P|3||P124")
    expect_result_violation(bad, "RESULT_SEQUENCE_SKIP")


def test_order_sequence_resets_per_patient():
    # 患者 2 的首个医嘱必须从 1 开始。
    bad = VALID_RESULT_SET.replace(b"O|1||S3", b"O|2||S3")
    expect_result_violation(bad, "RESULT_SEQUENCE_SKIP")


def test_order_sequence_continuous_within_patient():
    bad = VALID_RESULT_SET.replace(b"O|2||S2", b"O|3||S2")
    expect_result_violation(bad, "RESULT_SEQUENCE_SKIP")


def test_result_sequence_resets_per_order():
    # 第二个医嘱的首个结果必须从 1 开始（原数据是 R|1，改成 R|2 即跳变）。
    bad = VALID_RESULT_SET.replace(
        ORDER2 + bytes([CR]) + RESULT3,
        ORDER2 + bytes([CR]) + b"R|2||^^^K^M|4.0",
    )
    expect_result_violation(bad, "RESULT_SEQUENCE_SKIP")


def test_result_sequence_skip_rejected():
    bad = VALID_RESULT_SET.replace(b"R|2||^^^NA", b"R|3||^^^NA")
    expect_result_violation(bad, "RESULT_SEQUENCE_SKIP")


def test_empty_sequence_number_rejected():
    bad = VALID_RESULT_SET.replace(b"R|2|", b"R||")
    expect_result_violation(bad, "RESULT_SEQUENCE_SKIP")


def test_non_numeric_sequence_rejected():
    bad = VALID_RESULT_SET.replace(b"P|2||P124", b"P|X||P124", 1)
    expect_result_violation(bad, "RESULT_SEQUENCE_SKIP")


def test_patient_identifier_required():
    bad = VALID_RESULT_SET.replace(b"P|1||P123", b"P|1||")
    expect_result_violation(bad, "RESULT_MISSING_IDENTIFIER")


def test_sample_identifier_required():
    bad = VALID_RESULT_SET.replace(b"O|1||S1^^^ASTM^M|||", b"O|1|||||")
    expect_result_violation(bad, "RESULT_MISSING_IDENTIFIER")


def test_test_identifier_required():
    bad = VALID_RESULT_SET.replace(b"R|1||^^^GLU^M|5.1", b"R|1|||5.1")
    expect_result_violation(bad, "RESULT_MISSING_IDENTIFIER")


def test_duplicate_sample_within_patient_rejected():
    dup_order = b"O|2||S1^^^ASTM^M|||"  # 与 ORDER1 同样本号、同患者
    bad = VALID_RESULT_SET.replace(ORDER2, dup_order)
    expect_result_violation(bad, "RESULT_DUPLICATE_SAMPLE")


def test_same_sample_in_different_patients_allowed():
    other = VALID_RESULT_SET.replace(b"S3^^^ASTM^M", b"S1^^^ASTM^M")
    result = audit("x", result_events(other), "result_set")
    assert result["orders"] == 3
    assert result["sample_ids"][0] == result["sample_ids"][-1]


def test_patient_without_order_rejected():
    bad = result_payload(HEADER, PATIENT1, TERMINATOR)
    expect_result_violation(bad, "RESULT_PATIENT_WITHOUT_ORDER")


def test_order_without_result_rejected():
    bad = result_payload(HEADER, PATIENT1, ORDER1, TERMINATOR)
    expect_result_violation(bad, "RESULT_ORDER_WITHOUT_RESULT")


def test_last_order_without_result_before_next_patient_rejected():
    # 患者 1 有两个医嘱，第二个没有结果就进入患者 2。
    records = [HEADER, PATIENT1, ORDER1, RESULT1, ORDER2, PATIENT2, ORDER3, RESULT4, TERMINATOR]
    expect_result_violation(result_payload(*records), "RESULT_ORDER_WITHOUT_RESULT")


def test_empty_record_rejected():
    bad = VALID_RESULT_SET.replace(PATIENT1 + bytes([CR]), PATIENT1 + bytes([CR, CR]))
    expect_result_violation(bad, "RESULT_EMPTY_RECORD")


def test_leading_and_trailing_cr_rejected():
    expect_result_violation(bytes([CR]) + VALID_RESULT_SET, "RESULT_EMPTY_RECORD")
    expect_result_violation(VALID_RESULT_SET + bytes([CR]), "RESULT_EMPTY_RECORD")


@pytest.mark.parametrize("fsize", [7, 13, 40])
def test_semantic_failure_still_detected_across_frames(fsize):
    # 患者号缺失的记录被帧边界切碎时依然检出。
    bad = VALID_RESULT_SET.replace(b"P|2||P124", b"P|2||")
    expect_result_violation(bad, "RESULT_MISSING_IDENTIFIER", fsize=fsize)


# -- 位置定位：首个相关正文字节所在的原始非重传块 ---------------------------

def test_api_semantic_failure_reports_block_position():
    bad = VALID_RESULT_SET.replace(b"P|2||P124", b"P|3||P124")
    resp = _post(result_events(bad, fsize=11), piece=3, record_audit="result_set")
    assert resp.status_code == 422
    err = resp.json()
    assert err["code"] == "RESULT_SEQUENCE_SKIP"
    assert isinstance(err["block_index"], int)
    assert isinstance(err["position"], int)
    assert isinstance(err["global_offset"], int)
    # position 必须落在所报告的原始块内
    decoded = chunks_for(result_events(bad, fsize=11), 3)
    block = decoded[err["block_index"]][1]
    assert 0 <= err["position"] < len(block)


def test_error_position_uses_original_not_retransmitted_block():
    # 帧 1（含 H、P）经历一次 NAK 重传；患者无医嘱的错误必须定位到
    # *首次传输* 的帧所在块，而不是重传副本。
    seg1 = HEADER + bytes([CR]) + PATIENT1 + bytes([CR])
    f1 = make_frame(1, seg1, terminator=ETB)
    f2 = make_frame(2, TERMINATOR, terminator=ETX)
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
    # 逐字节切块：每个字节一个块，position 恒为 0。
    decoded = chunks_for(events, 1)
    with pytest.raises(ProtocolViolation) as exc:
        audit("x", decoded, "result_set")
    assert exc.value.code == "RESULT_PATIENT_WITHOUT_ORDER"
    assert exc.value.position == 0
    direction, raw = decoded[exc.value.block_index]
    assert direction == "sender"
    assert raw == b"P"
    # 重传副本起始的全局偏移 = ENQ + ACK + 首帧 + NAK
    retrans_start = 1 + 1 + len(f1) + 1
    assert exc.value.global_offset < retrans_start
