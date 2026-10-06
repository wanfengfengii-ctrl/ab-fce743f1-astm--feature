"""ASTM E1381 风格会话复核引擎。

线路帧格式::

    STX FN PAYLOAD (ETB|ETX) HEX HEX CR LF

* ``FN``  为单字节帧号，取值 ``'1'``..``'7'``、``'0'``，按 1..7,0 循环；
* ``PAYLOAD`` 为 1..240 个允许的 ASTM 文本字节（0x20..0x7E，以及记录分隔 CR）；
* 两位大写十六进制校验和 = STX 之后一个字节起、到结束符（含）逐字节求和模 256；
* 校验和之后必须紧跟 CRLF。

会话次序（sender / receiver 为相对于请求 ``sender`` 的方向）::

    sender: ENQ
    receiver: ACK
    sender: frame [receiver: ACK | NAK -> sender 原样重传 ...]
    ...
    sender: EOT

NAK 后只允许原样重传当前帧，且重传至多两次（即同一帧最多收到 2 个 NAK）。

引擎在 *解码后的字节流* 上逐字节工作，调用方可以把捕获内容切成任意块——
块边界可以落在 STX/ETX/CRLF 等控制序列或帧内部中间，解析结果与切分方式无关。
所有协议错误都携带稳定错误码以及“首个出错块内”的 0 基字节位置。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from array import array
from typing import List, Optional, Tuple

# ---- 线路控制字符 -----------------------------------------------------------
STX = 0x02
ETX = 0x03
EOT = 0x04
ENQ = 0x05
ACK = 0x06
LF = 0x0A
CR = 0x0D
NAK = 0x15
ETB = 0x17

MAX_CHUNKS = 2000
MAX_TOTAL_BYTES = 1024 * 1024  # 1 MiB
MAX_PAYLOAD = 240

DIRECTION_SENDER = "sender"
DIRECTION_RECEIVER = "receiver"
DIRECTIONS = (DIRECTION_SENDER, DIRECTION_RECEIVER)

# recordAudit 取值：result_set 在传输复核之外再校验结果集结构。
RECORD_AUDIT_RESULT_SET = "result_set"

# 帧号循环：1,2,...,7,0,1,...
_FRAME_CYCLE = (1, 2, 3, 4, 5, 6, 7, 0)


def _int_array() -> array:
    return array("i")


class RequestError(ValueError):
    """请求本身格式不合格（400），与 ASTM 会话内容无关。"""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class ProtocolViolation(Exception):
    """捕获到的字节流不满足合法 ASTM 会话要求（422）。"""

    def __init__(
        self,
        code: str,
        message: str,
        block_index: int,
        position: int,
        global_offset: int,
    ):
        super().__init__(message)
        self.code = code
        self.message = message
        self.block_index = block_index
        self.position = position
        self.global_offset = global_offset

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "block_index": self.block_index,
            "position": self.position,
            "global_offset": self.global_offset,
        }


def _is_allowed_text(b: int) -> bool:
    return 0x20 <= b <= 0x7E or b == CR


def parse_request(body: object) -> Tuple[str, List[Tuple[str, bytes]], Optional[str]]:
    """校验并解码 HTTP 请求体。

    返回 ``(sender, [(direction, bytes), ...], record_audit)``；
    ``record_audit`` 省略时为 ``None``，此时行为与旧版完全一致。
    """
    if not isinstance(body, dict):
        raise RequestError("INVALID_REQUEST", "请求体必须为 JSON 对象")

    sender = body.get("sender")
    if not isinstance(sender, str) or not sender.strip() or len(sender) > 128:
        raise RequestError("INVALID_REQUEST", "sender 必须为 1..128 字符的非空字符串")
    sender = sender.strip()

    record_audit = body.get("recordAudit")
    if record_audit is None:
        record_audit = None
    elif record_audit != RECORD_AUDIT_RESULT_SET:
        raise RequestError(
            "INVALID_REQUEST",
            f"recordAudit 只能省略或为 {RECORD_AUDIT_RESULT_SET!r}",
        )

    chunks = body.get("chunks")
    if not isinstance(chunks, list) or not (1 <= len(chunks) <= MAX_CHUNKS):
        raise RequestError(
            "INVALID_REQUEST",
            f"chunks 必须为 1..{MAX_CHUNKS} 个元素的数组",
        )

    decoded: List[Tuple[str, bytes]] = []
    total = 0
    for i, chunk in enumerate(chunks):
        if not isinstance(chunk, dict):
            raise RequestError("INVALID_REQUEST", f"块 {i} 必须为对象")
        direction = chunk.get("direction")
        if direction not in DIRECTIONS:
            raise RequestError(
                "INVALID_DIRECTION",
                f"块 {i} 的 direction 只能是 'sender' 或 'receiver'",
            )
        data = chunk.get("data")
        if not isinstance(data, str):
            raise RequestError("INVALID_REQUEST", f"块 {i} 的 data 必须为 Base64 字符串")
        try:
            raw = base64.b64decode(data, validate=True)
        except (binascii.Error, ValueError):
            raise RequestError("BAD_BASE64", f"块 {i} 不是合法 Base64")
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise RequestError(
                "SIZE_EXCEEDED",
                f"解码后总字节数超过 {MAX_TOTAL_BYTES} 字节（1 MiB）",
            )
        decoded.append((direction, raw))

    return sender, decoded, record_audit


# 会话阶段
_S_ENQ = "enq"                # 等待 sender 的 ENQ
_S_ENQ_ACK = "enq_ack"        # 等待 receiver 对 ENQ 的 ACK
_S_IDLE = "idle"              # 等待 sender 开始新帧（STX）或 EOT
_S_BODY = "body"              # 帧正文（含帧号）
_S_CKSUM1 = "cksum1"          # 校验和第 1 个十六进制字符
_S_CKSUM2 = "cksum2"          # 校验和第 2 个十六进制字符
_S_CR = "cr"                  # 结束后的 CR
_S_LF = "lf"                  # 结束后的 LF
_S_REPLY = "reply"            # 等待 receiver 的 ACK/NAK
_S_DONE = "done"              # EOT 之后，会话结束


class _Session:
    def __init__(self) -> None:
        self.state = _S_ENQ
        self.frame_count = 0
        self.retransmissions = 0

        self.fn_index = 0           # 下一个 *新* 帧在 _FRAME_CYCLE 中的下标
        self.payload = bytearray()    # 重组正文（不含帧号/控制符）
        # 重组正文中每个字节的来源（三块并行数组：块下标 / 块内位置 / 全局偏移）；
        # 重传帧中的字节不重复记录，因此位置始终指向首个（非重传）传输块。
        # 仅在调用方需要结果集定位时通过 enable_location_tracking 开启。
        self.track_locations = False
        self.loc_block = _int_array()
        self.loc_pos = _int_array()
        self.loc_offset = _int_array()
        self.body_loc: List[Tuple[int, int, int]] = []
        self.pending: bytes = b""     # 最近一次已通过校验的帧（整帧线路字节）
        self.nak_count = 0            # 当前帧已收到的 NAK 数
        self.retrans = False          # 当前正在收的是否为重传帧
        self.rt_pos = 0               # 重传逐字节比对位置

        self.body = bytearray()
        self.terminator = 0
        self.cksum = bytearray()

        # 位置追踪
        self.global_offset = 0
        self.block_index = 0
        self.block_len = 0

    def fail(self, code: str, message: str, pos: int) -> None:
        raise ProtocolViolation(
            code, message, self.block_index, pos, self.global_offset
        )

    def rt_match(self, b: int, pos: int) -> None:
        """重传帧必须与上一帧线路字节完全一致。"""
        if not self.retrans:
            return
        if self.rt_pos >= len(self.pending) or b != self.pending[self.rt_pos]:
            self.fail(
                "NON_IDENTICAL_RETRANSMISSION",
                "NAK 后必须原样重传当前帧",
                pos,
            )
        self.rt_pos += 1

    def feed(self, direction: str, raw: bytes, block_index: int, block_len: int) -> None:
        self.block_index = block_index
        self.block_len = block_len
        for pos, b in enumerate(raw):
            self._byte(direction, b, pos)
            self.global_offset += 1

    def _byte(self, direction: str, b: int, pos: int) -> None:
        st = self.state

        if st == _S_ENQ:
            if direction != DIRECTION_SENDER:
                self.fail("DIRECTION_VIOLATION", "会话必须由 sender 以 ENQ 开始", pos)
            if b != ENQ:
                self.fail("STAGE_ORDER", "会话必须以 ENQ 开始", pos)
            self.state = _S_ENQ_ACK
            return

        if st == _S_ENQ_ACK:
            if direction != DIRECTION_RECEIVER:
                self.fail("DIRECTION_VIOLATION", "ENQ 之后必须由 receiver 应答", pos)
            if b != ACK:
                # 本阶段的 NAK 会要求重新建立链路，不属于允许的帧重传流程。
                self.fail("STAGE_ORDER", "ENQ 之后只接受 ACK", pos)
            self.state = _S_IDLE
            return

        if st == _S_DONE:
            self.fail("TRAILING_DATA", "EOT 之后不允许再有任何字节", pos)

        if st == _S_REPLY:
            if direction != DIRECTION_RECEIVER:
                self.fail("DIRECTION_VIOLATION", "帧结束后必须由 receiver 应答 ACK/NAK", pos)
            if b == ACK:
                self.nak_count = 0
                self.state = _S_IDLE
                return
            if b == NAK:
                if self.nak_count >= 2:
                    self.fail(
                        "RETRANSMISSION_LIMIT",
                        "同一帧最多重传两次（NAK 至多 2 个）",
                        pos,
                    )
                self.nak_count += 1
                self.state = _S_IDLE  # sender 必须立刻重传
                return
            self.fail("UNEXPECTED_REPLY", "receiver 只能回复 ACK 或 NAK", pos)

        # ---- 以下状态均属于 sender 发帧阶段 ----
        if direction != DIRECTION_SENDER:
            self.fail("DIRECTION_VIOLATION", "当前阶段只允许 sender 发送", pos)

        if st == _S_IDLE:
            if self.nak_count > 0:
                # NAK 之后只能立刻原样重传当前帧，不允许 EOT、不允许发新帧。
                if b != STX:
                    self.fail(
                        "STAGE_ORDER",
                        "NAK 之后只能原样重传当前帧",
                        pos,
                    )
            elif b == EOT:
                self.state = _S_DONE
                return
            elif b != STX:
                self.fail("STAGE_ORDER", "此处只允许 STX 开始新帧或 EOT 结束会话", pos)
            self.body = bytearray()
            self.cksum = bytearray()
            self.body_loc = []
            self.retrans = self.nak_count > 0
            self.rt_pos = 0
            if self.retrans:
                # pending 第一字节必为 STX
                self.rt_match(b, pos)
            self.state = _S_BODY
            return

        if st == _S_BODY:
            if b in (ETB, ETX):
                if len(self.body) < 2 or len(self.body) - 1 > MAX_PAYLOAD:
                    self.fail(
                        "INVALID_FRAME",
                        f"帧正文（不含帧号）长度必须为 1..{MAX_PAYLOAD} 字节",
                        pos,
                    )
                self.terminator = b
                self.rt_match(b, pos)
                self.state = _S_CKSUM1
                return
            # 首字节是帧号
            if not self.body:
                if not self.retrans:
                    expected_fn = _FRAME_CYCLE[self.fn_index]
                    if b != ord(str(expected_fn)):
                        self.fail(
                            "FRAME_NUMBER_SKIP",
                            f"帧号必须为 {expected_fn}，且按 1..7,0 循环",
                            pos,
                        )
                # 重传帧的帧号由 rt_match 逐字节原样比对保证。
            if not _is_allowed_text(b):
                if self.track_locations:
                    # recordAudit=result_set 要求正文为 ASCII 可打印记录，
                    # 使用结果集专用稳定错误码；默认模式仍为 INVALID_BODY。
                    self.fail(
                        "NON_ASCII_BODY",
                        "重组正文必须全部为 ASCII 可打印字符，记录之间以 CR 分隔",
                        pos,
                    )
                self.fail("INVALID_BODY", "正文包含不允许的 ASTM 文本字节", pos)
            if len(self.body) >= 1 + MAX_PAYLOAD:
                self.fail(
                    "FRAME_TOO_LONG",
                    f"帧正文超过 {MAX_PAYLOAD} 字节",
                    pos,
                )
            self.rt_match(b, pos)
            self.body.append(b)
            if self.track_locations and not self.retrans:
                # global_offset 尚未在 feed() 中自增，正是当前字节的全局偏移。
                self.body_loc.append((self.block_index, pos, self.global_offset))
            return

        if st == _S_CKSUM1:
            if b not in b"0123456789ABCDEF":
                self.fail("CHECKSUM_FAILED", "校验和必须为两位大写十六进制字符", pos)
            self.rt_match(b, pos)
            self.cksum.append(b)
            self.state = _S_CKSUM2
            return

        if st == _S_CKSUM2:
            if b not in b"0123456789ABCDEF":
                self.fail("CHECKSUM_FAILED", "校验和必须为两位大写十六进制字符", pos)
            self.rt_match(b, pos)
            self.cksum.append(b)
            expected = (sum(self.body) + self.terminator) & 0xFF
            if int(self.cksum, 16) != expected:
                self.fail(
                    "CHECKSUM_FAILED",
                    f"校验和错误：收到 {self.cksum.decode()}，"
                    f"应为 {expected:02X}",
                    pos,
                )
            self.state = _S_CR
            return

        if st == _S_CR:
            self.rt_match(b, pos)
            if b != CR:
                self.fail("INVALID_TERMINATOR", "校验和之后必须为 CRLF", pos)
            self.state = _S_LF
            return

        if st == _S_LF:
            self.rt_match(b, pos)
            if b != LF:
                self.fail("INVALID_TERMINATOR", "校验和之后必须为 CRLF", pos)
            self._frame_complete()
            return

    def _frame_complete(self) -> None:
        wire = bytes([STX]) + bytes(self.body) + bytes(
            [self.terminator]
        ) + bytes(self.cksum) + bytes([CR, LF])

        if self.retrans:
            # 逐字节比对已保证一致；这里防御性兜底长度。
            if self.rt_pos != len(self.pending):
                # 位置信息在逐字节比对阶段已给出，正常不会走到这里。
                raise ProtocolViolation(
                    "NON_IDENTICAL_RETRANSMISSION",
                    "NAK 后必须原样重传当前帧",
                    self.block_index,
                    self.block_len - 1,
                    self.global_offset,
                )
            self.retransmissions += 1
        else:
            self.frame_count += 1
            self.payload.extend(self.body[1:])  # 去掉帧号
            if self.track_locations:
                for blk, bpos, goff in self.body_loc[1:]:
                    self.loc_block.append(blk)
                    self.loc_pos.append(bpos)
                    self.loc_offset.append(goff)
            self.fn_index = (self.fn_index + 1) % 8
        self.pending = wire
        self.state = _S_REPLY

    def finish(self, last_block_index: int, last_block_len: int) -> dict:
        if self.state != _S_DONE:
            raise ProtocolViolation(
                "INCOMPLETE_SESSION",
                "会话不完整：sender 必须依次完成 ENQ、逐帧发送并以 EOT 结束",
                last_block_index,
                last_block_len,
                self.global_offset,
            )
        payload_bytes = bytes(self.payload)
        return {
            "ok": True,
            "payload": payload_bytes.decode("latin-1"),
            "payload_bytes": len(payload_bytes),
            "frame_count": self.frame_count,
            "retransmissions": self.retransmissions,
            "sha256": hashlib.sha256(payload_bytes).hexdigest(),
        }


# ---- 结果集复核（recordAudit=result_set）-----------------------------------
#
# 重组正文按 CR 分隔成非空记录，层级为 H（头）→ P（患者）→ O（医嘱）→
# R（结果）→ L（结束）：H 必须首条、L 必须末条；每个 P 下至少一个 O，每个
# O 下至少一个 R；P-1/O-1/R-1 在各自作用域内从 1 连续递增；P-3 患者号、
# O-3 样本号、R-3 检验号必须非空；同一患者内样本号不得重复。
#
# 首条 H 记录开头声明四个互异的可打印分隔符：H 之后依次为字段、重复、分量、
# 转义分隔符（ASTM 惯例为 ``H|\^&``）；其余记录按声明的字段分隔符切分字段。


def validate_result_set(
    payload: bytes,
    loc_block: array,
    loc_pos: array,
    loc_offset: array,
) -> dict:
    """传输复核通过后校验结果集结构，返回计数与按正文顺序排列的标识汇总。

    所有违例都以重组正文中*首个相关字节*的下标上报，位置数组再把它映射到
    该字节所在的原始（非重传）块。
    """

    def fail(code: str, message: str, index: int) -> None:
        index = max(0, min(index, len(payload) - 1))
        raise ProtocolViolation(
            code, message, loc_block[index], loc_pos[index], loc_offset[index]
        )

    if not payload:
        # 传输层只保证帧非空，这里防御性兜底：空正文不可能构成 H..L 结构。
        fail("RECORD_ORDER", "重组正文为空，缺少 H 与 L 记录", 0)

    # ---- 1) 非 ASCII（最先扫描，保证报错位置是最靠左的相关字节） ---------
    for i, b in enumerate(payload):
        if b != CR and not (0x20 <= b <= 0x7E):
            fail(
                "NON_ASCII_BODY",
                "重组正文必须全部为 ASCII 可打印字符，记录之间以 CR 分隔",
                i,
            )

    # ---- 2) 以 CR 切分为非空记录，记录每条记录的起止下标 ------------------
    spans: List[Tuple[int, int]] = []
    start = 0
    for i, b in enumerate(payload):
        if b == CR:
            if start == i:
                # 开头 CR 或连续 CR：空记录从 start 处“开始”，属层级/结构失序
                fail("RECORD_ORDER", "记录必须非空，且只能以单个 CR 分隔", start)
            spans.append((start, i))
            start = i + 1
    if start >= len(payload):
        fail("RECORD_ORDER", "末条记录之后不允许多余的 CR", len(payload) - 1)
    spans.append((start, len(payload)))

    # ---- 3) H 开头声明四个互异可打印分隔符 --------------------------------
    h0, h1 = spans[0]
    if payload[h0 : h0 + 1] != b"H":
        fail("RECORD_ORDER", "首条记录必须为 H（头记录）", h0)
    if h1 - h0 < 5:
        fail(
            "INVALID_DELIMITER",
            "H 之后必须紧跟四个单字符分隔符（字段、重复、分量、转义）",
            h1,
        )
    delims = bytes(payload[h0 + 1 : h0 + 5])
    for k, d in enumerate(delims):
        if not (0x20 <= d <= 0x7E):
            fail("INVALID_DELIMITER", "分隔符必须为可打印 ASCII 字符", h0 + 1 + k)
    for k in range(4):
        for j in range(k):
            if delims[k] == delims[j]:
                fail("INVALID_DELIMITER", "四个分隔符必须互异", h0 + 1 + k)
    field_delim = delims[0]
    # H 记录的类型字段（首个字段分隔符之前）必须恰好为 H；四个声明符之后
    # 必须紧跟字段分隔符或记录结束，否则声明格式非法。
    decl_end = h0 + 5
    if decl_end < h1 and payload[decl_end] != field_delim:
        fail(
            "INVALID_DELIMITER",
            "四个分隔符声明之后必须紧跟字段分隔符或记录结束",
            decl_end,
        )

    def field_span(rec_no: int, field_no: int) -> Tuple[int, int]:
        """第 rec_no 条记录中第 field_no 个字段（1 基，含记录类型）的跨度。"""
        s, e = spans[rec_no]
        cur = s
        current = 1
        fb = s
        while cur < e:
            if payload[cur] == field_delim:
                if current == field_no:
                    return fb, cur
                current += 1
                fb = cur + 1
            cur += 1
        return fb, e  # 字段缺失：贴在记录末尾的空跨度

    def get_field(rec_no: int, field_no: int) -> bytes:
        s, e = field_span(rec_no, field_no)
        return payload[s:e]

    # ---- 4) 末条必须为 L --------------------------------------------------
    last_no = len(spans) - 1
    lt_s, lt_e = field_span(last_no, 1)
    if payload[lt_s:lt_e] != b"L":
        fail("RECORD_ORDER", "末条记录必须为 L（结束记录）", lt_s)
    if last_no < 2:
        fail("RECORD_ORDER", "H 与 L 之间至少要有一个患者及其医嘱、结果", lt_s)

    # ---- 5) 层级、序号、标识的单次顺序遍历 --------------------------------
    patient_count = 0
    order_count = 0
    result_count = 0
    patient_ids: List[str] = []
    sample_ids: List[str] = []
    result_counts: List[int] = []

    # stage：H 已读头；P 已读患者（等待其首个医嘱）；O 已开医嘱（等待首个
    # 结果）；R 当前医嘱已经有结果。
    stage = "H"
    p_seq = 0
    o_seq = 0        # 当前患者作用域内的医嘱序号
    r_seq = 0        # 当前医嘱作用域内的结果序号
    patient_samples: set = set()

    def check_seq(rec_no: int, what: str, expected: int) -> None:
        s, e = field_span(rec_no, 2)
        raw = payload[s:e]
        if not raw or not all(0x30 <= c <= 0x39 for c in raw) or int(raw) != expected:
            fail(
                "SEQUENCE_SKIP",
                f"{what}-1 序号必须在作用域内从 1 连续递增：此处应为 {expected}",
                s,
            )

    for rec_no in range(1, last_no):
        rec_s, _ = spans[rec_no]
        t_s, t_e = field_span(rec_no, 1)
        rtype = payload[t_s:t_e]

        if rtype == b"P":
            if stage == "P":
                # 上一个患者还没有任何医嘱就出现了新患者
                fail("RECORD_ORDER", "每个患者至少要有一个医嘱（O）", rec_s)
            if stage == "O":
                # 上一个医嘱还没有任何结果就切到了新患者
                fail("RECORD_ORDER", "每个医嘱至少要有一个结果（R）", rec_s)
            if stage not in ("H", "R"):
                fail("RECORD_ORDER", "记录层级失序：患者（P）位置非法", rec_s)
            check_seq(rec_no, "P", p_seq + 1)
            pid = get_field(rec_no, 4).strip()
            if not pid:
                fail("MISSING_IDENTIFIER", "P-3 患者号必须非空", field_span(rec_no, 4)[0])
            p_seq += 1
            patient_count += 1
            patient_ids.append(pid.decode("ascii"))
            patient_samples = set()
            o_seq = 0
            stage = "P"
            continue

        if rtype == b"O":
            if stage == "O":
                # 上一个医嘱还没有任何结果
                fail("RECORD_ORDER", "每个医嘱至少要有一个结果（R）", rec_s)
            if stage not in ("P", "R"):
                fail(
                    "RECORD_ORDER",
                    "记录层级失序：医嘱（O）必须位于患者（P）之下",
                    rec_s,
                )
            check_seq(rec_no, "O", o_seq + 1)
            sample_id = get_field(rec_no, 4).strip()
            if not sample_id:
                fail("MISSING_IDENTIFIER", "O-3 样本号必须非空", field_span(rec_no, 4)[0])
            if sample_id in patient_samples:
                fail("DUPLICATE_SAMPLE_ID", "同一患者内样本号不得重复", field_span(rec_no, 4)[0])
            patient_samples.add(sample_id)
            sample_ids.append(sample_id.decode("ascii"))
            o_seq += 1
            order_count += 1
            result_counts.append(0)
            r_seq = 0
            stage = "O"
            continue

        if rtype == b"R":
            if stage not in ("O", "R"):
                fail(
                    "RECORD_ORDER",
                    "记录层级失序：结果（R）必须位于医嘱（O）之下",
                    rec_s,
                )
            check_seq(rec_no, "R", r_seq + 1)
            test_id = get_field(rec_no, 4).strip()
            if not test_id:
                fail("MISSING_IDENTIFIER", "R-3 检验号必须非空", field_span(rec_no, 4)[0])
            r_seq += 1
            result_count += 1
            result_counts[-1] += 1
            stage = "R"
            continue

        fail(
            "RECORD_ORDER",
            "H 与 L 之间只允许按层级排列的 P、O、R 记录",
            t_s,
        )

    if stage in ("H", "P"):
        fail("RECORD_ORDER", "每个患者至少要有一个医嘱（O）", lt_s)
    if stage == "O":
        fail("RECORD_ORDER", "每个医嘱至少要有一个结果（R）", lt_s)

    return {
        "patient_count": patient_count,
        "order_count": order_count,
        "result_count": result_count,
        "patient_ids": patient_ids,
        "sample_ids": sample_ids,
        "result_counts": result_counts,
    }


def audit(
    sender: str,
    decoded: List[Tuple[str, bytes]],
    record_audit: Optional[str] = None,
) -> dict:
    """复核整段捕获；decoded 为 ``(direction, raw_bytes)`` 列表。"""
    session = _Session()
    session.track_locations = record_audit == RECORD_AUDIT_RESULT_SET
    last_index = 0
    last_len = 0
    for index, (direction, raw) in enumerate(decoded):
        if raw:
            last_index = index
            last_len = len(raw)
        session.feed(direction, raw, index, len(raw))
    result = session.finish(last_index, last_len)
    result["sender"] = sender
    # 重新排一下字段顺序，便于阅读
    response = {
        "ok": True,
        "sender": sender,
        "payload": result["payload"],
        "payload_bytes": result["payload_bytes"],
        "frame_count": result["frame_count"],
        "retransmissions": result["retransmissions"],
        "sha256": result["sha256"],
    }
    if record_audit == RECORD_AUDIT_RESULT_SET:
        response.update(
            validate_result_set(
                bytes(session.payload),
                session.loc_block,
                session.loc_pos,
                session.loc_offset,
            )
        )
    return response
