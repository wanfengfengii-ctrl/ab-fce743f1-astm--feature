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
from typing import List, Tuple

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

# 帧号循环：1,2,...,7,0,1,...
_FRAME_CYCLE = (1, 2, 3, 4, 5, 6, 7, 0)

# recordAudit 取值
RECORD_AUDIT_RESULT_SET = "result_set"

# 结果集记录类型
_REC_H = ord("H")    # 头记录，必须首条
_REC_P = ord("P")    # 患者记录
_REC_O = ord("O")    # 医嘱记录
_REC_R = ord("R")    # 结果记录
_REC_L = ord("L")    # 结束记录，必须末条


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


def parse_request(body: object) -> Tuple[str, List[Tuple[str, bytes]], str | None]:
    """校验并解码 HTTP 请求体。

    返回 ``(sender, [(direction, bytes), ...], record_audit)``；
    ``record_audit`` 为省略时的 ``None`` 或 ``"result_set"``。
    """
    if not isinstance(body, dict):
        raise RequestError("INVALID_REQUEST", "请求体必须为 JSON 对象")

    sender = body.get("sender")
    if not isinstance(sender, str) or not sender.strip() or len(sender) > 128:
        raise RequestError("INVALID_REQUEST", "sender 必须为 1..128 字符的非空字符串")
    sender = sender.strip()

    record_audit = body.get("recordAudit", None)
    if record_audit is not None and record_audit != RECORD_AUDIT_RESULT_SET:
        raise RequestError(
            "INVALID_REQUEST",
            f"recordAudit 只能省略或取值 {RECORD_AUDIT_RESULT_SET!r}",
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
    def __init__(self, track_origins: bool = False) -> None:
        self.state = _S_ENQ
        self.frame_count = 0
        self.retransmissions = 0

        self.fn_index = 0           # 下一个 *新* 帧在 _FRAME_CYCLE 中的下标
        self.payload = bytearray()    # 重组正文（不含帧号/控制符）
        self.pending: bytes = b""     # 最近一次已通过校验的帧（整帧线路字节）
        self.nak_count = 0            # 当前帧已收到的 NAK 数
        self.retrans = False          # 当前正在收的是否为重传帧
        self.rt_pos = 0               # 重传逐字节比对位置

        self.body = bytearray()
        self.body_origins: List[Tuple[int, int, int]] = []
        self.terminator = 0
        self.cksum = bytearray()

        # 位置追踪
        self.global_offset = 0
        self.block_index = 0
        self.block_len = 0

        # 结果集审计需要：每个重组正文字节的来源（块下标, 块内位置, 全局偏移），
        # 仅登记首次成功接收的帧（重传帧不产生新正文字节）。
        self.track_origins = track_origins
        self.payload_origins: List[Tuple[int, int, int]] = []

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
            self.body_origins = []
            self.cksum = bytearray()
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
                self.fail("INVALID_BODY", "正文包含不允许的 ASTM 文本字节", pos)
            if len(self.body) >= 1 + MAX_PAYLOAD:
                self.fail(
                    "FRAME_TOO_LONG",
                    f"帧正文超过 {MAX_PAYLOAD} 字节",
                    pos,
                )
            self.rt_match(b, pos)
            self.body.append(b)
            if self.track_origins:
                self.body_origins.append((self.block_index, pos, self.global_offset))
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
            if self.track_origins:
                # body[0] 是帧号，不属于重组正文
                self.payload_origins.extend(self.body_origins[1:])
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
            "payload_origins": list(self.payload_origins),
        }


# ---- 结果集记录审计（recordAudit=result_set）-------------------------------


def _origin_at(origins: List[Tuple[int, int, int]], payload_pos: int):
    """把重组正文偏移映射回 (block_index, position, global_offset)。

    重组正文只包含首次成功接收帧的载荷字节，因此映射到的必然是
    “原始非重传块”。
    """
    if origins:
        if 0 <= payload_pos < len(origins):
            return origins[payload_pos]
        return origins[-1]
    return 0, 0, 0


def audit_result_set(payload: bytes, origins: List[Tuple[int, int, int]]) -> dict:
    """校验重组正文为归属明确的完整 ASTM 结果集。

    成功返回计数（patients/orders/results）与按正文顺序排列的
    patient_ids、sample_ids、result_counts（每位患者的结果数）。
    任何语义问题抛出 :class:`ProtocolViolation`（422），位置指向首个相关
    正文字节所在的原始非重传块。
    """

    def fail(code: str, message: str, pos: int):
        block_index, position, global_offset = _origin_at(origins, pos)
        raise ProtocolViolation(code, message, block_index, position, global_offset)

    # 1) 全文必须为 ASCII：除记录分隔 CR 外，只允许 0x20..0x7E 的可打印字节。
    for i, b in enumerate(payload):
        if b != CR and not (0x20 <= b <= 0x7E):
            fail("RESULT_NON_ASCII", "重组正文必须全部为 ASCII（0x20..0x7E，记录以 CR 分隔）", i)

    # 2) 按 CR 切出非空记录；首尾 CR 与连续 CR 都意味着空记录。
    if not payload or payload[0] == CR:
        fail("RESULT_EMPTY_RECORD", "记录必须非空：正文不得以 CR 开始", 0)
    if payload[-1] == CR:
        fail("RESULT_EMPTY_RECORD", "记录必须非空：正文不得以 CR 结束", len(payload) - 1)

    records = payload.split(bytes([CR]))
    for rec in records:
        if not rec:
            # 首个空记录的起始即那个连续 CR 的位置
            idx = payload.find(bytes([CR, CR]))
            fail("RESULT_EMPTY_RECORD", "记录必须非空：不允许连续的 CR", idx if idx >= 0 else 0)

    # 3) H 必须首条、L 必须末条。
    if records[0][0] != _REC_H:
        fail("RESULT_HIERARCHY", "首条记录必须为 H（头记录）", 0)
    last_off = len(payload) - len(records[-1])
    if records[-1][0] != _REC_L:
        fail("RESULT_HIERARCHY", "末条记录必须为 L（结束记录）", last_off)

    # 4) H 开头声明四个互异的可打印分隔符：H|\\^&
    header = records[0]
    if len(header) < 5:
        fail(
            "RESULT_INVALID_DELIMITERS",
            "H 记录必须声明四个分隔符（字段/重复/组件/转义）",
            0,
        )
    delimiters = list(header[1:5])
    if any(not (0x20 <= d <= 0x7E) for d in delimiters):
        fail("RESULT_INVALID_DELIMITERS", "四个分隔符必须均为可打印 ASCII 字符", 1)
    if len(set(delimiters)) != 4:
        fail("RESULT_INVALID_DELIMITERS", "H 记录声明的四个分隔符必须互异", 1)
    field_sep = delimiters[0]

    # 记录首字节偏移表（按正文顺序累加：记录体 + 分隔 CR）。
    offsets: List[int] = []
    cursor = 0
    for rec in records:
        offsets.append(cursor)
        cursor += len(rec) + 1

    def field_pos(rec_idx: int, field_no: int) -> int:
        """第 rec_idx 条记录的第 field_no（1 基）字段首字节偏移。

        字段存在时指向其首字节；字段缺失时指向记录结束分隔 CR
        （即该字段本应开始的位置）。
        """
        rec = records[rec_idx]
        base = offsets[rec_idx]
        if field_no <= 1:
            return base
        seen = 1
        for i, b in enumerate(rec):
            if b == field_sep:
                seen += 1
                if seen == field_no:
                    return base + i + 1
        # 字段不存在：指向记录尾（CR 本身也是正文字节）。
        return min(base + len(rec), len(payload) - 1)

    def get_fields(rec_idx: int) -> List[bytes]:
        return records[rec_idx].split(bytes([field_sep]))

    def require_seq(rec_idx: int, tag: str, expected: int, scope: str) -> None:
        fields = get_fields(rec_idx)
        if len(fields) < 2 or not fields[1]:
            fail(
                "RESULT_SEQUENCE_SKIP",
                f"{tag}-1 记录序号必须非空，并在{scope}作用域内从 1 连续递增",
                field_pos(rec_idx, 2),
            )
        text = fields[1]
        if not text.isdigit() or int(text) < 1:
            fail(
                "RESULT_SEQUENCE_SKIP",
                f"{tag}-1 记录序号必须为从 1 开始的正整数",
                field_pos(rec_idx, 2),
            )
        value = int(text)
        if value != expected:
            fail(
                "RESULT_SEQUENCE_SKIP",
                f"{tag}-1 必须在{scope}作用域内从 1 连续递增：期望 {expected}，收到 {value}",
                field_pos(rec_idx, 2),
            )

    def require_identifier(rec_idx: int, tag: str, label: str) -> str:
        fields = get_fields(rec_idx)
        if len(fields) < 4 or not fields[3]:
            fail(
                "RESULT_MISSING_IDENTIFIER",
                f"{tag}-3 {label}必须非空",
                field_pos(rec_idx, 4),
            )
        return fields[3].decode("ascii")

    # 5) 层级状态机：仅允许 P(O(R*))* 序列，夹在 H 与 L 之间。
    patient_count = order_count = result_count = 0
    patient_ids: List[str] = []
    sample_ids: List[str] = []
    result_counts: List[int] = []

    # top: 尚未进入任何 P；in_p: 上一条是 P 或 R（可收 O）；
    # in_o: 上一条是 O 或 R（可收 R）。
    have_p = False
    orders_in_p = 0
    results_in_o = 0
    results_in_p = 0
    samples_in_p: set[str] = set()
    next_p = next_o = next_r = 1
    last_p_idx = -1   # 当前患者 P 记录的下标
    last_o_idx = -1   # 当前医嘱 O 记录的下标

    middle = records[1:-1]
    for slot, rec in enumerate(middle, start=1):
        kind = rec[0]
        off = offsets[slot]

        if kind == _REC_P:
            if have_p:
                # 收尾上一患者：最后一个医嘱必须有结果，患者本身必须有医嘱。
                if results_in_o == 0:
                    fail("RESULT_ORDER_WITHOUT_RESULT", "每个医嘱至少需要一个结果（R）", offsets[last_o_idx])
                if orders_in_p == 0:
                    fail("RESULT_PATIENT_WITHOUT_ORDER", "每个患者至少需要一个医嘱（O）", offsets[last_p_idx])
                result_counts.append(results_in_p)
            require_seq(slot, "P", next_p, "患者")
            pid = require_identifier(slot, "P", "患者号")
            patient_ids.append(pid)
            patient_count += 1
            next_p += 1
            next_o, next_r = 1, 1
            have_p = True
            orders_in_p = 0
            results_in_o = 0
            results_in_p = 0
            samples_in_p = set()
            last_p_idx = slot
            last_o_idx = -1

        elif kind == _REC_O:
            if not have_p:
                fail("RESULT_HIERARCHY", "O（医嘱）记录之前必须先有 P（患者）记录", off)
            if last_o_idx >= 0 and results_in_o == 0:
                fail("RESULT_ORDER_WITHOUT_RESULT", "每个医嘱至少需要一个结果（R）", offsets[last_o_idx])
            require_seq(slot, "O", next_o, "患者")
            sid = require_identifier(slot, "O", "样本号")
            if sid in samples_in_p:
                fail("RESULT_DUPLICATE_SAMPLE", "同一患者内样本号不得重复", field_pos(slot, 4))
            samples_in_p.add(sid)
            sample_ids.append(sid)
            order_count += 1
            orders_in_p += 1
            results_in_o = 0
            next_o += 1
            next_r = 1
            last_o_idx = slot

        elif kind == _REC_R:
            if not have_p or orders_in_p == 0:
                fail("RESULT_HIERARCHY", "R（结果）记录之前必须先有 O（医嘱）记录", off)
            require_seq(slot, "R", next_r, "医嘱")
            require_identifier(slot, "R", "检验号")
            result_count += 1
            results_in_o += 1
            results_in_p += 1
            next_r += 1

        else:
            fail(
                "RESULT_HIERARCHY",
                "H 与 L 之间只允许 P、O、R 记录，且须按 P→O→R 层级排列",
                off,
            )

    # 6) 收尾整个结果集。
    if not have_p:
        fail("RESULT_HIERARCHY", "H 与 L 之间至少需要一个患者（P）记录", 0)
    if orders_in_p == 0:
        fail("RESULT_PATIENT_WITHOUT_ORDER", "每个患者至少需要一个医嘱（O）", offsets[last_p_idx])
    if results_in_o == 0:
        fail("RESULT_ORDER_WITHOUT_RESULT", "每个医嘱至少需要一个结果（R）", offsets[last_o_idx])
    result_counts.append(results_in_p)

    return {
        "patients": patient_count,
        "orders": order_count,
        "results": result_count,
        "patient_ids": patient_ids,
        "sample_ids": sample_ids,
        "result_counts": result_counts,
    }


def audit(
    sender: str,
    decoded: List[Tuple[str, bytes]],
    record_audit: str | None = None,
) -> dict:
    """复核整段捕获；decoded 为 ``(direction, raw_bytes)`` 列表。

    ``record_audit`` 为 ``"result_set"`` 时，额外确认重组正文是归属明确的
    完整结果集（H/P/O/R/L 层级），并在响应中附加计数与标识；省略或为
    ``None`` 时请求、响应与错误语义完全保持不变。
    """
    track = record_audit == RECORD_AUDIT_RESULT_SET
    session = _Session(track_origins=track)
    last_index = 0
    last_len = 0
    for index, (direction, raw) in enumerate(decoded):
        if raw:
            last_index = index
            last_len = len(raw)
        session.feed(direction, raw, index, len(raw))
    result = session.finish(last_index, last_len)

    response = {
        "ok": True,
        "sender": sender,
        "payload": result["payload"],
        "payload_bytes": result["payload_bytes"],
        "frame_count": result["frame_count"],
        "retransmissions": result["retransmissions"],
        "sha256": result["sha256"],
    }

    if track:
        rs = audit_result_set(bytes(session.payload), session.payload_origins)
        response["record_audit"] = RECORD_AUDIT_RESULT_SET
        response["patients"] = rs["patients"]
        response["orders"] = rs["orders"]
        response["results"] = rs["results"]
        response["patient_ids"] = rs["patient_ids"]
        response["sample_ids"] = rs["sample_ids"]
        response["result_counts"] = rs["result_counts"]

    return response
