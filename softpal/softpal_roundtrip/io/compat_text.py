from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path


ORIGINAL_MARK = "○"
TRANSLATE_MARK = "●"
TRANSLATE_TAG_RE = re.compile(r"^[○●](?P<idx>\d{8})[○●](?P<tag>[a-z_]+)[○●](?P<text>.*)$")
TRANSLATE_RANGE_RE = re.compile(
    r"^#\s*提取范围：idx\s+(?P<start>-inf|\d+)\s+\.\.\s+(?P<end>\+inf|\d+)\s*$"
)
TEXT_ESCAPE_MARKER = "# SOFTPAL_TEXT_ESCAPE_V1"
_TEXT_ESCAPE_PREFIX = "# SOFTPAL_TEXT_ESCAPE_"
_FIELD_ESCAPES = {"\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t", "\v": "\\v", "\f": "\\f"}
_UNESCAPE_FIELDS = {value[1:]: key for key, value in _FIELD_ESCAPES.items()}
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def text_has_raw_bytes(text: str) -> bool:
    return any(0xDC80 <= ord(ch) <= 0xDCFF for ch in text)


def text_needs_escaping(text: str) -> bool:
    return any(ord(ch) < 0x20 or ch in "\x85\u2028\u2029" or 0xD800 <= ord(ch) <= 0xDFFF for ch in text)


def rows_need_text_escaping(rows: Iterable[dict]) -> bool:
    return any(text_needs_escaping(str(row[key])) for row in rows for key in ("original_text", "text") if key in row)


def escape_text_field(text: str, *, escaped_text: bool) -> str:
    if not escaped_text:
        return text
    result = []
    for ch in text:
        code = ord(ch)
        if ch in _FIELD_ESCAPES:
            result.append(_FIELD_ESCAPES[ch])
        elif 0xDC80 <= code <= 0xDCFF:
            result.append(f"\\x{code - 0xDC00:02X}")
        elif code == 0 or 0xD800 <= code <= 0xDFFF:
            raise ValueError(f"文本含不支持的字符 U+{code:04X}，无法生成有效的文本转义")
        elif code < 0x20 or ch in "\x85\u2028\u2029":
            result.append(f"\\u{code:04X}")
        else:
            result.append(ch)
    return "".join(result)


def text_escape_mode_from_lines(lines: list[str]) -> bool:
    escaped_text = False
    for line in lines:
        marker = line.strip()
        if not marker.startswith(_TEXT_ESCAPE_PREFIX):
            continue
        if marker != TEXT_ESCAPE_MARKER:
            raise ValueError(f"不支持的文本转义版本：{marker}")
        escaped_text = True
    return escaped_text


def unescape_text_field(text: str, *, escaped_text: bool, context: str = "文本") -> str:
    if not escaped_text:
        return text
    result = []
    position = 0
    while position < len(text):
        ch = text[position]
        if ch != "\\":
            if ch == "\0" or 0xD800 <= ord(ch) <= 0xDFFF:
                raise ValueError(f"{context} 第 {position + 1} 个字符不能直接用于文本转义")
            result.append(ch)
            position += 1
            continue
        start = position
        position += 1
        if position < len(text) and text[position] in _UNESCAPE_FIELDS:
            result.append(_UNESCAPE_FIELDS[text[position]])
            position += 1
            continue
        if position < len(text) and text[position] in {"x", "u"}:
            kind = text[position]
            width = 2 if kind == "x" else 4
            digits = text[position + 1:position + 1 + width]
            if len(digits) == width and all(digit in _HEX_DIGITS for digit in digits):
                value = int(digits, 16)
                if kind == "x" and 0x80 <= value <= 0xFF:
                    result.append(chr(0xDC00 + value))
                elif kind == "u" and value != 0 and not 0xD800 <= value <= 0xDFFF:
                    result.append(chr(value))
                else:
                    raise ValueError(f"{context} 第 {start + 1} 个字符的转义值不合法")
                position += 1 + width
                continue
        raise ValueError(f"{context} 第 {start + 1} 个字符的文本转义不合法；原字节使用 \\x80..\\xFF，字面反斜线使用 \\\\")
    return "".join(result)


def read_text_auto(path: Path) -> str:
    raw = path.read_bytes()
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig")
    for encoding in ("utf-8-sig", "utf-8", "utf-16"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise ValueError(f"无法识别 {path} 的文本编码")


def preview_text_for_error(text: str, limit: int = 80) -> str:
    preview = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    preview = "".join(
        f"\\x{ord(ch) - 0xDC00:02X}" if 0xDC80 <= ord(ch) <= 0xDCFF
        else f"\\u{ord(ch):04X}" if 0xD800 <= ord(ch) <= 0xDFFF else ch
        for ch in preview
    )
    if len(preview) > limit:
        preview = preview[:limit] + "..."
    return preview


def normalize_idx_range(
    idx_start: int | None,
    idx_end: int | None,
) -> tuple[int | None, int | None]:
    if idx_start is not None and idx_start < 0:
        raise ValueError(f"idx_start 不能小于 0: {idx_start}")
    if idx_end is not None and idx_end < 0:
        raise ValueError(f"idx_end 不能小于 0: {idx_end}")
    if idx_start is not None and idx_end is not None and idx_start > idx_end:
        raise ValueError(f"idx_start 不能大于 idx_end: {idx_start} > {idx_end}")
    return idx_start, idx_end


def row_in_idx_range(row: dict, idx_start: int | None, idx_end: int | None) -> bool:
    idx = int(row["idx"])
    if idx_start is not None and idx < idx_start:
        return False
    if idx_end is not None and idx > idx_end:
        return False
    return True


def filter_text_rows_by_idx(
    text_rows: list[dict],
    idx_start: int | None,
    idx_end: int | None,
) -> list[dict]:
    idx_start, idx_end = normalize_idx_range(idx_start, idx_end)
    return [row for row in text_rows if row_in_idx_range(row, idx_start, idx_end)]


def detect_idx_range_from_lines(lines: list[str]) -> tuple[int | None, int | None]:
    for line in lines:
        if line.strip() == "# 提取范围：ALL":
            return None, None
        match = TRANSLATE_RANGE_RE.match(line.strip())
        if match is None:
            continue
        start_text = match.group("start")
        end_text = match.group("end")
        idx_start = None if start_text == "-inf" else int(start_text)
        idx_end = None if end_text == "+inf" else int(end_text)
        return normalize_idx_range(idx_start, idx_end)
    return None, None
