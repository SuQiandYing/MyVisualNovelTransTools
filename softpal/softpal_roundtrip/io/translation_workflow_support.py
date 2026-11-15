from __future__ import annotations

import re

from ..core.message_layouts import validate_message_fields
from .compat_text import ORIGINAL_MARK, TEXT_ESCAPE_MARKER, TRANSLATE_MARK, escape_text_field


MESSAGE_TAG = "msg"
LEGACY_MESSAGE_TAG = "text"
SCENARIO_BOUNDARY_CALL_ID_HEX = "0x000F0002"
SIZE_TAG_RE = re.compile(r"^(?:<s\d+>)?(?P<body>.*?)(?:</s>)?$")


def normalize_translation_tag(tag: str) -> str:
    return MESSAGE_TAG if tag == LEGACY_MESSAGE_TAG else tag


def format_translation_line(marker: str, idx: int, tag: str, text: str) -> str:
    return f"{marker}{idx:08d}{marker}{tag}{marker}{text}"


def has_text_letter(text: str) -> bool:
    return any(ch.isalpha() for ch in text)


def strip_size_tags(text: str) -> str:
    match = SIZE_TAG_RE.fullmatch(text.strip())
    return text.strip() if match is None else match.group("body").strip()


def looks_like_spoken_or_thought_text(text: str) -> bool:
    stripped = strip_size_tags(text)
    return stripped.startswith(("「", "（"))


def looks_like_speaker_name_text(text: str) -> bool:
    stripped = text.strip()
    if not (1 <= len(stripped) <= 28):
        return False
    if any(ch.isspace() for ch in stripped):
        return False
    if any(ch in stripped for ch in '<>「」。、！？!?：:；;（）()[]【】《》…♪'):
        return False
    return has_text_letter(stripped)


def is_scenario_boundary_row(row: dict) -> bool:
    if "scenario_boundary_verified" in row:
        return row["scenario_boundary_verified"] is True
    scenario_role = str(row.get("scenario_role") or "")
    if scenario_role.startswith("scenario_boundary"):
        return True
    return SCENARIO_BOUNDARY_CALL_ID_HEX in {str(value) for value in row.get("direct_call_ids_hex", [])}


def scenario_body_ranges(rows: list[dict]) -> list[range]:
    boundary_positions = [index for index, row in enumerate(rows) if is_scenario_boundary_row(row)]
    ranges: list[range] = []
    for index, start in enumerate(boundary_positions):
        stop = boundary_positions[index + 1] if index + 1 < len(boundary_positions) else len(rows)
        if start + 1 < stop:
            ranges.append(range(start + 1, stop))
    return ranges


def collect_scenario_speaker_names(rows: list[dict], ranges: list[range]) -> set[str]:
    body_positions = {position for body_range in ranges for position in body_range}
    names: set[str] = set()
    for position in body_positions:
        text = str(rows[position].get("original_text", ""))
        if not looks_like_speaker_name_text(text):
            continue
        prev_text = str(rows[position - 1].get("original_text", "")) if position > 0 else ""
        next_text = str(rows[position + 1].get("original_text", "")) if position + 1 < len(rows) else ""
        if looks_like_spoken_or_thought_text(prev_text) or looks_like_spoken_or_thought_text(next_text):
            names.add(text.strip())
    return names


def looks_like_choice_text(text: str) -> bool:
    stripped = strip_size_tags(text)
    if stripped.startswith(("[choice]", "<choice", "<select")):
        return True
    return stripped.startswith("【") and stripped.endswith("】")


def annotate_scenario_export_tags(text_rows: list[dict], message_rows: list[dict]) -> list[dict]:
    validate_message_rows(message_rows)
    rows = [dict(row) for row in text_rows]
    for row in rows:
        row.pop("scenario_export_tag", None)
        row.pop("legacy_scenario_export_tag", None)
    ranges = scenario_body_ranges(rows)
    if not ranges:
        return rows

    text_idxs = {int(row["text_idx"]) for row in message_rows}
    name_idxs = {int(row["name_idx"]) for row in message_rows if row.get("name_idx") is not None}
    # Reproduce the previous tags only for importing existing translation files.
    # Adjacency and text shape must never promote internal rows in new exports.
    speaker_names = collect_scenario_speaker_names(rows, ranges)
    for body_range in ranges:
        for position in body_range:
            row = rows[position]
            current_tag = normalize_translation_tag(str(row.get("export_tag", "")))
            if current_tag in {"name", "choice", MESSAGE_TAG}:
                continue

            original_text = str(row.get("original_text", ""))
            if looks_like_speaker_name_text(original_text) and original_text.strip() in speaker_names:
                row["legacy_scenario_export_tag"] = "name"
            elif looks_like_choice_text(original_text):
                row["legacy_scenario_export_tag"] = "choice"
            else:
                row["legacy_scenario_export_tag"] = MESSAGE_TAG

            idx = int(row["idx"])
            if idx in name_idxs:
                row["scenario_export_tag"] = "name"
            elif idx in text_idxs:
                row["scenario_export_tag"] = MESSAGE_TAG
    return rows


def first_message_context_map(message_rows: list[dict]) -> dict[int, dict]:
    ctx: dict[int, dict] = {}
    for row in message_rows:
        text_idx = int(row["text_idx"])
        if text_idx not in ctx:
            ctx[text_idx] = {
                "role": "message_text",
                "call_offset_hex": row["call_offset_hex"],
                "line_id_hex": row["line_id_hex"],
                "pair_idx": row["name_idx"],
                "pair_text": row["name"],
                "kind": row["kind"],
            }
        name_idx = row["name_idx"]
        if name_idx is not None:
            name_idx = int(name_idx)
            if name_idx not in ctx:
                ctx[name_idx] = {
                    "role": "speaker_name",
                    "call_offset_hex": row["call_offset_hex"],
                    "line_id_hex": row["line_id_hex"],
                    "pair_idx": row["text_idx"],
                    "pair_text": row["text"],
                    "kind": row["kind"],
                }
    return ctx


def export_tag_for_row(row: dict) -> str:
    return normalize_translation_tag(str(row.get("scenario_export_tag", row["export_tag"])))


def translation_tag_matches_row(tag: str, row: dict) -> bool:
    if tag == export_tag_for_row(row):
        return True
    if row.get("scenario_boundary_verified") is True and tag == normalize_translation_tag(str(row.get("source_boundary_tag", ""))):
        return True
    legacy_tag = row.get("legacy_scenario_export_tag")
    return legacy_tag is not None and tag == normalize_translation_tag(str(legacy_tag))


def build_translate_blocks(text_rows: list[dict], message_rows: list[dict], *, escaped_text: bool = False) -> list[str]:
    ctx_map = first_message_context_map(message_rows)
    blocks: list[str] = []
    for row in text_rows:
        idx = int(row["idx"])
        tag = export_tag_for_row(row)
        comment_parts = [
            f"idx={idx}",
            f"off={row['entry_offset_hex']}",
            f"tag={tag}",
            f"refs={row['ref_count']}",
        ]
        if row.get("scenario_role"):
            comment_parts.append(f"scenario_role={row['scenario_role']}")
        if row.get("scenario_boundary_source"):
            comment_parts.append(f"scenario_src={row['scenario_boundary_source']}")
        if row.get("direct_call_ids_hex"):
            comment_parts.append("calls=" + ",".join(row["direct_call_ids_hex"]))
        ctx = ctx_map.get(idx)
        if ctx is not None:
            comment_parts.append(f"kind={ctx['kind']}")
            comment_parts.append(f"call={ctx['call_offset_hex']}")
            comment_parts.append(f"line={ctx['line_id_hex']}")
            comment_parts.append("pair=NONE" if ctx["pair_idx"] is None else f"pair={ctx['pair_idx']}")
        original_text = escape_text_field(row["original_text"], escaped_text=escaped_text)
        original_line = format_translation_line(ORIGINAL_MARK, idx, tag, original_text)
        translated_text = escape_text_field(row.get("text", row["original_text"]), escaped_text=escaped_text)
        translated_line = format_translation_line(TRANSLATE_MARK, idx, tag, translated_text)
        blocks.append("\n".join(["# " + " ".join(comment_parts), original_line, translated_line, ""]))
    return blocks


def validate_message_rows(message_rows: list[dict]) -> None:
    for row in message_rows:
        validate_message_fields(
            str(row["text"]), None if row.get("name") is None else str(row["name"]),
            context=f"call={row.get('call_offset_hex', '?')} 正文 idx={row['text_idx']} 人名 idx={row.get('name_idx')}",
        )


def build_translation_header(idx_start: int | None, idx_end: int | None, *, escaped_text: bool = False) -> list[str]:
    header = [
        "# SOFTPAL_TRANSLATE_V1",
        "# Supplemental tags: `title`=作品标题, `chapter_title`=章节标题, `route_title`=路线/分支标题, `replay_title`=回想标题。",
        "# 规则：每组只改第二行；第一行保持原文作对照；不要改动 `○编号○标签○` / `●编号●标签●` 这一段。",
        "# 标签说明：`name`=人名, `msg`=正文/旁白, `choice`=可见选项文本, `label`=机器脚本标签, `label_text`=文本型分支锚点, `label_internal`=内部锚点/标签, `ui`=可见 UI 文本, `display`=可见的独立展示文本, `system`=系统提示, `font`=字体名, `kana`=假名索引, `symbol`=分隔符/符号文本, `asset`=资源名或路径, `config`=配置/内部 ID, `scenario`=场景 ID, `debug`=调试/格式串, `misc`=未识别的其他文本, `unused`=当前未被引用。",
        (
            "# 提取范围：ALL"
            if idx_start is None and idx_end is None
            else f"# 提取范围：idx {idx_start if idx_start is not None else '-inf'} .. {idx_end if idx_end is not None else '+inf'}"
        ),
        "#",
        "",
    ]
    if escaped_text:
        header[1:1] = [
            TEXT_ESCAPE_MARKER,
            r"# 转义规则：\xNN 保留无法解码的原字节，\\ 表示字面反斜线，\n / \r / \t 表示换行、回车、制表符；保留此版本标记。",
        ]
    return header
