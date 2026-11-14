from __future__ import annotations

import re
from pathlib import Path

from ..io.compat_text import TRANSLATE_TAG_RE, preview_text_for_error, read_text_auto
from ..io.json_io import json_dump, jsonl_dump, load_jsonl
from ..io.translation_workflow_support import (
    annotate_scenario_export_tags,
    build_translate_blocks,
    build_translation_header,
    export_tag_for_row,
    normalize_translation_tag,
    translation_tag_matches_row,
)


SCENARIO_ID_RE = re.compile(r"^(?:after|s\d{2}_[0-9a-z_]+)(?:\s+.+)?$", re.IGNORECASE)
SCENARIO_SPLIT_COMPAT_RE = re.compile(r"^[A-Za-z]+_\d+(?:_\d+)+$")
SCENARIO_SPLIT_MARKER_LINE_RE = re.compile(r"^\s*(?:@@scenario_split@@\s*)?(?P<name>[A-Za-z]+_\d+(?:_\d+)+)\s*$")
SCENARIO_OPCODE_CONFIG_RE = re.compile(r"^(?:sce\d+_\d+|pro_\d+_\d+|[a-z]+_\d+(?:_\d+)+)$", re.IGNORECASE)
SCENARIO_OPCODE_UI_RE = re.compile(r"^(?:\d+[_-].+|.+\d+)$")
ASCII_CONFIG_RE = re.compile(r"^(?:DEF_|sys_|initialize$|[A-Za-z0-9_.%+-]+$)", re.IGNORECASE)
SCENARIO_TRANSLATION_TAGS = frozenset({
    "name", "msg", "choice", "ui", "display", "system", "title",
    "chapter_title", "route_title", "replay_title", "label_text",
})


def looks_like_scenario_text(text: str) -> bool:
    return SCENARIO_ID_RE.fullmatch(text) is not None


def looks_like_choice_compat_text(text: str, call_id_set: set[int]) -> bool:
    if 0x00060002 not in call_id_set:
        return False
    if not text or "<" in text or ">" in text:
        return False
    if ASCII_CONFIG_RE.fullmatch(text):
        return False
    if text.startswith("【") and text.endswith("】"):
        return True
    has_cjk = any("\u3040" <= ch <= "\u30ff" or "\u4e00" <= ch <= "\u9fff" for ch in text)
    return has_cjk and len(text) <= 32


def scenario_filename(text: str) -> str:
    base = text.strip()
    base = re.sub(r'[<>:"/\\|?*\x00-\x1F]', "_", base)
    base = re.sub(r"\s+", " ", base).strip().rstrip(".")
    return base or "unknown_scenario"


def looks_like_scenario_split_compat_text(text: str, tag: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    if looks_like_scenario_text(stripped):
        return True
    if tag != "config":
        return False
    return SCENARIO_SPLIT_COMPAT_RE.fullmatch(stripped) is not None


def parse_scenario_split_marker_line(line: str) -> str | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if looks_like_scenario_text(stripped):
        return stripped
    match = SCENARIO_SPLIT_MARKER_LINE_RE.fullmatch(stripped)
    if match is None:
        return None
    return match.group("name")


def build_scenario_split_marker_lines(scenario: dict) -> list[str]:
    name = str(scenario.get("name", "")).strip()
    tag = str(scenario.get("tag", "")).strip()
    if not looks_like_scenario_split_compat_text(name, tag):
        return []
    return [
        f"# scenario_split_boundary: {name}",
        "# 兼容标记：下方单独一行的场景分割标识仅用于 scenario_txt 分段提示，导入时会自动忽略。",
        name,
        "",
    ]


def boundary_has_near_message(boundary_idx: int, next_boundary_idx: int | None, message_rows: list[dict], *, near_window: int = 64) -> bool:
    first_hit: int | None = None
    for row in message_rows:
        candidates = [int(row["text_idx"])]
        if row.get("name_idx") is not None:
            candidates.append(int(row["name_idx"]))
        for idx in candidates:
            if idx < boundary_idx:
                continue
            if next_boundary_idx is not None and idx >= next_boundary_idx:
                continue
            if first_hit is None or idx < first_hit:
                first_hit = idx
    return first_hit is not None and first_hit <= boundary_idx + near_window


def filter_fallback_boundaries(candidates: list[dict], message_rows: list[dict]) -> list[dict]:
    filtered: list[dict] = []
    indexes = [int(item["start_idx"]) for item in candidates]
    for i, item in enumerate(candidates):
        next_idx = indexes[i + 1] if i + 1 < len(indexes) else None
        if boundary_has_near_message(int(item["start_idx"]), next_idx, message_rows):
            filtered.append(item)
    return filtered


def row_call_id_set(row: dict) -> set[int]:
    return {int(value) for value in row.get("direct_call_ids", [])}


def row_call_id_hex_set(row: dict) -> set[str]:
    return {str(value) for value in row.get("direct_call_ids_hex", [])}


def looks_like_opcode_boundary_text(text: str, tag: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    lowered = stripped.lower()
    if looks_like_scenario_text(stripped):
        return True
    if SCENARIO_SPLIT_COMPAT_RE.fullmatch(stripped):
        return True
    if SCENARIO_OPCODE_CONFIG_RE.fullmatch(stripped):
        return True
    if tag == "ui" and SCENARIO_OPCODE_UI_RE.fullmatch(stripped):
        return True
    if any(ch.isdigit() for ch in stripped) and any("\u3040" <= ch <= "\u30ff" or "\u4e00" <= ch <= "\u9fff" for ch in stripped):
        return True
    if stripped.isdigit() and 1 <= len(stripped) <= 3:
        return True
    if lowered.startswith(("pro_", "sce", "after ")):
        return True
    return False


def is_choice_like_ui_row(row: dict) -> bool:
    direct_call_ids = row_call_id_set(row)
    return bool(direct_call_ids) and looks_like_choice_compat_text(str(row.get("original_text", "")).strip(), direct_call_ids)


def classify_scenario_role(row: dict) -> tuple[str | None, str | None]:
    text = str(row.get("original_text", "")).strip()
    tag = export_tag_for_row(row)
    call_ids_hex = row_call_id_hex_set(row)
    if "0x000F0002" in call_ids_hex and tag not in {"debug", "system", "font", "asset", "symbol", "misc"}:
        if looks_like_opcode_boundary_text(text, tag):
            return "scenario_boundary", "opcode:0x000F0002"
    if is_choice_like_ui_row(row):
        return "scenario_boundary_fallback", "opcode:0x00060002"
    return None, None


def classify_primary_boundary_candidates(ordered_rows: list[dict]) -> tuple[list[dict], list[str]]:
    candidates: list[dict] = []
    tags: set[str] = set()
    for row in ordered_rows:
        scenario_role, boundary_source = classify_scenario_role(row)
        if scenario_role != "scenario_boundary" or boundary_source != "opcode:0x000F0002":
            continue
        candidates.append({"name": str(row.get("original_text", "")).strip(), "start_idx": int(row["idx"]), "tag": export_tag_for_row(row)})
        tags.add(export_tag_for_row(row))
    return candidates, sorted(tags)


def build_grouped_choice_boundaries(ordered_rows: list[dict]) -> list[dict]:
    groups: list[list[dict]] = []
    current: list[dict] = []
    for row in ordered_rows:
        if is_choice_like_ui_row(row):
            if current and int(row["idx"]) != int(current[-1]["idx"]) + 1:
                groups.append(current)
                current = []
            current.append(row)
            continue
        if current:
            groups.append(current)
            current = []
    if current:
        groups.append(current)
    boundaries: list[dict] = []
    for group in groups:
        if len(group) < 2:
            continue
        first = group[0]
        boundaries.append({"name": first["original_text"], "start_idx": int(first["idx"]), "tag": "choice"})
    return boundaries


def select_split_boundaries(ordered_rows: list[dict], message_rows: list[dict]) -> tuple[list[dict], list[str], bool]:
    opcode_primary, opcode_tags = classify_primary_boundary_candidates(ordered_rows)
    filtered_opcode_primary = filter_fallback_boundaries(opcode_primary, message_rows)
    if filtered_opcode_primary:
        return filtered_opcode_primary, opcode_tags or sorted({item["tag"] for item in filtered_opcode_primary}), False
    if opcode_primary:
        return opcode_primary, opcode_tags or sorted({item["tag"] for item in opcode_primary}), False
    
    folder1_logic = [{"name": row["original_text"], "start_idx": int(row["idx"]), "tag": export_tag_for_row(row)} for row in ordered_rows if "0x000F0005" in row_call_id_hex_set(row)]
    folder1_logic = filter_fallback_boundaries(folder1_logic, message_rows)
    if folder1_logic:
        return folder1_logic, ["scenario_boundary_0x000F0005"], True

    return [], [], False


def earliest_message_related_idx(message_rows: list[dict]) -> int | None:
    candidates: list[int] = []
    for row in message_rows:
        candidates.append(int(row["text_idx"]))
        if row.get("name_idx") is not None:
            candidates.append(int(row["name_idx"]))
    return min(candidates) if candidates else None


def unique_split_filename(base_name: str, used_names: set[str]) -> str:
    candidate = base_name
    serial = 2
    while candidate in used_names:
        candidate = f"{base_name}__{serial}"
        serial += 1
    used_names.add(candidate)
    return candidate


def export_scenario_split_command(dump_dir: Path, out_dir: Path, *, file_encoding: str = "utf-16") -> dict:
    text_rows = load_jsonl(dump_dir / "text_entries.jsonl")
    message_rows = load_jsonl(dump_dir / "messages.jsonl")
    text_rows = annotate_scenario_export_tags(text_rows, message_rows)
    ordered_rows = sorted(text_rows, key=lambda row: int(row["idx"]))
    scenarios, boundary_tags, include_pre_first = select_split_boundaries(ordered_rows, message_rows)
    scenario_indexes = [int(item["start_idx"]) for item in scenarios]
    pre_first_start_idx = earliest_message_related_idx(message_rows) if include_pre_first else None
    out_dir.mkdir(parents=True, exist_ok=True)
    files: list[dict] = []
    used_names: set[str] = set()
    excluded_internal_rows = 0
    for i, scenario in enumerate(scenarios):
        start_idx = int(scenario["start_idx"])
        next_start_idx = scenario_indexes[i + 1] if i + 1 < len(scenario_indexes) else None
        range_start_idx = pre_first_start_idx if i == 0 and pre_first_start_idx is not None and pre_first_start_idx < start_idx else start_idx
        range_rows = [row for row in ordered_rows if int(row["idx"]) >= range_start_idx and (next_start_idx is None or int(row["idx"]) < next_start_idx)]
        scenario_rows = [row for row in range_rows if int(row["idx"]) == start_idx or export_tag_for_row(row) in SCENARIO_TRANSLATION_TAGS]
        excluded_count = len(range_rows) - len(scenario_rows)
        excluded_internal_rows += excluded_count
        filename = unique_split_filename(scenario_filename(str(scenario["name"])), used_names) + ".txt"
        path = out_dir / filename
        lines = build_translation_header(range_start_idx, None if next_start_idx is None else next_start_idx - 1) + build_scenario_split_marker_lines(scenario) + build_translate_blocks(scenario_rows, message_rows)
        path.write_text("\n".join(lines).rstrip() + "\n", encoding=file_encoding, newline="\n")
        files.append({
            "scenario": scenario["name"],
            "boundary_tag": scenario["tag"],
            "scenario_role": "scenario_boundary",
            "path": str(path),
            "row_count": len(scenario_rows),
            "excluded_internal_rows": excluded_count,
            "start_idx": range_start_idx,
            "boundary_idx": start_idx,
            "end_idx": None if next_start_idx is None else next_start_idx - 1,
        })
    report = {
        "out_dir": str(out_dir),
        "file_encoding": file_encoding,
        "boundary_tags": boundary_tags,
        "include_pre_first_rows": include_pre_first,
        "scenario_count": len(scenarios),
        "files_written": len(files),
        "excluded_internal_rows": excluded_internal_rows,
        "sample_files": files[:20],
    }
    json_dump(out_dir / "scenario_split_report.json", report)
    return report


def import_scenario_split_command(dump_dir: Path, scenario_dir: Path) -> dict:
    text_rows = load_jsonl(dump_dir / "text_entries.jsonl")
    message_rows = load_jsonl(dump_dir / "messages.jsonl")
    export_rows = annotate_scenario_export_tags(text_rows, message_rows)
    export_row_by_idx = {int(row["idx"]): row for row in export_rows}
    text_by_idx = {int(row["idx"]): row for row in text_rows}
    updated_idxs: set[int] = set()
    file_reports: list[dict] = []
    legacy_tag_rows = 0
    for path in sorted(scenario_dir.glob("*.txt")):
        lines = read_text_auto(path).splitlines()
        parsed_pairs: list[tuple[int, str, str, str]] = []
        ignored_split_markers: list[str] = []
        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                i += 1
                continue
            marker_name = parse_scenario_split_marker_line(line)
            if marker_name is not None:
                ignored_split_markers.append(marker_name)
                i += 1
                continue
            m1 = TRANSLATE_TAG_RE.match(line)
            if m1 is None:
                raise ValueError(f"{path} 第{i + 1}行格式不合法：{preview_text_for_error(line)}")
            if i + 1 >= len(lines):
                raise ValueError(f"{path} idx={m1.group('idx')} 缺少第二行译文")
            line2 = lines[i + 1]
            m2 = TRANSLATE_TAG_RE.match(line2)
            if m2 is None:
                raise ValueError(f"{path} 第{i + 2}行不是合法的译文行：{preview_text_for_error(line2)}")
            idx1 = int(m1.group("idx"))
            idx2 = int(m2.group("idx"))
            if idx1 != idx2:
                raise ValueError(f"{path} 第{i + 1}-{i + 2}行编号不一致：{idx1} != {idx2}")
            tag1 = normalize_translation_tag(m1.group("tag"))
            tag2 = normalize_translation_tag(m2.group("tag"))
            if tag1 != tag2:
                raise ValueError(f"{path} 第{i + 1}-{i + 2}行标签不一致：{tag1!r} != {tag2!r}")
            parsed_pairs.append((idx1, tag1, m1.group("text"), m2.group("text")))
            i += 2
        changed = 0
        file_legacy_tag_rows = 0
        for idx, tag, original_line, translated_line in parsed_pairs:
            row = text_by_idx.get(idx)
            if row is None:
                raise ValueError(f"{path} 包含未知 idx={idx}")
            expected_tag = export_tag_for_row(export_row_by_idx[idx])
            if not translation_tag_matches_row(tag, export_row_by_idx[idx]):
                raise ValueError(f"{path} idx={idx} 的标签不匹配：文件里是 {tag!r}，当前 dump 期望 {expected_tag!r}")
            if tag != expected_tag:
                file_legacy_tag_rows += 1
            expected = row["original_text"]
            if original_line != expected:
                raise ValueError(
                    f"{path} idx={idx} 的第一行原文和 dump 不一致，疑似错位或误改。\n"
                    f"dump: {preview_text_for_error(expected, 120)}\nfile: {preview_text_for_error(original_line, 120)}"
                )
            if row.get("text", row["original_text"]) != translated_line:
                row["text"] = translated_line
                changed += 1
            updated_idxs.add(idx)
        legacy_tag_rows += file_legacy_tag_rows
        file_reports.append({"file": str(path), "pairs": len(parsed_pairs), "changed": changed, "legacy_tag_rows": file_legacy_tag_rows, "ignored_split_markers": ignored_split_markers[:20]})
    backup_path = dump_dir / "text_entries.jsonl.bak"
    if not backup_path.exists():
        backup_path.write_bytes((dump_dir / "text_entries.jsonl").read_bytes())
    jsonl_dump(dump_dir / "text_entries.jsonl", text_rows)
    report = {"scenario_dir": str(scenario_dir), "files": len(file_reports), "updated_idxs": len(updated_idxs), "legacy_tag_rows": legacy_tag_rows, "file_reports": file_reports[:50]}
    json_dump(dump_dir / "import_scenario_report.json", report)
    return report
