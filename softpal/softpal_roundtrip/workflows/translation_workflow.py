from __future__ import annotations

from pathlib import Path

from ..io.compat_text import (
    TRANSLATE_TAG_RE,
    detect_idx_range_from_lines,
    filter_text_rows_by_idx,
    normalize_idx_range,
    preview_text_for_error,
    read_text_auto,
)
from ..io.json_io import json_dump, jsonl_dump, load_jsonl
from ..io.translation_workflow_support import (
    annotate_scenario_export_tags,
    build_translate_blocks,
    build_translation_header,
    export_tag_for_row,
    normalize_translation_tag,
    translation_tag_matches_row,
)


def export_translation_command(
    dump_dir: Path,
    out_path: Path,
    *,
    file_encoding: str = "utf-16",
    idx_start: int | None = None,
    idx_end: int | None = None,
) -> dict:
    idx_start, idx_end = normalize_idx_range(idx_start, idx_end)
    text_rows = load_jsonl(dump_dir / "text_entries.jsonl")
    message_rows = load_jsonl(dump_dir / "messages.jsonl")
    text_rows = annotate_scenario_export_tags(text_rows, message_rows)
    filtered_rows = filter_text_rows_by_idx(text_rows, idx_start, idx_end)
    header = build_translation_header(idx_start, idx_end)
    body = build_translate_blocks(filtered_rows, message_rows)
    with out_path.open("w", encoding=file_encoding, newline="\r\n") as handle:
        handle.write("\n".join(header + body))
    return {
        "translation_file": str(out_path),
        "file_encoding": file_encoding,
        "idx_start": idx_start,
        "idx_end": idx_end,
        "rows": len(filtered_rows),
        "total_rows": len(text_rows),
    }


def import_translation_command(
    dump_dir: Path,
    in_path: Path,
    *,
    idx_start: int | None = None,
    idx_end: int | None = None,
) -> dict:
    text_rows = load_jsonl(dump_dir / "text_entries.jsonl")
    message_rows = load_jsonl(dump_dir / "messages.jsonl")
    export_rows = annotate_scenario_export_tags(text_rows, message_rows)
    export_row_by_idx = {int(row["idx"]): row for row in export_rows}
    text_by_idx = {int(row["idx"]): row for row in text_rows}
    content = read_text_auto(in_path)
    lines = content.splitlines()
    if idx_start is None and idx_end is None:
        idx_start, idx_end = detect_idx_range_from_lines(lines)
    idx_start, idx_end = normalize_idx_range(idx_start, idx_end)
    scoped_rows = filter_text_rows_by_idx(text_rows, idx_start, idx_end)
    scoped_idx_set = {int(row["idx"]) for row in scoped_rows}
    parsed_pairs: list[tuple[int, str, str, str]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        m1 = TRANSLATE_TAG_RE.match(line)
        if m1 is None:
            raise ValueError(f"第{i + 1}行格式不合法：{preview_text_for_error(line)}")
        if i + 1 >= len(lines):
            raise ValueError(f"idx={m1.group('idx')} 缺少第二行译文")
        line2 = lines[i + 1]
        m2 = TRANSLATE_TAG_RE.match(line2)
        if m2 is None:
            raise ValueError(f"第{i + 2}行不是合法的译文行：{preview_text_for_error(line2)}")
        idx1 = int(m1.group("idx"))
        idx2 = int(m2.group("idx"))
        if idx1 != idx2:
            raise ValueError(f"第{i + 1}-{i + 2}行编号不一致：{idx1} != {idx2}")
        tag1 = normalize_translation_tag(m1.group("tag"))
        tag2 = normalize_translation_tag(m2.group("tag"))
        if tag1 != tag2:
            raise ValueError(f"第{i + 1}-{i + 2}行标签不一致：{tag1!r} != {tag2!r}")
        parsed_pairs.append((idx1, tag1, m1.group("text"), m2.group("text")))
        i += 2

    seen: set[int] = set()
    changed = 0
    legacy_tag_rows = 0
    for idx, tag, original_line, translated_line in parsed_pairs:
        row = text_by_idx.get(idx)
        if row is None:
            raise ValueError(f"译文文件里的 idx={idx} 不存在于 text_entries.jsonl")
        if (idx_start is not None or idx_end is not None) and idx not in scoped_idx_set:
            raise ValueError(
                f"idx={idx} 不在当前导入范围内：{idx_start if idx_start is not None else '-inf'} .. {idx_end if idx_end is not None else '+inf'}"
            )
        expected_tag = export_tag_for_row(export_row_by_idx[idx])
        if not translation_tag_matches_row(tag, export_row_by_idx[idx]):
            raise ValueError(f"idx={idx} 的标签不匹配：文件里是 {tag!r}，当前 dump 期望 {expected_tag!r}")
        if tag != expected_tag:
            legacy_tag_rows += 1
        expected = row["original_text"]
        if original_line != expected:
            raise ValueError(
                f"idx={idx} 的第一行原文和 dump 不一致，疑似错位或误改。\n"
                f"dump: {preview_text_for_error(expected, 120)}\nfile: {preview_text_for_error(original_line, 120)}"
            )
        row["text"] = translated_line
        seen.add(idx)
        if translated_line != expected:
            changed += 1

    expected_rows = scoped_rows if (idx_start is not None or idx_end is not None) else text_rows
    missing = [row["idx"] for row in expected_rows if int(row["idx"]) not in seen]
    if missing:
        raise ValueError(f"译文文件不完整，缺少 {len(missing)} 条；第一条缺失 idx={missing[0]}")

    backup_path = dump_dir / "text_entries.jsonl.bak"
    if not backup_path.exists():
        backup_path.write_bytes((dump_dir / "text_entries.jsonl").read_bytes())
    jsonl_dump(dump_dir / "text_entries.jsonl", text_rows)
    report = {
        "translation_file": str(in_path),
        "idx_start": idx_start,
        "idx_end": idx_end,
        "imported_rows": len(expected_rows),
        "total_rows": len(text_rows),
        "changed_rows": changed,
        "unchanged_rows": len(expected_rows) - changed,
        "legacy_tag_rows": legacy_tag_rows,
    }
    json_dump(dump_dir / "import_translation_report.json", report)
    return report
