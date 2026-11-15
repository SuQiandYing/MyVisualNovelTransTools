from __future__ import annotations

from pathlib import Path
from typing import Iterable

from ..binary.primitives import sha256_hex
from ..core.errors import MessageLayoutError
from ..core.models import DumpArtifacts, MessageEvent, TextClassificationContext, TextEntry
from ..core.profiles import AbstractGameProfile
from ..engine.script_parser import ParsedScript
from ..engine.text_dat_parser import load_text_dat_auto
from ..engine.text_references import find_text_reference_sites
from ..io.json_io import json_dump, jsonl_dump
from ..io.compat_text import text_has_raw_bytes
from .scenario_workflow import classify_scenario_role
from .rebuild_workflow import _commit_outputs
from .source_recovery import recover_pasted_source


def build_text_offset_map(entries: Iterable[TextEntry]) -> dict[int, TextEntry]:
    return {entry.entry_offset: entry for entry in entries}


def build_message_rows(events: list[MessageEvent]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for event in events:
        rows.append(
            {
                "call_offset": event.call_offset,
                "call_offset_hex": f"0x{event.call_offset:08X}",
                "call_id": event.call_id,
                "call_id_hex": f"0x{event.call_id:08X}",
                "line_id": event.line_id,
                "line_id_hex": f"0x{event.line_id:08X}",
                "kind": event.kind,
                "flags": list(event.flags),
                "flags_hex": [f"0x{value:08X}" for value in event.flags],
                "text_offset": event.text_offset,
                "text_offset_hex": f"0x{event.text_offset:08X}",
                "text_idx": event.text_idx,
                "text": event.text,
                "name_offset": event.name_offset,
                "name_offset_hex": None if event.name_offset is None else f"0x{event.name_offset:08X}",
                "name_idx": event.name_idx,
                "name": event.name,
            }
        )
    return rows


def build_text_entry_rows(
    profile: AbstractGameProfile,
    entries: list[TextEntry],
    refs: dict[int, list[int]],
    events: list[MessageEvent],
    choice_offsets: set[int],
    label_offsets: set[int],
    direct_call_ids: dict[int, list[int]],
    *,
    verified_scenario_offsets: set[int] | None = None,
) -> list[dict[str, object]]:
    text_roles: dict[int, set[str]] = {entry.entry_offset: set() for entry in entries}
    text_event_count: dict[int, int] = {entry.entry_offset: 0 for entry in entries}
    name_event_count: dict[int, int] = {entry.entry_offset: 0 for entry in entries}
    paired_texts: dict[int, list[str]] = {entry.entry_offset: [] for entry in entries}

    for event in events:
        text_roles[event.text_offset].add("message_text")
        text_event_count[event.text_offset] += 1
        if event.name is not None:
            paired_texts[event.text_offset].append(event.name)
        if event.name_offset is not None:
            text_roles[event.name_offset].add("speaker_name")
            name_event_count[event.name_offset] += 1
            paired_texts[event.name_offset].append(event.text)

    rows: list[dict[str, object]] = []
    for entry in entries:
        role_set = set(text_roles[entry.entry_offset])
        if entry.entry_offset in choice_offsets:
            role_set.add("choice_text")
        if entry.entry_offset in label_offsets:
            role_set.add("script_label")
        if not role_set and refs[entry.entry_offset]:
            role_set.add("other_reference")
        if not role_set:
            role_set.add("unreferenced")
        role_list = sorted(role_set)
        call_ids = direct_call_ids.get(entry.entry_offset, [])
        context = TextClassificationContext(
            entry=entry,
            roles=tuple(role_list),
            reference_offsets=tuple(refs[entry.entry_offset]),
            direct_call_ids=tuple(call_ids),
            message_text_count=text_event_count[entry.entry_offset],
            speaker_name_count=name_event_count[entry.entry_offset],
            paired_texts=tuple(paired_texts[entry.entry_offset]),
        )
        export_tag = profile.classify_entry_tag(context)
        boundary_tag = export_tag
        verified_boundary = entry.entry_offset in (verified_scenario_offsets or ())
        if verified_boundary:
            export_tag = "scenario"
        scenario_role, boundary_source = classify_scenario_role(
            {
                "idx": entry.idx,
                "original_text": entry.original_text,
                "export_tag": export_tag,
                "direct_call_ids": call_ids,
                "direct_call_ids_hex": [f"0x{value:08X}" for value in call_ids],
                "scenario_boundary_verified": verified_boundary,
            }
        )
        rows.append(
            {
                "order": entry.order,
                "idx": entry.idx,
                "entry_offset": entry.entry_offset,
                "entry_offset_hex": f"0x{entry.entry_offset:08X}",
                "raw_text_hex": entry.raw_text.hex(),
                "original_text": entry.original_text,
                "text": entry.original_text,
                "roles": role_list,
                "primary_role": context.primary_role,
                "export_tag": export_tag,
                "ref_count": len(refs[entry.entry_offset]),
                "ref_word_offsets": refs[entry.entry_offset],
                "ref_word_offsets_hex": [f"0x{offset:08X}" for offset in refs[entry.entry_offset]],
                "direct_call_ids": call_ids,
                "direct_call_ids_hex": [f"0x{value:08X}" for value in call_ids],
                "scenario_role": scenario_role,
                "scenario_boundary_source": boundary_source,
                "scenario_boundary_verified": verified_boundary,
                "message_text_count": text_event_count[entry.entry_offset],
                "speaker_name_count": name_event_count[entry.entry_offset],
            }
        )
        if verified_boundary:
            rows[-1]["source_boundary_tag"] = boundary_tag
    return rows


def dump_command(
    script_path: Path,
    text_path: Path,
    out_dir: Path,
    *,
    profile: AbstractGameProfile,
    text_codec: str | None = None,
    reference_pac: Path | None = None,
) -> DumpArtifacts:
    out_dir.mkdir(parents=True, exist_ok=True)
    script_data = script_path.read_bytes()
    script = ParsedScript.from_bytes(
        script_data,
        instruction_set=profile.get_instruction_set(),
    )
    archive = load_text_dat_auto(
        text_path,
        profile,
        text_codec=text_codec or profile.get_text_codec(),
    )
    entries = list(archive.entries)
    text_map = build_text_offset_map(entries)
    recovered = None
    try:
        events = profile.extract_message_events(script, text_map)
    except MessageLayoutError as error:
        try:
            recovered = recover_pasted_source(
                script_path, text_path, script, archive, profile,
                text_codec=text_codec or profile.get_text_codec(), reference_pac=reference_pac,
            )
        except (ValueError, OSError) as recovery_error:
            raise MessageLayoutError(f"{error}\n恢复未完成：{recovery_error}") from recovery_error
        script_data = recovered.script_data
        script = ParsedScript.from_bytes(script_data, instruction_set=profile.get_instruction_set())
        archive = recovered.archive
        entries = list(archive.entries)
        text_map = build_text_offset_map(entries)
        events = profile.extract_message_events(script, text_map)
    refs = script.build_reference_map(text_map)
    choice_offsets = profile.detect_choice_text_offsets(script, text_map)
    label_offsets = profile.detect_label_text_offsets(script, text_map)
    direct_call_ids = script.build_direct_call_id_map(refs)
    verified_scenario_offsets = {
        site.entry_offset for site in find_text_reference_sites(script, entries)
        if site.call_id == 0x000F0002
    } if profile.name == "classic-softpal" else set()

    text_rows = build_text_entry_rows(
        profile,
        entries,
        refs,
        events,
        choice_offsets,
        label_offsets,
        direct_call_ids,
        verified_scenario_offsets=verified_scenario_offsets,
    )
    message_rows = build_message_rows(events)
    script_rows = script.to_rows(text_map)

    tag_counts: dict[str, int] = {}
    for row in text_rows:
        tag = str(row["export_tag"])
        tag_counts[tag] = tag_counts.get(tag, 0) + 1
    decode_issue_idxs = [entry.idx for entry in entries if text_has_raw_bytes(entry.original_text)]

    manifest = {
        "profile": profile.name,
        "script_name": script_path.name,
        "text_name": text_path.name,
        "script_size": len(script_data),
        "text_size": len(archive.normalized_data),
        "script_sha256": sha256_hex(script_data),
        "text_sha256": sha256_hex(archive.normalized_data),
        "text_header_hex": archive.header.hex(),
        "text_trailer_hex": archive.trailer.hex(),
        "text_codec": text_codec or profile.get_text_codec(),
        "text_decode_issue_count": len(decode_issue_idxs),
        "text_decode_issue_idx_sample": decode_issue_idxs[:20],
        "text_entry_count": len(entries),
        "script_word_count": len(script.words),
        "message_event_count": len(events),
        "message_call_ids_hex": [f"0x{value:08X}" for value in sorted(profile.get_message_call_ids())],
        "choice_text_count": len(choice_offsets),
        "label_text_count": len(label_offsets),
        "text_input_mode": archive.input_mode,
        "text_was_encrypted": archive.was_encrypted,
        "export_tag_counts": tag_counts,
        "notes": [
            "dump 会自动尝试按明文和加密两种模式解析 TEXT.DAT。",
            "如果输入是加密版，脚本会先在内存中解密，再执行反汇编与文本提取。",
            "text_entries.jsonl 是无损条目流；不改 text 字段时可原样回编。",
            "messages.jsonl 是高层消息事件；这里已经把人名和正文拆开。",
            "choice_text 由 0x60001..0x60003 选项构造块识别；script_label 由 0x12005A 锚点识别。",
            "额外标签会按调用结构与文本形态细分为 label_text / label_internal / ui / display / system / font / kana / symbol / asset / config / scenario / debug / misc。",
            "script_words.jsonl 是 SCRIPT.SRC 的无损 4 字节词流；从它重建可以保证位级一致。",
        ],
    }

    if decode_issue_idxs:
        manifest["notes"].append(f"有 {len(decode_issue_idxs)} 条记录含当前编码无法解码的字节；JSON 保留原字节，双行导出使用明确的字节转义。")

    if recovered is not None:
        _commit_outputs(out_dir / "source_recovered", {
            "SCRIPT.SRC": recovered.script_data, "TEXT.DAT": recovered.text_file_data,
        })
        manifest["source_recovery"] = recovered.report
        manifest["notes"].append("输入记录曾被合并并错位；已从原包核对并生成恢复副本，原始输入未覆盖。")
    json_dump(out_dir / "manifest.json", manifest)
    jsonl_dump(out_dir / "text_entries.jsonl", text_rows)
    jsonl_dump(out_dir / "messages.jsonl", message_rows)
    jsonl_dump(out_dir / "script_words.jsonl", script_rows)
    return DumpArtifacts(
        manifest=manifest,
        text_rows=text_rows,
        message_rows=message_rows,
        script_rows=script_rows,
    )
