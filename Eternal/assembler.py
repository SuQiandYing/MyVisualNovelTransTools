"""Strict import, ChangeSet planning, reference relocation, and atomic rebuild."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import struct
import sys
import time
import unicodedata

from opcodelist import DIALECT as D, DIALECT_ID, TOOL_VERSION, DIALECT_COMPATIBLE_HASHES
from disassembler import (ToolError, require, sha, canonical, codec, checked_read, save_json,
                          save_jsonl, CELL, HEADER, XOR_TABLE, CONTROL_PATTERN, Document,
                          parse_document, parse_container, serialize_container, render_text,
                          render_asm, verify_sources, choose_output, OutputTransaction,
                          ensure_cancel, certificate, projection_entries, display_width,
                          encode_message_parts, decode_message_parts)

# Own TEXT/2 and ASM projection syntax, not engine recognition heuristics.
TEXT_LINE = re.compile(r"^([○●])([0-9]{8})\1([a-z]+)\1(.*)$")  # dialect-literal-ok: public projection grammar
ASM_STRING = re.compile(r"^\.string id=([^ ]+) sid=([^ ]+) tag=([^ ]+) policy=([^ ]+) value=(.*)$")  # dialect-literal-ok: public projection grammar


@dataclass(frozen=True, slots=True)
class Edit:
    object_id: str
    idx: int
    target: str
    encoded: bytes
    origin: str
    line: int


@dataclass(slots=True)
class Prepared:
    project_path: Path
    source_root: Path
    project: dict
    documents: list[Document]
    edits: dict[str, dict[str, Edit]]
    plans: dict[str, dict]
    output: Path
    summary: dict
    input_hashes: dict[str, str]
    message_changes: dict[str, list[dict]]


def load_project(path: Path, source: Path | None = None):
    path = path.resolve()
    if path.is_file():
        while path.parent != path and not (path / "project.json").is_file():
            path = path.parent
    elif not (path / "project.json").is_file() and (path.parent / "project.json").is_file():
        path = path.parent
    require((path / "project.json").is_file(), "SOURCE_BINDING", str(path))
    try:
        project = json.loads((path / "project.json").read_text(encoding="utf-8"))
        binding = project.pop("binding_hash")
        require(sha(canonical(project)) == binding, "SOURCE_BINDING", "project.json")
        project["binding_hash"] = binding
        require(project["schema_version"] == 1 and project["tool_version"] == TOOL_VERSION
                and project["dialect_id"] == DIALECT_ID, "SOURCE_BINDING", "版本")
        require(project["dialect_hash"] in (sha(Path(__file__).with_name("opcodelist.py").read_bytes()),
                                            *DIALECT_COMPATIBLE_HASHES), "SOURCE_BINDING", "方言")
        codec(project["source_encoding"])
        codec(project["target_encoding"])
        require(project.get("text_projection", D["legacy_text_projection"]) in D["text_projection_modes"],
                "SOURCE_BINDING", "文本投影版本")
        root = Path(source).resolve() if source else Path(project["source_root"]).resolve()
        if root.is_file():
            root = root.parent
        manifest = project["manifest"]
        names = [row["sample"] for row in manifest]
        require(len(names) == len(set(names)) and manifest, "SOURCE_BINDING", "源清单")
        for row in manifest:
            name = Path(row["sample"])
            require(not name.is_absolute() and ".." not in name.parts
                    and (root / name).resolve().is_relative_to(root), "SOURCE_BINDING", str(name))
        verify_sources(root, manifest)
    except (KeyError, ValueError, TypeError) as exc:
        raise ToolError("SOURCE_BINDING", str(exc)) from exc
    return path, root, project


def make_edit(doc: Document, entry, target: str, reviewed: bool, origin: str, line: int,
              target_encoding: str, *, allow_empty: bool = False, check_controls: bool = True,
              allow_engine_linebreaks: bool = False) -> Edit | None:
    location = f"{doc.relative_path} 第 {entry.idx} 条 ({origin}:{line})"
    if target == entry.source:
        return None
    require(allow_empty or target != "" or entry.source == "", "EMPTY_TRANSLATION", location)
    require(entry.policy != "frozen", "FROZEN", location)
    require(entry.policy != "review-required" or reviewed, "REVIEW_REQUIRED", location)
    require("{{" not in target and not any(
        ord(c) < 32 and not (allow_engine_linebreaks and c == "\n") for c in target),
        "PLACEHOLDER_BROKEN", location)
    if check_controls:
        if entry.projection_mode == D["message_break_projection"]:
            validate_message_controls(entry, target)
        else:
            require(CONTROL_PATTERN.findall(target) == CONTROL_PATTERN.findall(entry.source),
                    "PLACEHOLDER_BROKEN", location)
    try:
        encoded = target.encode(target_encoding, "strict")
    except UnicodeError as exc:
        raise ToolError("ENCODING_UNREPRESENTABLE", f"{location}: {target_encoding}: {exc}") from exc
    require(len(encoded) <= D["maximum_text_bytes"] * max(1, len(entry.member_ids)), "LENGTH_OVERFLOW", location)
    return Edit(entry.object_id, entry.idx, target, encoded, origin, line)


def metadata_tokens(line: str) -> dict:
    result = {}
    for token in line.removeprefix("# ").split():
        require("=" in token, "TEXT_PROTOCOL", line)
        key, value = token.split("=", 1)
        require(key not in result, "TEXT_PROTOCOL", f"重复字段 {key}")
        result[key] = value
    return result


def import_text(doc: Document, path: Path, target_encoding: str,
                projection_mode: str = D["default_text_projection"]) -> dict[str, Edit]:
    try:
        content = path.read_text(encoding=D["text_encoding"])
    except (UnicodeError, OSError) as exc:
        raise ToolError("TEXT_PROTOCOL", str(path)) from exc
    lines = content.splitlines()
    fresh = render_text(doc, target_encoding, projection_mode).splitlines()
    require(lines[:4] == fresh[:4], "SOURCE_BINDING", f"{path}: 四行文件头")
    lookup = {entry.idx: entry for entry in projection_entries(doc, projection_mode)}
    pending = None
    source_seen = False
    seen, edits = set(), {}
    for number, line in enumerate(lines[4:], 5):
        if not line or line.startswith("# speaker:") or line == "#":
            continue
        if line.startswith("# idx="):
            require(pending is None, "TEXT_PROTOCOL", f"{path}:{number}: 缺少文本行")
            meta = metadata_tokens(line)
            try:
                idx = int(meta.get("idx", ""))
            except ValueError as exc:
                raise ToolError("TEXT_PROTOCOL", f"{path}:{number}") from exc
            require(meta.get("idx") == f"{idx:08d}" and idx in lookup and idx not in seen, "ENTRY_SET", f"{path}:{number}")
            entry = lookup[idx]
            expected = {"idx": f"{idx:08d}", "off": f"0x{entry.off:08X}", "tag": entry.tag,
                        "object_id": entry.object_id, "policy": entry.policy}
            require(all(meta.get(key) == val for key, val in expected.items()), "SOURCE_ANCHOR", f"{path}:{number}")
            require(set(meta) <= set(expected) | {"reviewed"} and meta.get("reviewed", "false") in ("true", "false"),
                    "TEXT_PROTOCOL", f"{path}:{number}")
            pending, source_seen = (entry, meta.get("reviewed") == "true"), False
            continue
        if line.startswith("#"):
            continue
        match = TEXT_LINE.fullmatch(line)
        require(match is not None and pending is not None, "TEXT_PROTOCOL", f"{path}:{number}")
        mark, number_text, tag, text = match.groups()
        entry, reviewed = pending
        require(number_text == f"{entry.idx:08d}" and tag == entry.tag, "TEXT_PROTOCOL", f"{path}:{number}")
        if mark == "○":
            require(not source_seen and text == entry.source, "SOURCE_ANCHOR", f"{path}:{number}")
            source_seen = True
        else:
            require(source_seen, "TEXT_PROTOCOL", f"{path}:{number}")
            if projection_mode == D["message_break_projection"] and entry.member_ids:
                try:
                    validate_message_target(entry, text)
                except ToolError as exc:
                    location = f"{Path(path).name}:{number} idx={entry.idx:08d} object_id={entry.object_id}"
                    raise ToolError(exc.code, f"{location}: {exc.detail}") from exc
            edit = make_edit(doc, entry, text, reviewed, str(path), number, target_encoding)
            if edit:
                edits[entry.object_id] = edit
            seen.add(entry.idx)
            pending = None
    require(pending is None and seen == set(lookup), "ENTRY_SET", str(path))
    return edits


def import_asm(doc: Document, path: Path, target_encoding: str) -> dict[str, Edit]:
    try:
        lines = path.read_text(encoding=D["asm_encoding"]).splitlines()
    except (UnicodeError, OSError) as exc:
        raise ToolError("ASM_PROTOCOL", str(path)) from exc
    fresh = render_asm(doc, target_encoding).splitlines()
    require(len(lines) == len(fresh), "ASM_PROTOCOL", str(path))
    edits = {}
    for number, (old, new) in enumerate(zip(fresh, lines), 1):
        if old == new:
            continue
        before, after = ASM_STRING.fullmatch(old), ASM_STRING.fullmatch(new)
        require(before is not None and after is not None and before.groups()[:4] == after.groups()[:4],
                "ASM_PROTOCOL", f"{path}:{number}")
        oid = after.group(1)
        require(oid in doc.by_id, "ASM_PROTOCOL", f"{path}:{number}")
        try:
            value = json.loads(after.group(5))
        except (ValueError, TypeError) as exc:
            raise ToolError("ASM_PROTOCOL", f"{path}:{number}") from exc
        require(isinstance(value, str), "ASM_PROTOCOL", f"{path}:{number}")
        edit = make_edit(doc, doc.by_id[oid], value, False, str(path), number, target_encoding,
                         allow_engine_linebreaks=doc.by_id[oid].tag == "msg")
        if edit:
            edits[oid] = edit
    return edits


def merge_edits(*groups):
    result = {}
    for group in groups:
        for oid, edit in group.items():
            if oid in result:
                previous = result[oid]
                require(previous.target == edit.target, "EDIT_CONFLICT",
                        f"idx={edit.idx}: {previous.origin}:{previous.line}={previous.target!r}; "
                        f"{edit.origin}:{edit.line}={edit.target!r}")
            else:
                result[oid] = edit
    return result


def text_atoms(text: str) -> list[str]:
    """Never split a native marker, combining sequence, or joined Unicode cluster."""
    result, index = [], 0
    while index < len(text):
        control = CONTROL_PATTERN.match(text, index)
        stop = control.end() if control else index + 1
        if not control:
            while stop < len(text):
                if unicodedata.category(text[stop]) in ("Mn", "Mc", "Me"):
                    stop += 1
                elif text[stop] == "\u200d" and stop + 1 < len(text):
                    stop += 2
                else:
                    break
        result.append(text[index:stop])
        index = stop
    return result


def join_message(entry, values: list[str], projection_mode: str = D["default_text_projection"]) -> str:
    require(len(values) == len(entry.member_ids), "VERIFY", "整句分段数")
    parts = [value[len(prefix):] if prefix and value.startswith(prefix) else value
             for value, prefix in zip(values, entry.prefixes)]
    return (encode_message_parts(parts) if projection_mode == D["message_break_projection"]
            else "".join(parts))


def message_line_length(value: str) -> int:
    return sum(not CONTROL_PATTERN.fullmatch(atom) for atom in text_atoms(value))


def validate_message_controls(entry, target: str):
    actual = decode_message_parts(target)
    expected = decode_message_parts(entry.source, len(entry.member_ids))
    actual_controls = [control for part in actual for control in CONTROL_PATTERN.findall(part)]
    expected_controls = [control for part in expected for control in CONTROL_PATTERN.findall(part)]
    require(actual_controls == expected_controls,
            "PLACEHOLDER_BROKEN", entry.object_id)


def validate_message_target(entry, target: str) -> list[str]:
    parts = decode_message_parts(target)
    require(len(parts) <= D["message_max_lines"], "LENGTH_OVERFLOW",
            f"{entry.object_id}: 最多 {D['message_max_lines']} 行")
    require(bool(entry.member_ids), "VERIFY", f"{entry.object_id}: 缺少物理文本槽")
    validate_message_controls(entry, target)
    for line, part in enumerate(parts, 1):
        length = message_line_length(part)
        require(length <= D["message_line_char_limit"], "LENGTH_OVERFLOW",
                f"{entry.object_id}: 第 {line} 行译文有 {length} 字，超过 {D['message_line_char_limit']} 字")
    return parts


def split_message(doc: Document, entry, target: str, encoding: str,
                  projection_mode: str = D["default_text_projection"]) -> list[str]:
    """Pack up to three display rows into the message's proven physical slots."""
    members = [doc.by_id[oid] for oid in entry.member_ids]
    if projection_mode == D["message_break_projection"]:
        parts = validate_message_target(entry, target)
        values = [""] * len(entry.member_ids)
        assigned = [0] * len(entry.member_ids)
        for index, part in enumerate(parts):
            slot = min(index, len(values) - 1)
            prefix = entry.prefixes[slot] if assigned[slot] == 0 and part else ""
            if assigned[slot] == 0:
                values[slot] = prefix + part
            else:
                values[slot] += "\n" + part
            assigned[slot] += 1
        for value in values:
            require(len(value.encode(encoding, "strict")) <= D["maximum_text_bytes"],
                    "LENGTH_OVERFLOW", entry.object_id)
        return values

    atoms = text_atoms(target)
    widths = [display_width(atom) for atom in atoms]
    sizes = [len(atom.encode(encoding, "strict")) for atom in atoms]
    prefix_widths = [display_width(prefix) for prefix in entry.prefixes]
    # Keep the source's widest row as a soft budget; spread longer text across
    # all existing rows. This is an estimate, not measured game-font wrapping.
    row_width = max(max(display_width(e.source) for e in members),
                    (sum(widths) + sum(prefix_widths) + len(members) - 1) // len(members), 1)
    result, cursor = [], 0
    for slot, prefix in enumerate(entry.prefixes):
        if cursor == len(atoms):
            result.append("")
            continue
        limit = D["maximum_text_bytes"] - len(prefix.encode(encoding, "strict"))
        budget = max(row_width - prefix_widths[slot], 1)
        if slot == len(members) - 1:
            stop = len(atoms)
        else:
            stop, used, used_bytes = cursor, 0, 0
            while stop < len(atoms) and used_bytes + sizes[stop] <= limit:
                if stop > cursor and used + widths[stop] > budget:
                    break
                used += widths[stop]
                used_bytes += sizes[stop]
                stop += 1
            require(stop > cursor, "LENGTH_OVERFLOW", f"{entry.object_id}: 不可拆分的文字或控制标记过长")
            # Avoid beginning a new row with closing punctuation, or ending
            # a row with an opening bracket. Budgets remain soft; byte limits do not.
            while stop < len(atoms) and atoms[stop][0] in D["line_start_forbidden"] and used_bytes + sizes[stop] <= limit:
                used_bytes += sizes[stop]
                stop += 1
            while stop > cursor + 1 and atoms[stop - 1][-1] in D["line_end_forbidden"]:
                stop -= 1
            if stop < len(atoms) and atoms[stop - 1].isascii() and atoms[stop - 1].isalnum() and atoms[stop].isascii() and atoms[stop].isalnum():
                word_start = stop
                while word_start > cursor and atoms[word_start - 1].isascii() and atoms[word_start - 1].isalnum():
                    word_start -= 1
                if word_start > cursor and sum(widths[cursor:word_start]) >= budget // 2:
                    stop = word_start
        value = prefix + "".join(atoms[cursor:stop])
        require(len(value.encode(encoding, "strict")) <= D["maximum_text_bytes"], "LENGTH_OVERFLOW", entry.object_id)
        result.append(value)
        cursor = stop
    require(cursor == len(atoms) and join_message(entry, result, projection_mode) == target,
            "VERIFY", f"整句分配 {entry.object_id}")
    require(CONTROL_PATTERN.findall(join_message(entry, result, projection_mode)) == CONTROL_PATTERN.findall(entry.source),
            "PLACEHOLDER_BROKEN", entry.object_id)
    return result


def resolve_edits(doc: Document, text_edits: dict[str, Edit], asm_edits: dict[str, Edit],
                  encoding: str, projection_mode: str):
    """Resolve logical TEXT and physical ASM once, before producing byte edits."""
    if projection_mode == D["legacy_text_projection"]:
        return merge_edits(text_edits, asm_edits), []
    projected = projection_entries(doc, projection_mode)
    logical = {e.object_id: e for e in projected if e.member_ids}
    physical = {oid: edit for oid, edit in text_edits.items() if oid not in logical}
    physical = merge_edits(physical, {oid: edit for oid, edit in asm_edits.items() if doc.by_id[oid].tag != "msg"})
    changes = []
    for oid, entry in logical.items():
        text_edit = text_edits.get(oid)
        asm_group = {member: asm_edits[member] for member in entry.member_ids if member in asm_edits}
        if not text_edit and not asm_group:
            continue
        if asm_group:
            values = [asm_group[member].target if member in asm_group else doc.by_id[member].source for member in entry.member_ids]
            target = join_message(entry, values, projection_mode)
            if text_edit:
                target_values = split_message(doc, entry, text_edit.target, encoding, projection_mode)
                require(values == target_values, "EDIT_CONFLICT", f"整句 {oid}: 文本与 ASM 分段译文不一致")
                target = text_edit.target
            physical.update(asm_group)
        else:
            target = text_edit.target
            values = split_message(doc, entry, target, encoding, projection_mode)
            for member, value in zip(entry.member_ids, values):
                edit = make_edit(doc, doc.by_id[member], value, False, text_edit.origin, text_edit.line,
                                 encoding, allow_empty=True, check_controls=False,
                                 allow_engine_linebreaks=True)
                if edit:
                    physical[member] = edit
        changes.append({"object_id": oid, "idx": entry.idx, "source": entry.source, "target": target,
                        "member_ids": entry.member_ids, "prefixes": entry.prefixes, "slots": values,
                        "name_ids": entry.name_ids, "anchor_offset": entry.anchor_offset})
    return physical, changes


def probe(doc: Document, edits: dict[str, Edit], requested: str = "auto") -> dict:
    require(requested in ("auto", "identity", "in_place", "pointer-rewrite"), "STRATEGY", requested)
    by_id = doc.by_id
    growing = [oid for oid, edit in edits.items() if len(edit.encoded) > len(by_id[oid].raw)]
    delta = sum(len(edits[oid].encoded) for oid in growing)
    require(len(doc.container.blocks[-1].data) + delta <= D["maximum_pool_bytes"], "LENGTH_OVERFLOW", doc.relative_path)
    verdicts = [
        {"strategy_id": "identity", "applicable": not edits, "reason_code": "NO_CHANGE" if not edits else "EDIT_PRESENT"},
        {"strategy_id": "in_place", "applicable": bool(edits) and not growing,
         "reason_code": "LENGTH_OVERFLOW" if growing else "OK" if edits else "NO_CHANGE", "blocking_refs": growing},
        {"strategy_id": "pointer-rewrite", "applicable": bool(edits), "reason_code": "OK" if edits else "NO_CHANGE",
         "estimated_deltas": {"bytes": delta, "pool_append_bytes": delta}},
        {"strategy_id": "full-layout", "applicable": False, "reason_code": "CAPABILITY_UNIMPLEMENTED"},
    ]
    available = [row["strategy_id"] for row in verdicts if row["applicable"]]
    require(available and (not edits or requested == "auto" or requested in available), "STRATEGY", f"{doc.relative_path}: {requested}")
    selected = "identity" if not edits else available[0] if requested == "auto" else requested
    plan = {"selected_strategy": selected, "verdicts": verdicts, "append_bytes": delta,
            "source_sha256": sha(doc.raw), "edits_hash": sha(canonical({oid: sha(edit.encoded) for oid, edit in sorted(edits.items())}))}
    plan["plan_hash"] = sha(canonical(plan))
    return plan


def protected_inputs(project: dict, root: Path) -> list[Path]:
    """Protect the actual input scope; single-file defaults are beside that file."""
    source_input = Path(project["source_input"])
    expected_pair = {source_input.name, source_input.with_suffix(".debug").name}
    legacy_kind = "file" if source_input.suffix.lower() == ".bin" and {r["sample"] for r in project["manifest"]} == expected_pair else "directory"
    kind = project.get("source_kind", legacy_kind)
    require(kind in ("file", "directory"), "SOURCE_BINDING", "输入类型")
    return [root / row["sample"] for row in project["manifest"]] if kind == "file" else [root]


def prepare_project(project_path: Path, output: Path | None = None, source: Path | None = None,
                    strategy: str = "auto", progress=None, cancel=None) -> Prepared:
    project_path, root, project = load_project(Path(project_path), source)
    source_input = Path(project["source_input"])
    projection_mode = project.get("text_projection", D["legacy_text_projection"])
    suffix = ("_rebuilt_segments" if projection_mode == D["legacy_text_projection"] else
              "_rebuilt" if projection_mode == D["message_break_projection"] else "_rebuilt_v1")
    output = Path(output).resolve() if output else choose_output(source_input, suffix)
    require(not output.exists(), "OUTPUT_EXISTS", str(output))
    for protected in (*protected_inputs(project, root), project_path):
        require(output != protected and not output.is_relative_to(protected), "OUTPUT_PATH", str(output))
    projections = project["projections"]
    present_kinds = {folder for folder in ("texts", "asm") if (project_path / folder).is_dir()}
    require(present_kinds, "ENTRY_SET", "先输出文本或 ASM")
    expected_paths = {row["path"] for row in projections if row["kind"] in present_kinds}
    actual_paths = {path.relative_to(project_path).as_posix() for folder in ("texts", "asm")
                    if (project_path / folder).exists() for path in (project_path / folder).rglob("*.txt")}
    require(actual_paths == expected_paths, "ENTRY_SET", "编辑面文件有缺失或额外文件")
    input_hashes = {relative: sha(checked_read(project_path / relative)) for relative in actual_paths}
    input_hashes["project.json"] = sha(checked_read(project_path / "project.json"))
    documents, all_edits, plans = [], {}, {}
    message_changes = {}
    bins = [row for row in project["manifest"] if row["sample"].lower().endswith(".bin")]
    for index, row in enumerate(bins):
        ensure_cancel(cancel)
        doc = parse_document(root / row["sample"], row["sample"], project["source_encoding"])
        require(serialize_container(doc.container) == doc.raw, "VERIFY", f"{row['sample']}: 零编辑前置")
        text_edits, asm_edits = {}, {}
        for projection in [p for p in projections if p["source"] == row["sample"] and p["kind"] in present_kinds]:
            relative = Path(projection["path"])
            path = (project_path / relative).resolve()
            require(path.is_relative_to(project_path), "SOURCE_BINDING", str(path))
            if projection["kind"] == "texts":
                # Unchanged text still goes through its full source and entry-set validation.
                text_edits = import_text(doc, path, project["target_encoding"], projection_mode)
            else:
                require(projection["kind"] == "asm", "SOURCE_BINDING", str(path))
                if sha(checked_read(path)) != projection["sha256"]:
                    asm_edits = import_asm(doc, path, project["target_encoding"])
        edits, logical_changes = resolve_edits(doc, text_edits, asm_edits, project["target_encoding"], projection_mode)
        documents.append(doc)
        all_edits[row["sample"]] = edits
        message_changes[row["sample"]] = logical_changes
        plans[row["sample"]] = probe(doc, edits, strategy)
        if progress:
            progress(index + 1, len(bins), row["sample"])
    summary = {"source_files": len(project["manifest"]), "scripts": len(documents),
               "changed_entries": sum(len(edits) for edits in all_edits.values()),
               "changed_files": sum(bool(edits) for edits in all_edits.values()),
               "growing_entries": sum(len(edit.encoded) > len(doc.by_id[oid].raw)
                                      for doc in documents for oid, edit in all_edits[doc.relative_path].items()),
               "append_bytes": sum(plan["append_bytes"] for plan in plans.values()), "conflicts": 0,
               "source_encoding": project["source_encoding"], "target_encoding": project["target_encoding"],
               "text_projection": projection_mode, "logical_message_changes": sum(len(v) for v in message_changes.values()),
               "output": str(output)}
    return Prepared(project_path, root, project, documents, all_edits, plans, output, summary, input_hashes, message_changes)


def layout_map(old: bytes, new: bytes, edits: list[tuple[int, int, str]]) -> list[dict]:
    crc_size = D["checksum_size"]
    tail = len(old) - crc_size
    ranges = sorted((a, b, reason) for a, b, reason in edits if a < b and a < tail)
    merged = []
    for a, b, reason in ranges:
        b = min(b, tail)
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(b, merged[-1][1]), merged[-1][2] + "; " + reason)
        else:
            merged.append((a, b, reason))
    result, cursor = [], 0
    for a, b, reason in merged:
        if cursor < a:
            result.append({"old_offset": cursor, "old_length": a - cursor, "new_offset": cursor,
                           "new_length": a - cursor, "kind": "preserve"})
        result.append({"old_offset": a, "old_length": b - a, "new_offset": a, "new_length": b - a,
                       "kind": "changed", "reason": reason})
        cursor = b
    if cursor < tail:
        result.append({"old_offset": cursor, "old_length": tail - cursor, "new_offset": cursor,
                       "new_length": tail - cursor, "kind": "preserve"})
    append = len(new) - len(old)
    require(append >= 0, "VERIFY", "本实现保留原文本池，不收缩文件")
    if append:
        result.append({"old_offset": tail, "old_length": 0, "new_offset": tail,
                       "new_length": append, "kind": "changed", "reason": "追加已编辑的超长文本"})
    same_crc = old[-crc_size:] == new[-crc_size:]
    result.append({"old_offset": tail, "old_length": crc_size, "new_offset": len(new) - crc_size,
                   "new_length": crc_size, "kind": "preserve" if same_crc else "changed",
                   **({} if same_crc else {"reason": "pool CRC16"})})
    for row in result:
        if row["kind"] == "preserve":
            a, b = row["old_offset"], row["new_offset"]
            require(old[a:a + row["old_length"]] == new[b:b + row["new_length"]], "VERIFY", f"未归因差异 {a}")
    return result


def site_records(doc: Document, new_doc: Document | None = None) -> list[dict]:
    new_by_id = new_doc.by_id if new_doc else {}
    rows = []
    for entry in doc.entries:
        for site in entry.sites:
            for field, offset, width, old_val in (("length", site + 2, 2, len(entry.raw)),
                                                   ("offset", site + 4, 4, entry.pool_offset)):
                row = {"site_offset": offset, "site_width": width, "site_endianness": "little",
                       "key_value": old_val, "key_kind": field,
                       "owner_object_id": entry.object_id, "rewrite_policy": "preserve"}
                if new_doc:
                    target = new_by_id[entry.object_id]
                    new_val = len(target.raw) if field == "length" else target.pool_offset
                    row.update(new_site_offset=offset, new_key_value=new_val,
                               rewrite_policy="rewrite" if old_val != new_val else "preserve")
                rows.append(row)
    return rows


def rebuild_document(doc: Document, edits: dict[str, Edit], plan: dict, target_encoding: str,
                     message_changes: list[dict] | None = None,
                     projection_mode: str = D["default_text_projection"]):
    checked_plan = dict(plan)
    claimed_hash = checked_plan.pop("plan_hash")
    require(sha(canonical(checked_plan)) == claimed_hash and plan["source_sha256"] == sha(doc.raw), "SOURCE_CHANGED", doc.relative_path)
    require(plan["edits_hash"] == sha(canonical({oid: sha(edit.encoded) for oid, edit in sorted(edits.items())})), "SOURCE_CHANGED", "变更集合")
    require(serialize_container(doc.container) == doc.raw, "VERIFY", f"{doc.relative_path}: 零编辑")
    code = bytearray(doc.container.blocks[-2].data)
    pool = bytearray(doc.container.blocks[-1].data)
    code_base, pool_base = doc.container.blocks[-2].start, doc.container.blocks[-1].start
    ranges, relocations = [], []
    for oid, edit in sorted(edits.items()):
        entry = doc.by_id[oid]
        require(entry.pool_offset is not None, "FROZEN", oid)
        if len(edit.encoded) > len(entry.raw):
            require(plan["selected_strategy"] == "pointer-rewrite", "STRATEGY", oid)
            new_offset = len(pool)
            pool.extend(edit.encoded.translate(XOR_TABLE))
        else:
            new_offset = entry.pool_offset
            pool[new_offset:new_offset + len(edit.encoded)] = edit.encoded.translate(XOR_TABLE)
            ranges.append((pool_base + new_offset, pool_base + new_offset + len(edit.encoded), f"text {oid}"))
        for site in entry.sites:
            # Rewrite only the proven length/pointer fields of this object.
            struct.pack_into("<HI", code, site - code_base + 2, len(edit.encoded), new_offset)
            ranges.append((site + 2, site + CELL.size, f"JoinSite {oid}@{site}"))
            relocations.append({"object_id": oid, "idx": entry.idx, "site_offset": site,
                                "old_pool_offset": entry.pool_offset, "new_pool_offset": new_offset,
                                "old_length": len(entry.raw), "new_length": len(edit.encoded),
                                "origin": edit.origin, "line": edit.line})
    header = list(doc.container.header)
    header[-1] = len(pool)
    raw_header = HEADER.pack(*header)
    changes = {"header": raw_header, "code": bytes(code), "pool": bytes(pool)}
    rebuilt = serialize_container(doc.container, changes)
    if raw_header != doc.container.blocks[0].data:
        ranges.append((HEADER.size - 4, HEADER.size, "pool size header"))
    for block in (doc.container.blocks[0], doc.container.blocks[-2]):
        if changes[block.name] != block.data:
            ranges.append((block.end - D["checksum_size"], block.end, f"{block.name} CRC16"))
    parsed = parse_document(doc.container.path, doc.relative_path, doc.source_encoding, rebuilt,
                            doc.companion.raw, baseline=False,
                            entry_encodings={oid: target_encoding for oid in edits})
    require(set(parsed.by_id) == set(doc.by_id), "VERIFY", "对象集合变化")
    for oid, before in doc.by_id.items():
        after = parsed.by_id[oid]
        expected = edits[oid].encoded if oid in edits else before.raw
        require(after.raw == expected and after.sites == before.sites and after.tag == before.tag
                and after.name_ids == before.name_ids, "VERIFY", f"{doc.relative_path}/{oid}")
        if oid in edits:
            require(after.source == edits[oid].target, "VERIFY", f"目标文本 {oid}")
    for offset, length in doc.metadata_ranges:
        require(doc.container.blocks[-1].data[offset:offset + length] == bytes(pool[offset:offset + length]), "VERIFY", "消息信息变化")
    if message_changes:
        logical = {entry.object_id: entry for entry in projection_entries(doc, projection_mode) if entry.member_ids}
        for row in message_changes:
            entry = logical[row["object_id"]]
            values = [parsed.by_id[oid].source for oid in entry.member_ids]
            expected_values = split_message(doc, entry, row["target"], target_encoding, projection_mode)
            require(values == row["slots"] == expected_values, "VERIFY",
                    f"{doc.relative_path}: 整句回读 {entry.object_id}")
            require(all(parsed.by_id[oid].name_ids == entry.name_ids for oid in entry.member_ids), "VERIFY", "整句人名绑定变化")
    require(bool(edits) == (rebuilt != doc.raw), "VERIFY", "编辑未生效或零编辑变化")
    mapping = layout_map(doc.raw, rebuilt, ranges)
    protected_collisions = 0
    keys = {entry.pool_offset for entry in doc.entries if entry.pool_offset is not None}
    pointer_fields = {site + 4 for entry in doc.entries for site in entry.sites}
    for anchor in doc.anchors:
        for arg in anchor.arguments:
            if arg.site + 4 not in pointer_fields and arg.value in keys:
                require(doc.raw[arg.site:arg.site + CELL.size] == rebuilt[arg.site:arg.site + CELL.size], "VERIFY", "值碰撞常量被改动")
                protected_collisions += 1
    report = {"sample": doc.relative_path, "status": "pass", "changed_entries": len(edits),
              "selected_strategy": plan["selected_strategy"], "source_sha256": sha(doc.raw), "output_sha256": sha(rebuilt),
              "source_size": len(doc.raw), "output_size": len(rebuilt), "byte_delta": len(rebuilt) - len(doc.raw),
              "semantic_reparse": "pass", "unedited_objects": "pass", "site_set_isomorphism": "pass",
              "message_rejoin": "pass" if message_changes else "not_applicable",
              "difference_attribution": "pass", "preserved_value_collisions": protected_collisions,
              "byte_coverage": 1.0, "runtime_validation": "not_verified"}
    return rebuilt, report, {"layout": mapping, "sites": site_records(doc, parsed),
                              "rebuilt_sites": site_records(parsed), "relocations": relocations,
                              "coverage": certificate(parsed.container)}


def execute_prepared(prepared: Prepared, progress=None, cancel=None) -> dict:
    started = time.perf_counter()
    project = prepared.project
    verify_sources(prepared.source_root, project["manifest"])
    for relative, digest in prepared.input_hashes.items():
        require(sha(checked_read(prepared.project_path / relative)) == digest, "SOURCE_CHANGED", f"预览后编辑面改变: {relative}")
    txn = OutputTransaction(prepared.output, [*protected_inputs(project, prepared.source_root), prepared.project_path])
    documents = {doc.relative_path: doc for doc in prepared.documents}
    reports, verdicts = [], []
    try:
        for index, item in enumerate(project["manifest"]):
            ensure_cancel(cancel)
            relative = item["sample"]
            source = prepared.source_root / relative
            original = checked_read(source)
            require(sha(original) == item["sha256"], "SOURCE_CHANGED", relative)
            if relative in documents:
                doc = documents[relative]
                rebuilt, report, audit = rebuild_document(doc, prepared.edits[relative], prepared.plans[relative], project["target_encoding"],
                                                          prepared.message_changes.get(relative),
                                                          project.get("text_projection", D["legacy_text_projection"]))
                verdicts.append({"sample": relative, **prepared.plans[relative]})
                if report["changed_entries"]:
                    audit_path = txn.stage / "_work/audit" / relative
                    for key in ("layout", "sites", "rebuilt_sites", "relocations"):
                        save_jsonl(audit_path / (key + ".jsonl"), audit[key])
                    if prepared.message_changes.get(relative):
                        save_jsonl(audit_path / "message_changes.jsonl", prepared.message_changes[relative])
                    save_json(audit_path / "coverage.json", audit["coverage"])
            elif source.suffix.lower() == ".debug":
                rebuilt = serialize_container(parse_container(source, original))
                require(rebuilt == original, "VERIFY", relative)
                report = {"sample": relative, "status": "pass", "changed_entries": 0,
                          "source_sha256": sha(original), "output_sha256": sha(rebuilt), "roundtrip_identity": "pass"}
            else:
                rebuilt = original
                report = {"sample": relative, "status": "pass", "changed_entries": 0,
                          "source_sha256": sha(original), "output_sha256": sha(rebuilt), "preservation": "opaque-copy"}
            destination = txn.stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("wb") as stream:
                stream.write(rebuilt)
                stream.flush()
                os.fsync(stream.fileno())
            require(checked_read(destination) == rebuilt, "VERIFY", f"落盘重读 {relative}")
            reports.append(report)
            if progress:
                progress(index + 1, len(project["manifest"]), relative)
        verify_sources(prepared.source_root, project["manifest"])
        summary = {"status": "pass", "scope": "static-rebuild-validation", **prepared.summary,
                   "roundtrip_identity": "pass" if prepared.summary["changed_entries"] == 0 else "baseline-pass",
                   "source_unchanged": "pass", "runtime_validation": "not_verified",
                   "seconds": round(time.perf_counter() - started, 3)}
        save_json(txn.stage / "_work/reports/rebuild.json", reports)
        save_json(txn.stage / "_work/reports/repack_verdicts.json", verdicts)
        save_json(txn.stage / "_work/reports/summary.json", summary)
        save_json(txn.stage / "_work/reports/source_manifest.json", project["manifest"])
        ensure_cancel(cancel)
        txn.commit()
        return summary
    except Exception as exc:
        save_json(prepared.output.parent / ("." + prepared.output.name + ".failure-" + str(time.time_ns()) + ".json"),
                  {"status": "not_verified" if isinstance(exc, ToolError) and exc.code == "CANCELLED" else "fail",
                   "stage": "rebuild", "error": str(exc), "completed_files": len(reports),
                   "next_action": "修正原因后重新执行；不自动切换策略", "output": str(prepared.output)})
        txn.abort()
        raise


def rebuild_project(project_path: Path, output: Path | None = None, source: Path | None = None,
                    strategy: str = "auto", progress=None, cancel=None) -> dict:
    return execute_prepared(prepare_project(project_path, output, source, strategy, progress, cancel), progress, cancel)


def main():
    parser = argparse.ArgumentParser(description="严格校验并回封已解出的 NORI v65536 脚本文本，结果写入独立新目录。")
    parser.add_argument("project", type=Path, help="*_text 工作目录，或其中的 texts/ASM 文件")
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("-s", "--source", type=Path)
    parser.add_argument("--strategy", choices=("auto", "identity", "in_place", "pointer-rewrite"), default="auto")
    parser.add_argument("--preview", action="store_true")
    args = parser.parse_args()
    try:
        prepared = prepare_project(args.project, args.output, args.source, args.strategy)
        result = {"status": "pass", "scope": "read-only-preview", **prepared.summary} if args.preview else execute_prepared(prepared)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (ToolError, OSError) as exc:
        print(json.dumps({"status": "fail", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    raise SystemExit(main())
