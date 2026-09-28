#!/usr/bin/env python3
"""Strict TEXT/2 and .string edits -> ACT_A/PTR/TXD -> verified data.fpk."""

import argparse
from collections import Counter
from difflib import SequenceMatcher
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import sys
import tempfile
import time

from disassembler import ToolError, default_output, input_paths, render_asm
from extract_text import ANCHOR, NAME_ID_BASE, digest, examine, parse_spt, render_scene
from fpk_repack import Archive, build as build_archive, verify as verify_archive
from opcodelist import DIALECT


HEADER = re.compile(r"^# TEXT/2 ir=1 tool=([a-zA-Z0-9_.-]+) "
                    r"src_sha256=([a-f0-9]{64}) src_id=([^\s]+)$")
COMMENT = re.compile(r"^# idx=([0-9]{8}) tag=(name|msg|choice|label|ui|system|ruby|misc)"
                     r"(?: speaker=(.*))?$")
ORIGINAL = re.compile(r"^○([0-9]{8})○(name|msg|choice|label|ui|system|ruby|misc)○(.*)$")
TRANSLATION = re.compile(r"^●([0-9]{8})●(name|msg|choice|label|ui|system|ruby|misc)●(.*)$")
TOKEN = re.compile(r"\\n|&heart;|\{\{[0-9A-F]{2}(?::[0-9A-F]{2})*\}\}")


def _text_file(path, *, bom=False):
    raw = path.read_bytes()
    if bom and not raw.startswith(b"\xef\xbb\xbf"):
        # Older exports from extract_text.py used UTF-8 without a BOM.
        pass
    try:
        text = raw.decode("utf-8-sig", "strict")
    except UnicodeError as exc:
        raise ToolError("TEXT_ENCODING", f"{path}: {exc}") from exc
    if "\r" in text.replace("\r\n", ""):
        raise ToolError("TEXT_SYNTAX", f"{path}: 不允许单独的 CR 字符")
    return text.replace("\r\n", "\n")


def _expected(entries):
    by_idx = {}
    for e in entries:
        if e["name_id"] is not None:
            by_idx[e["name_id"]] = ("name", e["speaker"], None, e["id"])
        by_idx[e["id"]] = (e["tag"], e["text"], e["speaker"], e["id"])
    return by_idx


def _tokens_equal(source, candidate, idx):
    old, new = TOKEN.findall(source), TOKEN.findall(candidate)
    if old != new or ("{{" in candidate and "{{" not in source):
        raise ToolError("PLACEHOLDER_BROKEN",
                        f"idx={idx:08d}: 保留 \\n / &heart; 的数量和顺序；新字节占位符不受支持")
    if "{{" in candidate:
        # This dialect has no demonstrated raw-byte token ledger.
        raise ToolError("PLACEHOLDER_BROKEN", f"idx={idx:08d}: 字面占位符有歧义")


def _marker_positions(text):
    """Return dialect markers, offsets in visible codepoints, and visible text."""
    markers, positions, spans = [], [], []
    cursor = visible = 0
    for match in TOKEN.finditer(text):
        part = text[cursor:match.start()]
        spans.append(part)
        visible += len(part)
        markers.append(match.group())
        positions.append(visible)
        cursor = match.end()
    spans.append(text[cursor:])
    return markers, positions, "".join(spans)


def _word_boundary(text, offset, lower, upper):
    """Do not insert a marker into the middle of an ASCII/full-width Latin word."""
    latin = re.compile(r"[A-Za-z0-9Ａ-Ｚａ-ｚ０-９]")
    if not (0 < offset < len(text) and latin.fullmatch(text[offset - 1])
            and latin.fullmatch(text[offset])):
        return offset
    possible = [i for i in range(lower, upper + 1)
                if not (0 < i < len(text) and latin.fullmatch(text[i - 1])
                        and latin.fullmatch(text[i]))]
    return min(possible, key=lambda i: (abs(i - offset), i)) if possible else offset


def _propose_marker_alignment(source, candidate, idx):
    """Project source marker order onto the current translation; never match text/IDs.

    Translation content is left intact. Existing matching markers stay at their
    original positions; missing markers use proportional positions between
    matched anchors and extras are removed. The user must review this proposal.
    """
    if source and not candidate:
        raise ToolError("EMPTY_TRANSLATION", f"idx={idx:08d}")
    if "\n" in candidate or "\r" in candidate or "\x00" in candidate:
        raise ToolError("TEXT_SYNTAX", f"idx={idx:08d}: 请使用原有的字面 \\n 分行")
    old, old_pos, old_text = _marker_positions(source)
    new, new_pos, new_text = _marker_positions(candidate)
    if old == new:
        return candidate
    if "{{" in source or "{{" in candidate:
        raise ToolError("PLACEHOLDER_BROKEN",
                        f"idx={idx:08d}: 字节占位符身份未证明，不能自动调整")
    if Counter(old) == Counter(new):
        raise ToolError("PLACEHOLDER_BROKEN",
                        f"idx={idx:08d}: 标记数量相同但顺序改变，请手动恢复")
    matching_blocks = SequenceMatcher(None, old, new, autojunk=False).get_matching_blocks()
    matched = {i + k: j + k
               for i, j, length in matching_blocks
               for k in range(length)}
    if old and new and not matched:
        raise ToolError("PLACEHOLDER_BROKEN",
                        f"idx={idx:08d}: 标记类型无法对应，请手动恢复")
    source_anchors = [(-1, 0, 0)]
    source_anchors.extend((i, old_pos[i], new_pos[j]) for i, j in sorted(matched.items()))
    source_anchors.append((len(old), len(old_text), len(new_text)))
    placements = {}
    for i, (left_idx, left_src, left_dst) in enumerate(source_anchors[:-1]):
        right_idx, right_src, right_dst = source_anchors[i + 1]
        for marker_idx in range(left_idx + 1, right_idx):
            if right_src == left_src:
                at = left_dst
            else:
                at = left_dst + round((old_pos[marker_idx] - left_src)
                                      * (right_dst - left_dst) / (right_src - left_src))
            placements[marker_idx] = _word_boundary(new_text, at, left_dst, right_dst)
    for source_idx, target_idx in matched.items():
        placements[source_idx] = new_pos[target_idx]
    by_position = sorted((offset, i, old[i]) for i, offset in placements.items())
    parts, cursor = [], 0
    for offset, _, token in by_position:
        parts.extend((new_text[cursor:offset], token))
        cursor = offset
    parts.append(new_text[cursor:])
    proposed = "".join(parts)
    if TOKEN.findall(proposed) != old or TOKEN.sub("", proposed) != new_text:
        raise ToolError("PLACEHOLDER_BROKEN",
                        f"idx={idx:08d}: 自动调整标记未能保持译文字节")
    return proposed


def _validate_value(idx, tag, source, candidate):
    if candidate == source:
        return
    if source and not candidate:
        raise ToolError("EMPTY_TRANSLATION", f"idx={idx:08d}")
    if "\n" in candidate or "\r" in candidate or "\x00" in candidate:
        raise ToolError("TEXT_SYNTAX", f"idx={idx:08d}: 请使用原有的字面 \\n 分行")
    _tokens_equal(source, candidate, idx)
    if tag == "name" and ("," in candidate or "\u3000" in candidate):
        raise ToolError("NAME_DELIMITER", f"idx={idx:08d}: 人名不能含逗号或全角空格")
    try:
        candidate.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise ToolError("ENCODING_UNREPRESENTABLE", f"idx={idx:08d}: {exc}") from exc


def _parse_text(path, items, source_hash, scene, source_enc, target_enc,
                marker_repairs):
    lines = _text_file(path, bom=True).split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if len(lines) < 4:
        raise ToolError("TEXT_SYNTAX", f"{path}: 头部不足四行")
    match = HEADER.fullmatch(lines[0])
    if not match or match.group(1) != "interheart-extract-1":
        raise ToolError("TEXT_SYNTAX", f"{path}: TEXT/2 头部或工具版本无效")
    if (match.group(2), match.group(3)) != (source_hash, scene):
        raise ToolError("SOURCE_MISMATCH", f"{path}: 旧译文与当前 SPT/ACT_A/PTR/TXD 不匹配")
    if lines[1:4] != [
        f"# encoding source={source_enc} target={target_enc} file=utf-8",
        "# scope kind=all range=ALL part=1/1",
        "# tags name msg choice label ui system ruby misc",
    ]:
        raise ToolError("TEXT_HEADER", f"{path}: 编码/范围/标签声明不匹配")
    expected = _expected(items)
    seen = set()
    changes = {}
    cursor = 4
    while cursor < len(lines):
        if not lines[cursor]:
            cursor += 1
            continue
        if cursor + 2 >= len(lines):
            raise ToolError("TEXT_SYNTAX", f"{path}:{cursor+1}: 条目缺行")
        m, a, b = (COMMENT.fullmatch(lines[cursor]),
                   ORIGINAL.fullmatch(lines[cursor + 1]),
                   TRANSLATION.fullmatch(lines[cursor + 2]))
        if not (m and a and b):
            raise ToolError("TEXT_SYNTAX", f"{path}:{cursor+1}: 三行格式/分隔符错误")
        if m.group(1) != a.group(1) or m.group(1) != b.group(1):
            raise ToolError("TEXT_ID", f"{path}:{cursor+1}: 三行编号不一致")
        idx = int(m.group(1))
        if idx in seen or idx not in expected:
            raise ToolError("TEXT_ID", f"{path}:{cursor+1}: 重复或未知 idx={idx:08d}")
        seen.add(idx)
        tag, source, speaker, ident = expected[idx]
        if (m.group(2), a.group(2), b.group(2)) != (tag, tag, tag):
            raise ToolError("TEXT_TAG", f"{path}:{cursor+1}: idx={idx:08d}")
        if m.group(3) != (speaker or None) or a.group(3) != source:
            raise ToolError("SOURCE_ANCHOR", f"{path}:{cursor+1}: idx={idx:08d} 原文/人名锚不匹配")
        value = b.group(3)
        repaired = _propose_marker_alignment(source, value, idx)
        if repaired != value:
            marker_repairs.append({
                "scene": scene, "idx": f"{idx:08d}",
                "before": value, "after": repaired,
            })
            value = repaired
        _validate_value(idx, tag, source, value)
        if value != source:
            changes[idx] = value
        cursor += 3
        if cursor < len(lines) and lines[cursor]:
            raise ToolError("TEXT_SYNTAX", f"{path}:{cursor+1}: 条目间缺空行")
    if seen != set(expected):
        raise ToolError("TEXT_MISSING", f"{path}: 缺少 {len(set(expected)-seen)} 条")
    return changes


def _parse_asm(path, fresh, expected):
    user = _text_file(path).splitlines()
    canonical = fresh.decode("utf-8").splitlines()
    if len(user) != len(canonical):
        raise ToolError("TIER_TOO_LOW", f"{path}: 不允许增删或重排结构行")
    changes = {}
    for line_no, (old, new) in enumerate(zip(canonical, user), 1):
        if old == new:
            continue
        if not old.startswith("    .string "):
            raise ToolError("TIER_TOO_LOW", f"{path}:{line_no}: 非字符串结构尚不能改写")
        prefix, old_value = old.split(" value=", 1)
        if not new.startswith(prefix + " value="):
            raise ToolError("TIER_TOO_LOW", f"{path}:{line_no}: 只允许改 .string 的 value")
        ident = prefix.split(" id=", 1)[1].split(" ", 1)[0]
        idx = NAME_ID_BASE + int(ident[1:]) if ident[0] == "N" else int(ident[1:])
        try:
            value = json.loads(new[len(prefix) + len(" value="):])
        except (ValueError, TypeError) as exc:
            raise ToolError("ASM_SYNTAX", f"{path}:{line_no}: JSON 引号字符串格式无效") from exc
        if not isinstance(value, str) or idx not in expected:
            raise ToolError("ASM_SYNTAX", f"{path}:{line_no}: 不是已知字符串对象")
        tag, source, _, _ = expected[idx]
        _validate_value(idx, tag, source, value)
        if value != source:
            changes[idx] = value
    return changes


def _projection_changes(edits, analysis, manifest):
    text_dir, asm_dir = edits / "texts", edits / "asm"
    if not text_dir.is_dir() and not asm_dir.is_dir():
        raise ToolError("NO_PROJECTION", f"{edits}: 找不到 texts/ 或 asm/")
    text_changes, asm_changes, marker_repairs = {}, {}, []
    if text_dir.is_dir():
        expected_names = {name + ".txt" for name in analysis["by_file"]}
        actual_names = {p.name for p in text_dir.iterdir() if p.is_file()}
        if expected_names != actual_names:
            raise ToolError("TEXT_MISSING", f"texts/: 缺少 {sorted(expected_names-actual_names)[:3]} "
                            f"多余 {sorted(actual_names-expected_names)[:3]}")
        for name, items in analysis["by_file"].items():
            text_changes.update(_parse_text(
                text_dir / (name + ".txt"), items,
                analysis["source_identities"][name], name,
                manifest["source_encoding"], manifest["target_encoding"],
                marker_repairs))
    if asm_dir.is_dir():
        expected_names = {p.name + ".asm.txt" for p in analysis["files"]}
        actual_names = {p.name for p in asm_dir.iterdir() if p.is_file()}
        if expected_names != actual_names:
            raise ToolError("ASM_MISSING", f"asm/: 缺少 {sorted(expected_names-actual_names)[:3]} "
                            f"多余 {sorted(actual_names-expected_names)[:3]}")
        for path in analysis["files"]:
            name = path.name
            raw, rows = parse_spt(path)
            fresh = render_asm(name, raw, rows, analysis["by_file"].get(name, []),
                               analysis["source_identities"][name],
                               manifest["target_encoding"])
            asm_changes.update(_parse_asm(
                asm_dir / (name + ".asm.txt"), fresh,
                _expected(analysis["by_file"].get(name, []))))
    conflicts = {idx: {"texts": text_changes[idx], "asm": asm_changes[idx]}
                 for idx in text_changes.keys() & asm_changes.keys()
                 if text_changes[idx] != asm_changes[idx]}
    return {**asm_changes, **text_changes}, conflicts, marker_repairs


def _source_candidate(data, analysis, changes):
    """Keep CRLF and every source line count; only edit demonstrated text spans."""
    raw = (data / "ACT_A.txt").read_bytes()
    if b"\n" in raw.replace(b"\r\n", b""):
        raise ToolError("SOURCE_LAYOUT", "ACT_A.txt 有未证明的换行模式")
    lines = raw.decode("utf-8", "strict").split("\r\n")
    touched = set()
    for ident, e in analysis["bindings"].items():
        name = changes.get(e["name_id"], e["speaker"]) if e["name_id"] else ""
        body = changes.get(ident, e["text"])
        if (name, body) == (e["speaker"], e["text"]):
            continue
        row = parse_spt(data / e["scene"])[1][e["record"]]
        start, count = row[4], row[5]
        parts = body.split(r"\n")
        if len(parts) != count - (1 if name else 0):
            raise ToolError("SOURCE_LAYOUT", f"idx={ident:08d}: 原脚本行数不可改变")
        if set(range(start, start + count)) & touched:
            raise ToolError("SOURCE_LAYOUT", f"idx={ident:08d}: 源行跨度重叠")
        touched.update(range(start, start + count))
        if name:
            lead = lines[start]
            if not lead.startswith(e["speaker"] + "\u3000"):
                raise ToolError("SOURCE_ANCHOR", f"idx={ident:08d}: 人名前缀不匹配")
            lines[start] = name + lead[len(e["speaker"]):]
            lines[start + 1:start + count] = parts
        else:
            lead = lines[start]
            if not lead.endswith(f"[{ident}]"):
                raise ToolError("SOURCE_ANCHOR", f"idx={ident:08d}: 锚点不在行尾")
            lines[start:start + count] = [parts[0] + f"[{ident}]"] + parts[1:]
    return "\r\n".join(lines).encode("utf-8")


def _build_records(data, analysis, changes):
    old_ptr = (data / "ACT_A_JA.PTR").read_bytes()
    old_txd = (data / "ACT_A_JA.TXD").read_bytes()
    ptr = bytearray(old_ptr[:16])
    txd = bytearray()
    for ident in sorted(analysis["bindings"]):
        e = analysis["bindings"][ident]
        name = changes.get(e["name_id"], e["speaker"]) if e["name_id"] else ""
        body = changes.get(ident, e["text"])
        new = (name + "," + body).encode("utf-8", "strict")
        if name == e["speaker"] and body == e["text"]:
            new = old_txd[e["txd_offset"]:e["txd_offset"] + e["txd_size"]]
        if len(txd) + len(new) > 0xFFFFFFFF:
            raise ToolError("POINTER_OVERFLOW", f"idx={ident:08d}")
        ptr.extend(struct.pack("<III", ident, len(txd), len(new)))
        txd.extend(new)
    return bytes(ptr), bytes(txd)


def _verdicts(analysis, changes, new_txd):
    has_edit = bool(changes)
    same_size = not has_edit or all(
        len(((changes.get(e["name_id"], e["speaker"]) if e["name_id"] else "")
             + "," + changes.get(ident, e["text"])).encode("utf-8")) == e["txd_size"]
        for ident, e in analysis["bindings"].items())
    ids = [f"idx={idx:08d}" for idx in sorted(changes)[:16]]
    return [
        {"strategy_id": "identity", "applicable": not has_edit,
         "reason_code": "OK" if not has_edit else "EDIT_PRESENT",
         "blocking_refs": [] if not has_edit else ids},
        {"strategy_id": "in_place", "applicable": has_edit and same_size,
         "reason_code": "OK" if has_edit and same_size else
                        ("NO_CHANGE" if not has_edit else "CAPACITY_UNKNOWN"),
         "blocking_refs": [] if same_size else ids},
        {"strategy_id": "pointer-rewrite", "applicable": has_edit,
         "reason_code": "OK" if has_edit else "NO_CHANGE", "blocking_refs": [],
         "estimated_deltas": {"txd_bytes": len(new_txd) -
                              (analysis["data_dir"] / "ACT_A_JA.TXD").stat().st_size}},
        {"strategy_id": "full-layout", "applicable": False,
         "reason_code": "TIER_TOO_LOW",
         "blocking_refs": ["non-text SPT instruction semantics"]},
    ]


def _write_mapping_reports(stage, data, new_ptr, new_txd, new_source):
    reports = stage / "reports"
    reports.mkdir()
    old_ptr = (data / "ACT_A_JA.PTR").read_bytes()
    old_txd = (data / "ACT_A_JA.TXD").read_bytes()
    old_source = (data / "ACT_A.txt").read_bytes()
    original_sites, rebuilt_sites, relocations, txd_layout = [], [], [], []
    ptr_hash = digest(old_ptr)
    old_cursor = new_cursor = 0
    count = struct.unpack_from("<I", old_ptr, 4)[0]
    for i in range(count):
        ident, old_off, old_size = struct.unpack_from("<III", old_ptr, 16 + 12*i)
        new_ident, new_off, new_size = struct.unpack_from("<III", new_ptr, 16 + 12*i)
        if ident != new_ident or old_off != old_cursor or new_off != new_cursor:
            raise ToolError("VERIFY_FAILED", f"PTR ID/offset 错位：{i+1}")
        original = old_txd[old_off:old_off + old_size]
        rebuilt = new_txd[new_off:new_off + new_size]
        same = original == rebuilt
        txd_layout.append({
            "old_offset": old_off, "old_length": old_size,
            "new_offset": new_off, "new_length": new_size,
            "kind": "preserve" if same else "changed",
            **({} if same else {"reason": f"TXD entry ID {ident} text edit"}),
        })
        for suffix, field, before, after in (
                (4, "txd-offset", old_off, new_off),
                (8, "txd-size", old_size, new_size)):
            loc = 16 + 12*i + suffix
            original_sites.append({
                "site_offset": loc, "site_width": 4, "site_endianness": "little",
                "key_kind": field, "key_value": before, "new_key_value": after,
                "rewrite_policy": "rewrite", "source_artifact_hash": ptr_hash,
            })
            rebuilt_sites.append({
                "site_offset": loc, "site_width": 4, "site_endianness": "little",
                "key_kind": field, "key_value": after,
            })
            if before != after:
                relocations.append({"id": ident, "field": field, "offset": loc,
                                    "length": 4, "old_value": before, "new_value": after})
        old_cursor += old_size
        new_cursor += new_size
    if old_cursor != len(old_txd) or new_cursor != len(new_txd):
        raise ToolError("VERIFY_FAILED", "TXD 布局缺口")
    old_lines = old_source.splitlines(keepends=True)
    new_lines = new_source.splitlines(keepends=True)
    if len(old_lines) != len(new_lines):
        raise ToolError("SOURCE_LAYOUT", "源脚本行数被改变")
    source_layout = []
    old_cursor = new_cursor = 0
    for i, (before, after) in enumerate(zip(old_lines, new_lines), 1):
        same = before == after
        source_layout.append({
            "old_offset": old_cursor, "old_length": len(before),
            "new_offset": new_cursor, "new_length": len(after),
            "kind": "preserve" if same else "changed",
            **({} if same else {"reason": f"ACT_A.txt source line {i} text edit"}),
        })
        old_cursor += len(before)
        new_cursor += len(after)
    for name, records in (
            ("ptr_sites_original.jsonl", original_sites),
            ("ptr_sites_rebuilt.jsonl", rebuilt_sites),
            ("ptr_relocation_log.jsonl", relocations),
            ("txd_layout.jsonl", txd_layout),
            ("source_layout.jsonl", source_layout)):
        with (reports / name).open("w", encoding="utf-8", newline="\n") as file:
            for record in records:
                file.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    (reports / "empty_sites.jsonl").touch()
    return {"ptr_sites": len(original_sites), "ptr_rewrites": len(relocations),
            "txd_layout_records": len(txd_layout),
            "source_layout_lines": len(source_layout)}


def prepare(source, edits, *, target_encoding=None):
    edit_root = Path(edits).resolve()
    if edit_root.name in ("texts", "asm"):
        edit_root = edit_root.parent
    if not edit_root.is_dir() or not (edit_root / "manifest.json").is_file():
        raise ToolError("INPUT_MISSING", f"{edit_root}: 需要本工具生成的 manifest.json")
    try:
        manifest = json.loads((edit_root / "manifest.json").read_text("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise ToolError("TEXT_HEADER", f"manifest.json 无效：{exc}") from exc
    data, archive = input_paths(source or manifest["data"])
    if (manifest["dialect"] != DIALECT["engine_id"] or
            manifest["archive_sha256"] != digest(archive.read_bytes()) or
            manifest["source_encoding"] != "utf-8" or
            manifest["target_encoding"] != "utf-8" or
            (target_encoding and target_encoding != manifest["target_encoding"])):
        raise ToolError("SOURCE_MISMATCH", "归档、编码或方言与导出作业不一致")
    check = verify_archive(archive, data)
    if check["status"] != "pass":
        raise ToolError("SOURCE_MISMATCH", str(check["mismatches"]))
    analysis = examine(data)
    source_archive = Archive(archive)
    if b"".join(source_archive.identity_chunks()) != source_archive.data:
        raise ToolError("IDENTITY_FAILED", "归档索引零编辑重编码不一致")
    identity_ptr, identity_txd = _build_records(data, analysis, {})
    identity_source = _source_candidate(data, analysis, {})
    if (identity_ptr != (data / "ACT_A_JA.PTR").read_bytes() or
            identity_txd != (data / "ACT_A_JA.TXD").read_bytes() or
            identity_source != (data / "ACT_A.txt").read_bytes()):
        raise ToolError("IDENTITY_FAILED", "文本池零编辑重建不一致")
    if (manifest["source_hashes"] != analysis["source_hashes"] or
            manifest["scenes"] != analysis["source_identities"]):
        raise ToolError("SOURCE_MISMATCH", "源目录在导出后已改变")
    changes, conflicts, marker_repairs = _projection_changes(edit_root, analysis, manifest)
    if conflicts:
        return {"data": data, "archive": archive, "edits": edit_root,
                "analysis": analysis, "changes": changes, "conflicts": conflicts,
                "manifest": manifest, "selected_strategy": None, "verdicts": [],
                "marker_repairs": marker_repairs}
    new_ptr, new_txd = _build_records(data, analysis, changes)
    new_source = _source_candidate(data, analysis, changes)
    verdicts = _verdicts(analysis, changes, new_txd)
    selected = next(v["strategy_id"] for v in verdicts if v["applicable"])
    changed_names = [name for name, content in (
        ("ACT_A.txt", new_source), ("ACT_A_JA.PTR", new_ptr),
        ("ACT_A_JA.TXD", new_txd)) if content != (data / name).read_bytes()]
    return {"data": data, "archive": archive, "edits": edit_root,
            "analysis": analysis, "changes": changes, "conflicts": {},
            "manifest": manifest, "marker_repairs": marker_repairs,
            "selected_strategy": selected,
            "verdicts": verdicts, "new_ptr": new_ptr, "new_txd": new_txd,
            "new_source": new_source, "changed_files": changed_names,
            "txd_delta": len(new_txd) - (data / "ACT_A_JA.TXD").stat().st_size}


def execute(plan, output=None, *, overwrite=False, progress=None, cancelled=None,
            accept_marker_repairs=False):
    if plan["conflicts"]:
        raise ToolError("EDIT_CONFLICT", json.dumps(plan["conflicts"], ensure_ascii=False))
    if plan["marker_repairs"] and not accept_marker_repairs:
        raise ToolError("MARKER_REPAIR_CONFIRMATION",
                        "先预览全部标记调整，再在 GUI 确认，或使用 --accept-marker-repairs")
    data, archive = plan["data"], plan["archive"]
    dest = Path(output).resolve() if output else default_output(data, "_rebuilt")
    if dest == data or dest.is_relative_to(data) or dest == archive or dest == plan["edits"]:
        raise ToolError("OUTPUT_UNSAFE", str(dest))
    if dest.exists() and not overwrite:
        raise ToolError("OUTPUT_EXISTS", str(dest))
    if digest(archive.read_bytes()) != plan["manifest"]["archive_sha256"]:
        raise ToolError("SOURCE_MISMATCH", "预览后源归档已改变")
    if examine(data)["source_identities"] != plan["analysis"]["source_identities"]:
        raise ToolError("SOURCE_MISMATCH", "预览后源目录已改变")
    dest.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="._rebuilt-", dir=dest.parent))
    backup = None
    try:
        entries_dir = stage / "entries"
        entries_dir.mkdir()
        sources = sorted(p for p in data.iterdir() if p.is_file())
        total_bytes = sum(p.stat().st_size for p in sources)
        processed_bytes = 0
        for i, path in enumerate(sources, 1):
            if cancelled and cancelled.is_set():
                raise ToolError("CANCELLED", "已取消，未提交临时输出")
            target = entries_dir / path.name
            if path.name in plan["changed_files"]:
                content = {"ACT_A.txt": plan["new_source"],
                           "ACT_A_JA.PTR": plan["new_ptr"],
                           "ACT_A_JA.TXD": plan["new_txd"]}[path.name]
                with target.open("wb") as f:
                    f.write(content)
                    f.flush()
                    os.fsync(f.fileno())
            else:
                shutil.copyfile(path, target)
            if progress:
                processed_bytes += path.stat().st_size
                progress(processed_bytes, total_bytes, path.name)
        reread = examine(entries_dir)
        for ident, e in plan["analysis"]["bindings"].items():
            expected_name = plan["changes"].get(e["name_id"], e["speaker"]) if e["name_id"] else ""
            expected_body = plan["changes"].get(ident, e["text"])
            rebuilt = reread["bindings"][ident]
            if (rebuilt["speaker"], rebuilt["text"], rebuilt["scene"], rebuilt["record"]) != (
                    expected_name, expected_body, e["scene"], e["record"]):
                raise ToolError("VERIFY_FAILED", f"idx={ident:08d}: 回读对象内容或站点不符")
        if reread["shape"] != plan["analysis"]["shape"]:
            raise ToolError("VERIFY_FAILED", "SPT 结构变化")
        maps = _write_mapping_reports(stage, data, plan["new_ptr"],
                                      plan["new_txd"], plan["new_source"])
        archive_report = build_archive(archive, data, entries_dir, stage / "data.fpk")
        if sorted(archive_report["changed"]) != sorted(plan["changed_files"]):
            raise ToolError("VERIFY_FAILED", "归档变更范围不符")
        if not plan["changes"] and (archive.read_bytes() != (stage / "data.fpk").read_bytes()
                                    or any(plan["changed_files"])):
            raise ToolError("VERIFY_FAILED", "零编辑非逐字节一致")
        if plan["changes"] and archive_report["output_sha256"] == archive_report["source_sha256"]:
            raise ToolError("EDIT_LOST", "有编辑但归档哈希未改变")
        report = {
            "status": "pass", "selected_strategy": plan["selected_strategy"],
            "verdicts": plan["verdicts"], "edited_entries": len(plan["changes"]),
            "marker_repairs": plan["marker_repairs"],
            "changed_files": plan["changed_files"], "txd_delta": plan["txd_delta"],
            "source_archive_sha256": archive_report["source_sha256"],
            "output_archive_sha256": archive_report["output_sha256"],
            "identity": archive_report["byte_identical"],
            "verified_pool_entries": len(reread["bindings"]),
            "spt_sites_preserved": len(reread["bindings"]),
            "mapping_reports": maps,
            "byte_coverage": 1.0, "runtime_validation": "not_verified",
            "understanding": "T2 target text and references; non-text SPT instruction semantics not claimed",
        }
        (stage / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if cancelled and cancelled.is_set():
            raise ToolError("CANCELLED", "已取消，未提交临时输出")
        if dest.exists():
            backup = dest.with_name(dest.name + "_backup_" + str(time.time_ns()))
            os.replace(dest, backup)
        try:
            os.replace(stage, dest)
        except OSError:
            if backup is not None and not dest.exists():
                os.replace(backup, dest)
            raise
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return report, backup


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("edits", nargs="?", type=Path,
                   help="edited *_text directory, or its texts/ or asm/ folder")
    p.add_argument("--edits", dest="edits_option", type=Path)
    p.add_argument("--data", type=Path, help="source data folder; default from manifest")
    p.add_argument("-o", "--output", type=Path)
    p.add_argument("--target-encoding")
    p.add_argument("--preview", action="store_true")
    p.add_argument("--accept-marker-repairs", action="store_true",
                   help="after reviewing --preview, apply the listed marker fixes in memory")
    p.add_argument("--overwrite", action="store_true",
                   help="save old output to a timestamped sibling backup")
    args = p.parse_args(argv)
    try:
        edits = args.edits_option or args.edits
        if edits is None:
            p.error("provide edited directory")
        plan = prepare(args.data, edits, target_encoding=args.target_encoding)
        if plan["conflicts"]:
            raise ToolError("EDIT_CONFLICT", json.dumps(plan["conflicts"], ensure_ascii=False))
        if args.preview:
            report = {"status": "pass", "edited_entries": len(plan["changes"]),
                      "selected_strategy": plan["selected_strategy"],
                      "txd_delta": plan["txd_delta"], "verdicts": plan["verdicts"],
                      "marker_repairs": plan["marker_repairs"]}
        else:
            report, backup = execute(plan, args.output, overwrite=args.overwrite,
                                     accept_marker_repairs=args.accept_marker_repairs)
            if backup:
                report["previous_output_backup"] = str(backup)
    except ToolError as exc:
        print(f"{exc}", file=sys.stderr)
        return 1
    except (ValueError, OSError, UnicodeError, KeyError) as exc:
        print(f"FORMAT_ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
