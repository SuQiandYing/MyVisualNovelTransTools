from __future__ import annotations

import json
import os
import shutil
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..binary.primitives import encode_with_codec, sha256_hex
from ..core.models import TextDatArchive, TextEntry
from ..crypto.softpal import softpal_decrypt_bytes, softpal_encrypt_bytes
from ..engine.script_parser import ParsedScript
from ..engine.text_dat_parser import load_text_dat_auto, parse_text_dat_bytes
from ..engine.text_references import TextReferenceSite, find_text_reference_sites, reference_map_by_entry
from ..io.json_io import json_dump, load_jsonl
from ..profiles import load_profile


PAC_COMPATIBLE_ENCODINGS = {"932", "cp932", "ms932", "ms_kanji", "shift_jis", "shiftjis", "sjis"}


@dataclass(frozen=True, slots=True)
class RebuildStrategy:
    name: str
    probe: Callable[..., tuple[bool, str]]
    run: Callable[..., dict]


def rebuild_text_dat_from_rows(
    manifest: dict,
    text_rows: list[dict],
    *,
    inplace_mode: bool,
    strict_original: bool,
    edited_encoding: str = "cp932",
) -> bytes:
    parts = [bytes.fromhex(manifest["text_header_hex"])]
    for row in text_rows:
        idx = int(row["idx"])
        original_text = row["original_text"]
        current_text = row.get("text", original_text)
        original_raw = bytes.fromhex(row["raw_text_hex"])
        if strict_original and current_text != original_text:
            raise ValueError(f"idx={idx} 的 text 字段已被修改，rebuild-lossless 只允许从未改动的 dump 原样回编")
        if inplace_mode and current_text != original_text:
            encoded = encode_with_codec(current_text, edited_encoding)
            if len(encoded) != len(original_raw):
                raise ValueError(
                    f"idx={idx} 原文长度 {len(original_raw)}，新文长度 {len(encoded)}，原地回编要求字节长度完全一致"
                )
            raw_text = encoded
        elif current_text != original_text:
            raw_text = encode_with_codec(current_text, edited_encoding)
        else:
            raw_text = original_raw
        parts.extend([struct.pack("<I", idx), raw_text, b"\x00"])
    parts.append(bytes.fromhex(manifest["text_trailer_hex"]))
    return b"".join(parts)


def rebuild_text_dat_with_relocations(
    manifest: dict,
    text_rows: list[dict],
    *,
    edited_encoding: str,
) -> tuple[bytes, dict[int, int], int]:
    header = bytes.fromhex(manifest["text_header_hex"])
    trailer = bytes.fromhex(manifest["text_trailer_hex"])
    parts = [header]
    old_to_new: dict[int, int] = {}
    changed_rows = 0
    cursor = len(header)
    for row in text_rows:
        idx = int(row["idx"])
        old_offset = int(row["entry_offset"])
        old_to_new[old_offset] = cursor
        original_text = row["original_text"]
        current_text = row.get("text", original_text)
        original_raw = bytes.fromhex(row["raw_text_hex"])
        raw_text = encode_with_codec(current_text, edited_encoding) if current_text != original_text else original_raw
        if current_text != original_text:
            changed_rows += 1
        parts.extend([struct.pack("<I", idx), raw_text, b"\x00"])
        cursor += 4 + len(raw_text) + 1
    parts.append(trailer)
    return b"".join(parts), old_to_new, changed_rows


def rebuild_script_from_rows(script_rows: list[dict]) -> bytes:
    blob = bytearray()
    expected_offset = 0
    for row in script_rows:
        offset = int(row["offset"])
        value = int(row["u32"])
        if offset != expected_offset:
            raise ValueError(f"script_words.jsonl 偏移不连续：期望 0x{expected_offset:08X}，实际 0x{offset:08X}")
        blob.extend(struct.pack("<I", value))
        expected_offset += 4
    return bytes(blob)


def rebuild_script_from_rows_with_relocations(
    script_rows: list[dict],
    old_to_new: dict[int, int],
    *,
    reference_sites: tuple[TextReferenceSite, ...],
) -> tuple[bytes, int]:
    script_data = rebuild_script_from_rows(script_rows)
    rebuilt, log = rebuild_script_with_reference_sites(script_data, old_to_new, reference_sites)
    return rebuilt, len(log)


def rebuild_script_with_reference_sites(
    script_data: bytes,
    old_to_new: dict[int, int],
    reference_sites: tuple[TextReferenceSite, ...],
) -> tuple[bytes, list[dict[str, object]]]:
    output = bytearray(script_data)
    log = []
    for site in reference_sites:
        current = struct.unpack_from("<I", script_data, site.site_offset)[0]
        if current != site.entry_offset:
            raise ValueError(f"0x{site.site_offset:08X} 的源引用与已解析站点不一致")
        new_offset = old_to_new[site.entry_offset]
        if not 0 <= new_offset <= 0xFFFFFFFF:
            raise ValueError(f"idx={site.text_idx} 的文本地址超出 32 位范围")
        if new_offset == current:
            continue
        struct.pack_into("<I", output, site.site_offset, new_offset)
        log.append({"text_idx": site.text_idx, "site_offset": site.site_offset, "old_offset": current, "new_offset": new_offset})
    return bytes(output), log


def write_encrypted_variants(
    out_dir: Path,
    manifest: dict,
    script_data: bytes,
    text_data: bytes,
    *,
    replace_plain_outputs: bool = False,
) -> dict[str, str | bool]:
    encrypted_paths: dict[str, str | bool] = {}
    text_encrypted = softpal_encrypt_bytes(text_data)
    text_name = manifest["text_name"] if replace_plain_outputs else manifest["text_name"] + ".en"
    (out_dir / text_name).write_bytes(text_encrypted)
    encrypted_paths["text_encrypted"] = text_name
    script_encrypted = softpal_encrypt_bytes(script_data)
    script_name = manifest["script_name"] if replace_plain_outputs else manifest["script_name"] + ".en"
    (out_dir / script_name).write_bytes(script_encrypted)
    encrypted_paths["script_encrypted"] = script_name
    encrypted_paths["encrypted_replaces_plain"] = replace_plain_outputs
    return encrypted_paths


def rebuild_lossless_command(dump_dir: Path, out_dir: Path, *, encrypt_output: bool = False, replace_plain_with_encrypted: bool = False) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((dump_dir / "manifest.json").read_text(encoding="utf-8"))
    text_rows = load_jsonl(dump_dir / "text_entries.jsonl")
    script_rows = load_jsonl(dump_dir / "script_words.jsonl")
    text_data = rebuild_text_dat_from_rows(manifest, text_rows, inplace_mode=False, strict_original=True)
    script_data = rebuild_script_from_rows(script_rows)
    if not replace_plain_with_encrypted:
        (out_dir / manifest["text_name"]).write_bytes(text_data)
        (out_dir / manifest["script_name"]).write_bytes(script_data)
    report = {
        "script_sha256": sha256_hex(script_data),
        "text_sha256": sha256_hex(text_data),
        "script_matches_original": sha256_hex(script_data) == manifest["script_sha256"],
        "text_matches_original": sha256_hex(text_data) == manifest["text_sha256"],
    }
    if encrypt_output:
        report.update(write_encrypted_variants(out_dir, manifest, script_data, text_data, replace_plain_outputs=replace_plain_with_encrypted))
    json_dump(out_dir / "rebuild_report.json", report)
    return report


def rebuild_inplace_command(dump_dir: Path, out_dir: Path, *, edited_encoding: str = "cp932", encrypt_output: bool = False, replace_plain_with_encrypted: bool = False) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((dump_dir / "manifest.json").read_text(encoding="utf-8"))
    text_rows = load_jsonl(dump_dir / "text_entries.jsonl")
    script_rows = load_jsonl(dump_dir / "script_words.jsonl")
    text_data = rebuild_text_dat_from_rows(manifest, text_rows, inplace_mode=True, strict_original=False, edited_encoding=edited_encoding)
    script_data = rebuild_script_from_rows(script_rows)
    if not replace_plain_with_encrypted:
        (out_dir / manifest["text_name"]).write_bytes(text_data)
        (out_dir / manifest["script_name"]).write_bytes(script_data)
    report = {
        "script_sha256": sha256_hex(script_data),
        "text_sha256": sha256_hex(text_data),
        "script_matches_original": sha256_hex(script_data) == manifest["script_sha256"],
        "text_matches_original": sha256_hex(text_data) == manifest["text_sha256"],
        "edited_encoding": edited_encoding,
        "note": "如果你改了 text_entries.jsonl 里的 text 字段，TEXT.DAT 的哈希理应变化；完全不改时应与原文件完全一致。",
    }
    if encrypt_output:
        report.update(write_encrypted_variants(out_dir, manifest, script_data, text_data, replace_plain_outputs=replace_plain_with_encrypted))
    json_dump(out_dir / "rebuild_report.json", report)
    return report


def rebuild_relocate_command(dump_dir: Path, out_dir: Path, *, edited_encoding: str, encrypt_output: bool = False, replace_plain_with_encrypted: bool = False, audit_log: bool = False) -> dict:
    return _rebuild_verified_references(
        dump_dir, out_dir, edited_encoding=edited_encoding,
        encrypt_output=encrypt_output,
        replace_plain_with_encrypted=replace_plain_with_encrypted,
        audit_log=audit_log,
    )


def _load_relocation_source(
    dump_dir: Path,
    *,
    script_path: Path | None = None,
    text_path: Path | None = None,
) -> tuple[dict, list[dict], bytes, TextDatArchive]:
    manifest = json.loads((dump_dir / "manifest.json").read_text(encoding="utf-8"))
    rows = load_jsonl(dump_dir / "text_entries.jsonl")
    profile = load_profile(manifest.get("profile", "classic-softpal"))
    if profile.name != "classic-softpal":
        raise ValueError(f"尚未定义 {profile.name} 的安全文本重定位参数布局")
    codec = manifest.get("text_codec", "cp932")
    if script_path is not None:
        script_data = script_path.read_bytes()
    else:
        script_data = rebuild_script_from_rows(load_jsonl(dump_dir / "script_words.jsonl"))
    if text_path is not None:
        archive = load_text_dat_auto(text_path, profile, text_codec=codec)
    else:
        original_rows = [{**row, "text": row["original_text"]} for row in rows]
        original_text_data = rebuild_text_dat_from_rows(manifest, original_rows, inplace_mode=False, strict_original=True)
        header, entries, trailer = parse_text_dat_bytes(original_text_data, "dump original", text_codec=codec)
        archive = TextDatArchive(header, entries, trailer, original_text_data, False, "dump")
    if sha256_hex(script_data) != manifest["script_sha256"]:
        raise ValueError("SCRIPT.SRC 与 dump 的源哈希不一致，请使用对应的原始脚本重新反汇编")
    if sha256_hex(archive.normalized_data) != manifest["text_sha256"]:
        raise ValueError("TEXT.DAT 与 dump 的源哈希不一致，请使用对应的原始文本重新反汇编")
    if len(rows) != len(archive.entries):
        raise ValueError("text_entries.jsonl 的条目数与原始 TEXT.DAT 不一致")
    if archive.header.hex() != manifest["text_header_hex"] or archive.trailer.hex() != manifest["text_trailer_hex"]:
        raise ValueError("dump 的文本头部或尾部与源文件不一致")
    for row, entry in zip(rows, archive.entries):
        if (
            int(row["idx"]) != entry.idx
            or int(row["entry_offset"]) != entry.entry_offset
            or bytes.fromhex(row["raw_text_hex"]) != entry.raw_text
            or row["original_text"] != entry.original_text
        ):
            raise ValueError(f"idx={entry.idx} 的编号、原文或源偏移已改变；回封只允许修改 text 字段")
    return manifest, rows, script_data, archive


def _validate_relocated_output(
    manifest: dict,
    rows: list[dict],
    source_script: bytes,
    archive: TextDatArchive,
    script_data: bytes,
    text_data: bytes,
    sites: tuple[TextReferenceSite, ...],
    *,
    edited_encoding: str,
) -> None:
    header, entries, trailer = parse_text_dat_bytes(text_data, "rebuilt TEXT.DAT", text_codec=manifest.get("text_codec", "cp932"))
    if header != archive.header or trailer != archive.trailer or len(entries) != len(archive.entries):
        raise ValueError("回封后文本的头部、尾部或条目数不一致")
    for row, entry in zip(rows, entries):
        current = row.get("text", row["original_text"])
        expected = bytes.fromhex(row["raw_text_hex"]) if current == row["original_text"] else encode_with_codec(current, edited_encoding)
        if entry.idx != int(row["idx"]) or entry.raw_text != expected:
            raise ValueError(f"回封后 idx={row['idx']} 的文字与译文不一致")
    before = {site.site_offset: site.text_idx for site in sites}
    after = {site.site_offset: site.text_idx for site in find_text_reference_sites(ParsedScript.from_bytes(script_data), entries)}
    if before != after:
        raise ValueError("回封后的文本引用关系不一致，请检查格式占位符或调用参数")
    allowed = bytearray(source_script)
    offsets = {entry.idx: entry.entry_offset for entry in entries}
    for site in sites:
        struct.pack_into("<I", allowed, site.site_offset, offsets[site.text_idx])
    if bytes(allowed) != script_data:
        raise ValueError("回封脚本出现了文本引用之外的字节改动")


def _commit_outputs(out_dir: Path, payloads: dict[str, bytes], *, remove_names: tuple[str, ...] = ()) -> None:
    if set(payloads).intersection(remove_names):
        raise ValueError("同一输出文件不能同时写入和删除")
    output_root = out_dir.resolve()
    names = tuple(dict.fromkeys((*payloads, *remove_names)))
    for name in names:
        if Path(name).name != name:
            raise ValueError(f"输出文件名必须是单个文件名：{name!r}")
        target = out_dir / name
        if not target.resolve().is_relative_to(output_root):
            raise ValueError(f"输出文件不在输出目录内：{name!r}")
        if target.exists() and not target.is_file():
            raise ValueError(f"输出目标必须是文件：{name!r}")
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".rebuild-", dir=out_dir) as temporary:
        staging = Path(temporary).resolve()
        if not staging.is_relative_to(out_dir.resolve()):
            raise ValueError("临时目录不在输出目录内")
        backups: dict[str, Path | None] = {}
        for name in names:
            if name in payloads:
                data = payloads[name]
                target = staging / name
                with target.open("wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                if target.read_bytes() != data:
                    raise ValueError(f"临时输出 {name} 的回读验证失败")
            existing = out_dir / name
            backup = staging / (name + ".previous") if existing.exists() else None
            if backup is not None:
                shutil.copy2(existing, backup)
            backups[name] = backup
        committed = []
        try:
            for name in payloads:
                os.replace(staging / name, out_dir / name)
                committed.append(name)
            for name in remove_names:
                if backups[name] is not None:
                    (out_dir / name).unlink()
                    committed.append(name)
        except Exception:
            for name in reversed(committed):
                backup = backups[name]
                if backup is None:
                    (out_dir / name).unlink()
                else:
                    os.replace(backup, out_dir / name)
            raise


def _rebuild_verified_references(
    dump_dir: Path,
    out_dir: Path,
    *,
    edited_encoding: str,
    encrypt_output: bool,
    replace_plain_with_encrypted: bool,
    script_path: Path | None = None,
    text_path: Path | None = None,
    start_idx: int = 0,
    script_scan_start: int | None = None,
    audit_log: bool = False,
) -> dict:
    manifest, rows, source_script, archive = _load_relocation_source(dump_dir, script_path=script_path, text_path=text_path)
    for source in (script_path, text_path):
        if source is not None and (out_dir / source.name).resolve() == source.resolve():
            raise ValueError("回封输出不能覆盖原始 SCRIPT.SRC/TEXT.DAT，请选择独立输出目录")
    if out_dir.resolve() == dump_dir.parent.resolve():
        raise ValueError("请将回封文件写入独立输出目录，保留源文件")
    text_data, old_to_new, changed_rows = rebuild_text_dat_with_relocations(manifest, rows, edited_encoding=edited_encoding)
    for row in rows:
        current = row.get("text", row["original_text"])
        if current != row["original_text"] and b"\x00" in encode_with_codec(current, edited_encoding):
            raise ValueError(f"idx={row['idx']} 的译文包含 NUL，不能写入此文本格式")
    script = ParsedScript.from_bytes(source_script)
    sites = find_text_reference_sites(script, archive.entries)
    refs = reference_map_by_entry(sites)
    # A moved entry with unexplained value matches needs an ABI definition,
    # rather than an arbitrary first match or a global integer replacement.
    candidate_values = set(script.words)
    unresolved = [entry.idx for entry in archive.entries if old_to_new[entry.entry_offset] != entry.entry_offset and entry.entry_offset in candidate_values and entry.entry_offset not in refs]
    if unresolved:
        raise ValueError(f"以下文本缺少已证明的引用参数布局，无法安全变长回封：idx={unresolved[:20]}")
    script_data, relocation_log = rebuild_script_with_reference_sites(source_script, old_to_new, sites)
    _validate_relocated_output(manifest, rows, source_script, archive, script_data, text_data, sites, edited_encoding=edited_encoding)
    encrypted_script = softpal_encrypt_bytes(script_data)
    encrypted_text = softpal_encrypt_bytes(text_data)
    if softpal_decrypt_bytes(encrypted_script) != script_data or softpal_decrypt_bytes(encrypted_text) != text_data:
        raise ValueError("输出文件的加密/解密往返验证失败")
    delivered_script = encrypted_script if encrypt_output and replace_plain_with_encrypted else script_data
    delivered_text = encrypted_text if encrypt_output and replace_plain_with_encrypted else text_data
    payloads = {manifest["script_name"]: delivered_script, manifest["text_name"]: delivered_text}
    report = {
        "backend": "verified_reference_rebuild",
        "edited_encoding": edited_encoding,
        "changed_rows": changed_rows,
        "relocated_offsets": sum(old != new for old, new in old_to_new.items()),
        "verified_reference_sites": len(sites),
        "referenced_text_entries": len(refs),
        "rewritten_script_words": len(relocation_log),
        "preserved_value_collisions": sum(word in old_to_new for word in script.words) - len(sites),
        "reference_scope": "entire_script",
        "legacy_anchor_idx": start_idx,
        "legacy_script_scan_start": script_scan_start,
        "script_sha256": sha256_hex(delivered_script),
        "text_sha256": sha256_hex(delivered_text),
        "plain_script_sha256": sha256_hex(script_data),
        "plain_text_sha256": sha256_hex(text_data),
        "script_matches_original": source_script == script_data,
        "text_matches_original": archive.normalized_data == text_data,
        "validation": "pass",
        "runtime_validation": "not_verified",
        "audit_log": audit_log,
        "note": "更新全脚本内已证明的文本引用；定位锚点不限制回封范围。",
    }
    if encrypt_output:
        script_name = manifest["script_name"] if replace_plain_with_encrypted else manifest["script_name"] + ".en"
        text_name = manifest["text_name"] if replace_plain_with_encrypted else manifest["text_name"] + ".en"
        payloads[script_name] = encrypted_script
        payloads[text_name] = encrypted_text
        report.update({"script_encrypted_path": script_name, "text_encrypted_path": text_name, "encrypted_replaces_plain": replace_plain_with_encrypted})
    audit_names = ("reference_sites.jsonl", "relocation_log.jsonl")
    if audit_log:
        payloads[audit_names[0]] = "".join(json.dumps(site.to_row(), ensure_ascii=False, separators=(",", ":")) + "\n" for site in sites).encode("utf-8")
        payloads[audit_names[1]] = "".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n" for row in relocation_log).encode("utf-8")
    payloads["rebuild_report.json"] = json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8")
    _commit_outputs(out_dir, payloads, remove_names=() if audit_log else audit_names)
    return report


def normalize_codec_name(codec: str) -> str:
    return codec.strip().lower().replace("-", "_")


def is_pointer_table_compatible_codec(codec: str) -> bool:
    return normalize_codec_name(codec) in PAC_COMPATIBLE_ENCODINGS


def find_pointer_table_start(text_data: bytes, script_data: bytes, start_idx: int = 0) -> tuple[int, int]:
    # Compatibility API: the count is a parsed header field, and this is a
    # reference site for display. Sv20 has no monotonic text pointer table.
    _, script_hit_pos = auto_find_anchor_idx(text_data, script_data, start_idx=start_idx)
    return 0x0C, script_hit_pos


def auto_find_anchor_idx(text_data: bytes, script_data: bytes, start_idx: int = 0, limit: int = 10000) -> tuple[int, int]:
    """Choose an entry with one proven reference; this never bounds rebuilds."""
    _, entries, _ = parse_text_dat_bytes(text_data, "anchor TEXT.DAT")
    refs = reference_map_by_entry(find_text_reference_sites(ParsedScript.from_bytes(script_data), entries))
    for entry in sorted(entries, key=lambda entry: entry.idx):
        if start_idx <= entry.idx < start_idx + limit:
            sites = refs.get(entry.entry_offset, [])
            if len(sites) == 1:
                return entry.idx, sites[0]
    raise ValueError(f"无法定位具有唯一已证明引用的文本锚点（索引范围 {start_idx}..{start_idx + limit - 1}）。")


def build_pointer_table_map(script_data: bytes, entries: list[TextEntry], *, start_idx: int = 0, script_scan_start: int = 0) -> dict[int, list[int]]:
    """Compatibility name for all verified sites, independent of old anchors."""
    del start_idx, script_scan_start
    mapping: dict[int, list[int]] = {}
    for site in find_text_reference_sites(ParsedScript.from_bytes(script_data), entries):
        mapping.setdefault(site.text_idx, []).append(site.site_offset)
    return mapping


def rebuild_with_pointer_table_command(
    dump_dir: Path,
    script_path: Path,
    text_path: Path,
    out_dir: Path,
    *,
    edited_encoding: str,
    encrypt_output: bool = False,
    replace_plain_with_encrypted: bool = False,
    start_idx: int = 0,
    script_scan_start: int | None = None,
    audit_log: bool = False,
) -> dict:
    if not is_pointer_table_compatible_codec(edited_encoding):
        raise ValueError("pointer-table backend 仅支持 cp932/932/Shift-JIS 系编码")
    return _rebuild_verified_references(
        dump_dir, out_dir, script_path=script_path, text_path=text_path,
        edited_encoding=edited_encoding, encrypt_output=encrypt_output,
        replace_plain_with_encrypted=replace_plain_with_encrypted,
        start_idx=start_idx, script_scan_start=script_scan_start,
        audit_log=audit_log,
    )


def _probe_inplace(
    dump_dir: Path,
    *,
    edited_encoding: str,
    **_: object,
) -> tuple[bool, str]:
    manifest = json.loads((dump_dir / "manifest.json").read_text(encoding="utf-8"))
    text_rows = load_jsonl(dump_dir / "text_entries.jsonl")
    changed_rows = 0
    for row in text_rows:
        original_text = row["original_text"]
        current_text = row.get("text", original_text)
        if current_text == original_text:
            continue
        changed_rows += 1
        original_raw = bytes.fromhex(row["raw_text_hex"])
        encoded = encode_with_codec(current_text, edited_encoding)
        if len(encoded) != len(original_raw):
            return False, f"inplace length mismatch at idx={row['idx']}"
    if changed_rows == 0:
        return True, "no edited rows; inplace is safe"
    return True, f"{changed_rows} changed rows with matching byte lengths"


def _probe_relocate(
    dump_dir: Path,
    *,
    edited_encoding: str,
    script_path: Path | None = None,
    text_path: Path | None = None,
    **_: object,
) -> tuple[bool, str]:
    try:
        manifest, rows, source_script, archive = _load_relocation_source(dump_dir, script_path=script_path, text_path=text_path)
        text_data, old_to_new, _changed = rebuild_text_dat_with_relocations(manifest, rows, edited_encoding=edited_encoding)
        script = ParsedScript.from_bytes(source_script)
        sites = find_text_reference_sites(script, archive.entries)
        refs = reference_map_by_entry(sites)
        candidate_values = set(script.words)
        unresolved = [entry.idx for entry in archive.entries if old_to_new[entry.entry_offset] != entry.entry_offset and entry.entry_offset in candidate_values and entry.entry_offset not in refs]
        if unresolved:
            return False, f"unresolved text references: idx={unresolved[:20]}"
        script_data, _log = rebuild_script_with_reference_sites(source_script, old_to_new, sites)
        _validate_relocated_output(manifest, rows, source_script, archive, script_data, text_data, sites, edited_encoding=edited_encoding)
    except Exception as exc:
        return False, str(exc)
    return True, f"{len(sites)} text reference sites verified across the entire script"


def _probe_pointer_table(
    dump_dir: Path,
    *,
    edited_encoding: str,
    script_path: Path,
    text_path: Path,
    **_: object,
) -> tuple[bool, str]:
    if not is_pointer_table_compatible_codec(edited_encoding):
        return False, "pointer-table backend only supports Shift-JIS compatible encodings"
    return _probe_relocate(dump_dir, edited_encoding=edited_encoding, script_path=script_path, text_path=text_path)


def get_rebuild_strategies() -> list[RebuildStrategy]:
    return [
        RebuildStrategy(
            name="inplace",
            probe=_probe_inplace,
            run=lambda **kwargs: rebuild_inplace_command(**kwargs),
        ),
        RebuildStrategy(
            name="relocate",
            probe=_probe_relocate,
            run=lambda **kwargs: rebuild_relocate_command(**kwargs),
        ),
        RebuildStrategy(
            name="pointer-table",
            probe=_probe_pointer_table,
            run=lambda **kwargs: rebuild_with_pointer_table_command(**kwargs),
        ),
    ]


def rebuild_auto_command(
    dump_dir: Path,
    out_dir: Path,
    *,
    script_path: Path,
    text_path: Path,
    edited_encoding: str,
    encrypt_output: bool = False,
    replace_plain_with_encrypted: bool = False,
    audit_log: bool = False,
) -> dict:
    attempts: list[dict[str, object]] = []
    strategies = get_rebuild_strategies()
    for strategy in strategies:
        probe_ok, reason = strategy.probe(
            dump_dir,
            edited_encoding=edited_encoding,
            script_path=script_path,
            text_path=text_path,
            encrypt_output=encrypt_output,
            replace_plain_with_encrypted=replace_plain_with_encrypted,
        )
        attempts.append({"strategy": strategy.name, "probe_ok": probe_ok, "reason": reason})
    selected = next((strategy for strategy, attempt in zip(strategies, attempts) if attempt["probe_ok"]), None)
    if selected is None:
        raise ValueError(f"auto rebuild could not find a usable strategy: {attempts}")
    run_arguments = dict(
        dump_dir=dump_dir, out_dir=out_dir, edited_encoding=edited_encoding,
        encrypt_output=encrypt_output,
        replace_plain_with_encrypted=replace_plain_with_encrypted,
    )
    if selected.name == "pointer-table":
        run_arguments.update(script_path=script_path, text_path=text_path)
    if selected.name in {"relocate", "pointer-table"}:
        run_arguments["audit_log"] = audit_log
    # A failed run is a real failure, not permission to try a weaker backend.
    result = selected.run(**run_arguments)
    result["selected_strategy"] = selected.name
    result["auto_attempts"] = attempts
    _commit_outputs(out_dir, {"rebuild_report.json": json.dumps(result, ensure_ascii=False, indent=2).encode("utf-8")})
    return result
