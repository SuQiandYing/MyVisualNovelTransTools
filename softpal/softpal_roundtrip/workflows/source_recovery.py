from __future__ import annotations

import difflib
import re
import struct
from dataclasses import dataclass
from pathlib import Path

from ..binary.primitives import sha256_hex
from ..core.errors import MessageLayoutError
from ..core.message_layouts import MESSAGE_ARGUMENT_ROLES
from ..core.models import TextDatArchive, TextEntry
from ..core.profiles import AbstractGameProfile
from ..crypto.softpal import softpal_decrypt_bytes, softpal_encrypt_bytes
from ..engine.script_parser import ParsedScript
from ..engine.text_dat_parser import load_text_dat_bytes_auto
from ..engine.text_references import find_text_reference_sites, reference_map_by_entry
from .rebuild_workflow import (
    _validate_relocated_output,
    rebuild_script_with_reference_sites,
    rebuild_text_dat_with_relocations,
)


@dataclass(frozen=True, slots=True)
class RecoveredSource:
    script_data: bytes
    archive: TextDatArchive
    text_file_data: bytes
    report: dict


@dataclass(frozen=True, slots=True)
class DisplayToken:
    entry: TextEntry
    name_entry: TextEntry | None
    value: str


def read_pac_sources(path: Path) -> tuple[bytes, dict[str, bytes]]:
    """Read only the two source members of the verified 40-byte PAC table."""
    data = path.read_bytes()
    if len(data) < 0x804 or data[:8] != b"PAC \0\0\0\0":
        raise ValueError("原始 PAC 的头部或版本不受支持")
    count = struct.unpack_from("<I", data, 8)[0]
    table_end = 0x804 + count * 40
    if not count or table_end > len(data):
        raise ValueError("原始 PAC 的目录越界或为空")
    wanted = {"SCRIPT.SRC", "TEXT.DAT"}
    members = {}
    for i in range(count):
        start = 0x804 + i * 40
        raw_name = data[start:start + 32].split(b"\0", 1)[0]
        try:
            name = raw_name.decode("ascii").upper()
        except UnicodeDecodeError:
            continue
        if name not in wanted:
            continue
        size, offset = struct.unpack_from("<II", data, start + 32)
        if not size or offset < table_end or offset + size > len(data) or name in members:
            raise ValueError(f"原始 PAC 的 {name} 目录重复或数据越界")
        members[name] = data[offset:offset + size]
    if set(members) != wanted:
        raise ValueError("原始 PAC 缺少 SCRIPT.SRC 或 TEXT.DAT")
    return data, members


def _display_tokens(archive: TextDatArchive, script: ParsedScript, profile: AbstractGameProfile):
    text_map = {entry.entry_offset: entry for entry in archive.entries}
    events = profile.extract_message_events(script, text_map)
    bodies = {event.text_idx for event in events if event.call_id in MESSAGE_ARGUMENT_ROLES}
    pairs = {}
    for event in events:
        if event.call_id not in MESSAGE_ARGUMENT_ROLES or event.name_offset is None:
            continue
        body, name = text_map[event.text_offset], text_map[event.name_offset]
        visible = re.sub(r"<[^>]*>", "", body.original_text).strip()
        if name.order != body.order + 1 or not visible.startswith(("「", "『", "（")):
            continue
        previous = pairs.get(body.idx)
        if previous is not None and previous != name:
            raise ValueError(f"idx={body.idx} 的基准人名配对不唯一，无法恢复")
        pairs[body.idx] = name
    skipped = {name.idx for name in pairs.values()}
    if skipped & bodies:
        raise ValueError("基准中存在共享的人名／正文槽，无法恢复合并列表")
    tokens = []
    for entry in archive.entries:
        if entry.idx in skipped:
            continue
        name = pairs.get(entry.idx)
        value = entry.original_text if name is None else name.original_text + entry.original_text
        tokens.append(DisplayToken(entry, name, value))
    return tokens, bodies, len(skipped)


def _recover_edits(tokens: list[DisplayToken], supplied: TextDatArchive, original: TextDatArchive, bodies: set[int]) -> tuple[dict[int, str], int]:
    changed_orders = [i for i, (old, new) in enumerate(zip(original.entries, supplied.entries)) if old.raw_text != new.raw_text]
    if not changed_orders:
        raise ValueError("没有可恢复的合并列表")
    # A pasted display stream replaces a prefix; the untouched original tail
    # must match byte for byte. It is never used as a second copy of edits.
    pasted = supplied.entries[:changed_orders[-1] + 1]
    matcher = difflib.SequenceMatcher(
        None, [token.value.strip() for token in tokens],
        [entry.original_text.strip() for entry in pasted], autojunk=False,
    )
    opcodes = matcher.get_opcodes()
    edits = {}
    reversed_joins = 0

    def assign(token: DisplayToken, value: str, *, changed: bool) -> None:
        if token.name_entry is not None:
            name = token.name_entry.original_text
            if not value.startswith(name):
                raise ValueError(f"idx={token.entry.idx} 的合并人名无法唯一恢复；请保留原文件并重新提取")
            value = value[len(name):]
            visible = re.sub(r"<[^>]*>", "", value).strip()
            if not visible.startswith(("「", "『", "（")):
                raise ValueError(f"idx={token.entry.idx} 的合并正文边界不明确，无法恢复")
        elif changed and token.entry.idx not in bodies:
            raise ValueError(f"idx={token.entry.idx} 的非正文内容发生变化，无法安全对齐恢复")
        if value != token.entry.original_text:
            if token.entry.idx in edits and edits[token.entry.idx] != value:
                raise ValueError(f"idx={token.entry.idx} 的恢复译文冲突")
            edits[token.entry.idx] = value

    for ordinal, (operation, start, end, input_start, input_end) in enumerate(opcodes):
        if operation == "equal":
            for token, entry in zip(tokens[start:end], pasted[input_start:input_end]):
                assign(token, entry.original_text, changed=False)
            continue
        if operation != "replace":
            raise ValueError("合并列表缺行、增行或未完整覆盖基准，无法恢复对齐")
        previous_anchor = ordinal > 0 and opcodes[ordinal - 1][0] == "equal"
        next_anchor = ordinal + 1 < len(opcodes) and opcodes[ordinal + 1][0] == "equal"
        if not (previous_anchor and next_anchor):
            raise ValueError("改文两侧缺少基准锚点，无法唯一对齐恢复")
        if end - start == input_end - input_start:
            for token, entry in zip(tokens[start:end], pasted[input_start:input_end]):
                assign(token, entry.original_text, changed=True)
            continue
        # Some old display exporters joined a following narration label
        # before a quoted line. Only exact, unedited two-field joins qualify.
        if end - start == 2 and input_end - input_start == 1:
            left, right = tokens[start:end]
            actual = pasted[input_start].original_text
            if left.name_entry is None and right.name_entry is None and actual == right.value + left.value:
                reversed_joins += 1
                continue
        raise ValueError("合并列表存在无法证明的拼接或编辑，停止恢复并保留原文件")
    return edits, reversed_joins


def recover_pasted_source(
    script_path: Path,
    text_path: Path,
    script: ParsedScript,
    supplied: TextDatArchive,
    profile: AbstractGameProfile,
    *,
    text_codec: str,
    reference_pac: Path | None = None,
) -> RecoveredSource:
    if reference_pac is None:
        if script_path.parent.resolve() != text_path.parent.resolve():
            raise MessageLayoutError("人名与正文记录错位，需要显式指定同版本原始 PAC")
        reference_pac = script_path.parent.with_suffix(".pac")
    if not reference_pac.is_file():
        raise MessageLayoutError("人名与正文记录错位；未找到同名原始 PAC，请用 --reference-pac 指定同版本原包后重新反汇编")
    pac_data, members = read_pac_sources(reference_pac)
    baseline_script = ParsedScript.from_bytes(members["SCRIPT.SRC"], instruction_set=profile.get_instruction_set())
    original = load_text_dat_bytes_auto(members["TEXT.DAT"], profile, source_name="PAC/TEXT.DAT", text_codec=text_codec)
    if script.raw_data[:12] != baseline_script.raw_data[:12] or len(script.raw_data) != len(baseline_script.raw_data):
        raise ValueError("脚本与原始 PAC 的基准版本不一致，停止恢复")
    if supplied.header != original.header or supplied.trailer != original.trailer or [e.idx for e in supplied.entries] != [e.idx for e in original.entries]:
        raise ValueError("DAT 与原始 PAC 的记录身份不一致，停止恢复")
    if len({e.idx for e in original.entries}) != len(original.entries):
        raise ValueError("原始 PAC 中的 DAT 编号重复，停止恢复")
    baseline_sites = find_text_reference_sites(baseline_script, original.entries)
    supplied_sites = find_text_reference_sites(script, supplied.entries)
    binding = lambda sites: {(s.site_offset, s.call_offset, s.call_id, s.argument_depth): s.text_idx for s in sites}
    if binding(baseline_sites) != binding(supplied_sites):
        raise ValueError("脚本与原始 PAC 的文本引用身份不一致，停止恢复")
    supplied_offsets = {e.idx: e.entry_offset for e in supplied.entries}
    expected_script = bytearray(baseline_script.raw_data)
    for site in baseline_sites:
        struct.pack_into("<I", expected_script, site.site_offset, supplied_offsets[site.text_idx])
    if bytes(expected_script) != script.raw_data:
        raise ValueError("脚本包含文本重定位以外的基准差异，无法安全恢复")
    tokens, bodies, collapsed_names = _display_tokens(original, baseline_script, profile)
    edits, reversed_joins = _recover_edits(tokens, supplied, original, bodies)
    rows = [{
        "idx": entry.idx, "entry_offset": entry.entry_offset,
        "raw_text_hex": entry.raw_text.hex(), "original_text": entry.original_text,
        "text": edits.get(entry.idx, entry.original_text),
    } for entry in original.entries]
    manifest = {"text_header_hex": original.header.hex(), "text_trailer_hex": original.trailer.hex(), "text_codec": text_codec}
    text_data, relocations, changed = rebuild_text_dat_with_relocations(manifest, rows, edited_encoding=text_codec)
    refs = reference_map_by_entry(baseline_sites)
    candidate_values = set(baseline_script.words)
    unresolved = [e.idx for e in original.entries if relocations[e.entry_offset] != e.entry_offset and e.entry_offset in candidate_values and e.entry_offset not in refs]
    if unresolved:
        raise ValueError(f"恢复后的文本缺少已证明的引用：idx={unresolved[:20]}")
    script_data, _ = rebuild_script_with_reference_sites(baseline_script.raw_data, relocations, baseline_sites)
    _validate_relocated_output(manifest, rows, baseline_script.raw_data, original, script_data, text_data, baseline_sites, edited_encoding=text_codec)
    cipher = profile.get_text_cipher_config()
    text_file_data = softpal_encrypt_bytes(text_data, cipher) if supplied.was_encrypted else text_data
    if supplied.was_encrypted and softpal_decrypt_bytes(text_file_data, cipher) != text_data:
        raise ValueError("恢复后的 DAT 加密往返校验失败")
    archive = load_text_dat_bytes_auto(text_file_data, profile, source_name="recovered/TEXT.DAT", text_codec=text_codec)
    report = {
        "status": "pass", "strategy": "verified_display_stream_recovery",
        "baseline_pac_name": reference_pac.name, "baseline_pac_sha256": sha256_hex(pac_data),
        "input_script_sha256": sha256_hex(script.raw_data), "input_text_sha256": sha256_hex(text_path.read_bytes()),
        "input_plain_text_sha256": sha256_hex(supplied.normalized_data),
        "baseline_script_sha256": sha256_hex(baseline_script.raw_data),
        "baseline_plain_text_sha256": sha256_hex(original.normalized_data),
        "script_file": "source_recovered/SCRIPT.SRC", "text_file": "source_recovered/TEXT.DAT",
        "script_sha256": sha256_hex(script_data), "text_sha256": sha256_hex(text_file_data),
        "preserved_edit_rows": changed, "preserved_edit_idxs": sorted(edits),
        "collapsed_name_rows": collapsed_names, "reversed_joins": reversed_joins,
        "verified_reference_sites": len(baseline_sites), "runtime_validation": "not_verified",
    }
    return RecoveredSource(script_data, archive, text_file_data, report)
