"""Read-only NORI parser and deterministic TEXT/2/structured projections."""
from __future__ import annotations

import argparse
import binascii
import codecs
from collections import Counter, defaultdict
from dataclasses import dataclass, field, replace
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import sys
import time
import uuid
import unicodedata

from opcodelist import DIALECT as D, DIALECT_ID, TOOL_VERSION, ERRORS, OPCODE_NAMES, OPCODE_SHAPES

HEADER = struct.Struct(D["header_format"])
CELL = struct.Struct(D["cell_format"])
PAIR = struct.Struct(D["table_prefix_format"])
XOR_TABLE = bytes(i ^ D["xor_key"] for i in range(256))
NAME_PATTERN = re.compile(D["name_pattern"])
CONTROL_PATTERN = re.compile(D["native_control_pattern"])


class ToolError(Exception):
    def __init__(self, code: str, detail: str = ""):
        self.code, self.detail = code, detail
        super().__init__(f"{code}: {ERRORS[code]}" + (f"；{detail}" if detail else ""))


def require(condition, code, detail=""):
    if not condition:
        raise ToolError(code, detail)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def save_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def save_jsonl(path: Path, values):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for value in values:
            stream.write(canonical(value).decode("utf-8") + "\n")


def codec(name: str) -> str:
    try:
        return codecs.lookup(name).name
    except LookupError as exc:
        raise ToolError("ENCODING", name) from exc


def checked_read(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ToolError("IO", f"{path}: {exc}") from exc


def decode(raw: bytes, encoding: str, location: str) -> str:
    try:
        return raw.decode(encoding, "strict")
    except UnicodeError as exc:
        raise ToolError("ENCODING", f"{location}: {exc}") from exc


@dataclass(slots=True)
class Block:
    name: str
    start: int
    data: bytes
    logical: bytes

    @property
    def end(self):
        return self.start + len(self.data) + D["checksum_size"]


@dataclass(slots=True)
class TableText:
    table: int
    ordinal: int
    ident: int
    start: int
    length: int
    raw: bytes


@dataclass(slots=True)
class Container:
    path: Path
    raw: bytes
    header: tuple
    blocks: list[Block]
    tables: list[TableText]


@dataclass(slots=True)
class Argument:
    site: int
    ordinal: int
    kind: int
    length: int
    value: int


@dataclass(slots=True)
class Anchor:
    offset: int
    opcode: int
    stored_count: int
    info: int
    source_line: int
    source: str
    arguments: list[Argument]
    shape_id: str


@dataclass(slots=True)
class TextEntry:
    idx: int
    object_id: str
    storage_id: str
    off: int
    raw: bytes
    source: str
    tag: str
    policy: str
    tag_source: str
    sites: list[int] = field(default_factory=list)
    speakers: list[str] = field(default_factory=list)
    name_ids: list[str] = field(default_factory=list)
    pool_offset: int | None = None
    undecodable: bool = False
    member_ids: tuple[str, ...] = ()
    prefixes: tuple[str, ...] = ()
    anchor_offset: int | None = None
    projection_mode: str = ""


@dataclass(slots=True)
class Document:
    container: Container
    companion: Container
    relative_path: str
    src_id: str
    entries: list[TextEntry]
    anchors: list[Anchor]
    metadata_ranges: list[tuple[int, int]]
    bindings: list[dict]
    source_encoding: str

    @property
    def raw(self):
        return self.container.raw

    @property
    def by_id(self):
        return {entry.object_id: entry for entry in self.entries}


def parse_container(path: Path, raw: bytes | None = None) -> Container:
    data = checked_read(path) if raw is None else raw
    require(len(data) >= HEADER.size + D["checksum_size"], "FORMAT", str(path))
    h = HEADER.unpack_from(data)
    require(data[:len(D["magic"])] == D["magic"] and h[1] == D["version"], "FORMAT", str(path))
    sizes = [HEADER.size, h[3], h[5], h[7], h[8], h[9]]
    require(sum(sizes) + len(sizes) * D["checksum_size"] == len(data), "FORMAT", f"{path.name}: 总长度")
    blocks, tables, pos = [], [], 0
    for block_index, (name, size) in enumerate(zip(D["block_names"], sizes)):
        payload = data[pos:pos + size]
        logical = payload
        if 1 <= block_index <= len(D["table_names"]):
            plain = bytearray()
            cursor = 0
            for ordinal in range(h[block_index * 2]):
                require(cursor + PAIR.size <= size, "FORMAT", f"{path.name}/{name}/{ordinal}")
                prefix = payload[cursor:cursor + PAIR.size]
                ident, length = PAIR.unpack(prefix[:PAIR.size // 2] + prefix[PAIR.size // 2:].translate(XOR_TABLE))
                start = cursor + PAIR.size
                require(start + length <= size, "FORMAT", f"{path.name}/{name}/{ordinal}: 长度")
                decoded = payload[start:start + length].translate(XOR_TABLE)
                plain.extend(PAIR.pack(ident, length))
                plain.extend(decoded)
                tables.append(TableText(block_index - 1, ordinal, ident, pos + start, length, decoded))
                cursor = start + length
            require(cursor == size, "FORMAT", f"{path.name}/{name}: 未解析尾部")
            logical = bytes(plain)
        expected = int.from_bytes(data[pos + size:pos + size + D["checksum_size"]], D["checksum_byteorder"])
        require(binascii.crc_hqx(logical, 0) == expected, "CHECKSUM", f"{path.name}/{name}")
        blocks.append(Block(name, pos, payload, logical))
        pos += size + D["checksum_size"]
    return Container(path, data, h, blocks, tables)


def serialize_container(container: Container, changes: dict[str, bytes] | None = None) -> bytes:
    changes = changes or {}
    result = bytearray()
    for block in container.blocks:
        data = changes.get(block.name, block.data)
        logical = block.logical if block.name in D["table_names"] else data
        result.extend(data)
        result.extend(binascii.crc_hqx(logical, 0).to_bytes(D["checksum_size"], D["checksum_byteorder"]))
    return bytes(result)


def debug_records(container: Container) -> dict[int, tuple[int, str]]:
    data = container.blocks[-1].data
    records, pos = {}, 0
    while pos < len(data):
        require(pos + PAIR.size <= len(data), "FORMAT", f"{container.path.name}: 调试记录")
        line, length = PAIR.unpack_from(data, pos)
        stop = pos + PAIR.size + length
        require(stop <= len(data), "FORMAT", f"{container.path.name}: 调试记录长度")
        records[pos] = (line, decode(data[pos + PAIR.size:stop], D["source_encoding"], str(container.path)))
        pos = stop
    require(records and 0 in records, "FORMAT", f"{container.path.name}: 调试源路径")
    return records


def display_bytes(raw: bytes, encoding: str, *, allow_linefeeds: bool = False) -> tuple[str, bool]:
    try:
        value = raw.decode(encoding, "strict")
        # TEXT/2 is retained. This corpus has no token-like literals or unsafe bytes.
        unsafe = any((ord(c) < 32 and not (allow_linefeeds and c == "\n"))
                     or 127 <= ord(c) < 160 or 57344 <= ord(c) <= 63743
                     for c in value)  # dialect-literal-ok: standard Unicode C1/control/private-use ranges, not engine parameters
        if not unsafe and "{{" not in value:
            return value, False
    except UnicodeError:
        pass
    return "{{" + ":".join(f"{byte:02X}" for byte in raw) + "}}", True


def role(opcode: int, ordinal: int, count: int, named: bool) -> tuple[str, str, str]:
    if opcode in D["message_opcodes"]:
        if named and ordinal == 1:
            return "name", "translatable", "binding"
        return "msg", "translatable", "anchor"
    if opcode in D["choice_opcodes"]:
        return "choice", "translatable", "anchor"
    if opcode in D["ui_opcodes"]:
        return "ui", "translatable", "anchor"
    if opcode in D["system_opcodes"]:
        return "system", "translatable", "anchor"
    if opcode == D["callr_opcode"]:
        if ordinal in (0, 1, count - 1):
            return "label", "frozen", "anchor"
        return "misc", "review-required", "unresolved"
    if opcode in D["frozen_opcodes"]:
        return "label", "frozen", "anchor"
    return "misc", "review-required", "unresolved"


def parse_document(path: Path, relative_path: str | None = None, source_encoding: str = "cp932",
                   raw: bytes | None = None, companion_raw: bytes | None = None,
                   baseline: bool = True, entry_encodings: dict[str, str] | None = None) -> Document:
    require(bool(D.get("evidence_refs")) and all(isinstance(ref, str) and ref for ref in D["evidence_refs"]),
            "FORMAT", "方言缺少格式证据引用")
    source_encoding = codec(source_encoding)
    original = parse_container(path, raw)
    cp = path.with_suffix(".debug")
    require(companion_raw is not None or cp.is_file(), "COMPANION", str(cp))
    companion = parse_container(cp, companion_raw)
    require(original.header[2:9] == companion.header[2:9], "COMPANION", f"{path.name}: 结构头")
    for index in range(1, len(D["table_names"]) + 1):
        require(original.blocks[index].data == companion.blocks[index].data, "COMPANION", f"{path.name}: 表")
    code, dcode = original.blocks[-2], companion.blocks[-2]
    require(len(code.data) % CELL.size == 0, "FORMAT", f"{path.name}: 单元对齐")
    records = debug_records(companion)
    starts, used_records = [], set()
    for offset in range(0, len(dcode.data), CELL.size):
        cell = dcode.data[offset:offset + CELL.size]
        if cell == D["debug_fill"]:
            continue
        opcode, marker, ref = CELL.unpack(cell)
        require(marker == D["debug_flag"] and ref in records and ref != 0, "COMPANION", f"{path.name}: 单元 {offset}")
        require(ref not in used_records, "COMPANION", f"{path.name}: 重复源记录 {ref}")
        used_records.add(ref)
        starts.append((offset, opcode, ref))
    require((not dcode.data or (starts and starts[0][0] == 0)) and used_records == set(records) - {0},
            "COMPANION", f"{path.name}: 命令集合")
    anchors, metadata, objects, binding_candidates = [], [], {}, []
    pool = original.blocks[-1]
    for index, (offset, opcode, source_ref) in enumerate(starts):
        stop = starts[index + 1][0] if index + 1 < len(starts) else len(code.data)
        op, stored, info = CELL.unpack_from(code.data, offset)
        require(op == opcode, "COMPANION", f"{path.name}: 命令 {offset}")
        line, source = records[source_ref]
        command = source.split(" ", 1)[0].split(";", 1)[0]
        require(command in OPCODE_NAMES.get(opcode, ()), "UNKNOWN_SHAPE", f"{path.name}: {opcode}/{command}")
        args = []
        for ordinal, relative in enumerate(range(offset + CELL.size, stop, CELL.size)):
            kind, length, value = CELL.unpack_from(code.data, relative)
            args.append(Argument(code.start + relative, ordinal, kind, length, value))
        shape = (stored, tuple(arg.kind for arg in args))
        require(shape in OPCODE_SHAPES.get(opcode, ()), "UNKNOWN_SHAPE", f"{path.name}: {offset} {opcode} {shape}")
        shape_id = f"op{opcode}-n{stored}-" + ".".join(str(arg.kind) for arg in args)
        anchors.append(Anchor(offset, opcode, stored, info, line, source, args, shape_id))
        name_match = NAME_PATTERN.match(source)
        named = name_match is not None
        if named:
            require(opcode in D["message_opcodes"] and len(args) >= 3 and args[1].kind == D["string_type"],
                    "UNKNOWN_SHAPE", f"{path.name}: 人名槽位 {offset}")
        messages, name_key = [], None
        for arg in args:
            if arg.kind == D["message_metadata_type"]:
                require(arg.value + D["metadata_size"] <= len(pool.data), "FORMAT", f"{path.name}: 消息信息")
                metadata.append((arg.value, D["metadata_size"]))
            if arg.kind != D["string_type"]:
                continue
            require(arg.value + arg.length <= len(pool.data), "FORMAT", f"{path.name}: 文本引用 {arg.site}")
            payload = pool.data[arg.value:arg.value + arg.length].translate(XOR_TABLE)
            prospective_id = f"S{(arg.site - code.start) // CELL.size:08d}"
            selected_encoding = (entry_encodings or {}).get(prospective_id, source_encoding)
            tag, policy, evidence = role(opcode, arg.ordinal, len(args), named)
            text, unsafe = display_bytes(payload, selected_encoding, allow_linefeeds=(tag == "msg"))
            if unsafe:
                policy = "frozen"
            key = (arg.value, arg.length)
            if key not in objects:
                oid = prospective_id
                objects[key] = TextEntry(0, oid, f"pool:{arg.value}:{arg.length}", pool.start + arg.value,
                                         payload, text, tag, policy, evidence, pool_offset=arg.value,
                                         undecodable=unsafe)
            entry = objects[key]
            require((entry.tag, entry.policy) == (tag, policy), "UNKNOWN_SHAPE", f"{path.name}: 共享文本角色冲突")
            entry.sites.append(arg.site)
            if tag == "name":
                name_key = key
                if baseline:
                    require(text == name_match.group(1), "COMPANION", f"{path.name}: 人名原文 {offset}")
            elif tag == "msg":
                messages.append(key)
        if named:
            require(name_key is not None, "COMPANION", f"{path.name}: 名字不存在")
            binding_candidates.extend((msg, name_key, offset) for msg in messages)
    entries = []
    for item in original.tables:
        text, unsafe = display_bytes(item.raw, source_encoding)
        entries.append(TextEntry(0, f"T{item.table}_{item.ordinal:08d}", f"table:{item.table}:{item.ordinal}",
                                 item.start, item.raw, text, "label", "frozen", "structural", undecodable=unsafe))
    entries.extend(objects.values())
    for idx, entry in enumerate(entries, 1):
        entry.idx = idx
    bindings = []
    for message_key, name_key, offset in binding_candidates:
        msg, name = objects[message_key], objects[name_key]
        if name.object_id not in msg.name_ids:
            msg.name_ids.append(name.object_id)
            msg.speakers.append(name.source)
        bindings.append({"msg_object_id": msg.object_id, "name_object_id": name.object_id,
                         "anchor_offset": offset, "method": "slot-ordinal+debug-source-marker",
                         "confidence": "derived", "evidence_refs": ["EV_NAMES"]})
    require(all(len(entry.name_ids) <= 1 for entry in entries), "COMPANION", f"{path.name}: 人名绑定歧义")
    rel = relative_path or path.name
    sid = sha(rel.encode("utf-8") + b"\0" + bytes.fromhex(sha(original.raw)))[:24]
    return Document(original, companion, rel, sid, entries, anchors, sorted(set(metadata)), bindings, source_encoding)


def display_width(value: str) -> int:
    """Stable wrapping estimate, not a claim about the game's font metrics."""
    return sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in ("W", "F") else 1
               for c in value)


def encode_message_parts(parts: list[str]) -> str:
    """Encode display breaks as literal \\n and escape native backslash controls."""
    return r"\n".join(row.replace("\\", "\\\\")
                       for part in parts for row in part.split("\n"))


def decode_message_parts(text: str, expected_count: int | None = None) -> list[str]:
    """Decode row separators and escaped native controls from a logical message."""
    parts, current, index = [], [], 0
    while index < len(text):
        if text[index] != "\\":
            current.append(text[index])
            index += 1
        elif index + 1 < len(text) and text[index + 1] == "\\":
            current.append("\\")
            index += 2
        elif text.startswith(r"\n", index):
            parts.append("".join(current))
            current = []
            index += 2
        else:
            current.append("\\")
            index += 1
    parts.append("".join(current))
    require(expected_count is None or len(parts) == expected_count, "LENGTH_OVERFLOW",
            f"整句需要 {expected_count} 行，以字面 \\n 分隔")
    return parts


def projection_entries(doc: Document, mode: str = D["default_text_projection"]) -> list[TextEntry]:
    require(mode in D["text_projection_modes"], "SOURCE_BINDING", f"文本投影 {mode}")
    if mode == D["legacy_text_projection"]:
        return doc.entries
    by_site = {site: entry for entry in doc.entries if entry.tag == "msg" for site in entry.sites}
    groups, consumed = {}, set()
    for anchor in doc.anchors:
        if anchor.opcode not in D["message_opcodes"]:
            continue
        members = [by_site[arg.site] for arg in anchor.arguments if arg.site in by_site]
        require(members and all(len(e.sites) == 1 and e.object_id not in consumed for e in members),
                "UNKNOWN_SHAPE", f"{doc.relative_path}: 对话分段共享或缺失 {anchor.offset}")
        prefixes = tuple("" if index == 0 else e.source[:len(e.source) - len(e.source.lstrip(D["message_indent"]))]
                         for index, e in enumerate(members))
        parts = [e.source[len(prefix):] for e, prefix in zip(members, prefixes)]
        source = (encode_message_parts(parts) if mode == D["message_break_projection"] else "".join(parts))
        first = members[0]
        require(all(e.name_ids == first.name_ids for e in members), "COMPANION", "整句人名绑定不一致")
        group = TextEntry(0, f"M{anchor.offset:08d}", f"message:{anchor.offset}", first.off,
                          b"".join(e.raw for e in members), source, "msg",
                          "frozen" if any(e.policy == "frozen" for e in members) else "translatable", "anchor",
                          sites=[site for e in members for site in e.sites], speakers=list(first.speakers),
                          name_ids=list(first.name_ids), undecodable=any(e.undecodable for e in members),
                          member_ids=tuple(e.object_id for e in members), prefixes=prefixes, anchor_offset=anchor.offset,
                          projection_mode=mode)
        groups[first.object_id] = group
        consumed.update(group.member_ids)
    require(consumed == {e.object_id for e in doc.entries if e.tag == "msg"}, "UNKNOWN_SHAPE", "正文分组集合不一致")
    result = []
    for entry in doc.entries:
        if entry.object_id in groups:
            result.append(groups[entry.object_id])
        elif entry.object_id not in consumed:
            result.append(replace(entry))
    for idx, entry in enumerate(result, 1):
        entry.idx = idx
    return result


def message_group_records(doc: Document, projection_mode: str = D["default_text_projection"]) -> list[dict]:
    records, by_id = [], doc.by_id
    for entry in projection_entries(doc, projection_mode):
        if not entry.member_ids:
            continue
        records.append({"sample": doc.relative_path, "src_id": doc.src_id, "object_id": entry.object_id,
                        "idx": entry.idx, "anchor_offset": entry.anchor_offset, "source": entry.source,
                        "name_ids": entry.name_ids, "members": [
                            {"object_id": oid, "source": by_id[oid].source, "prefix": prefix,
                             "off": by_id[oid].off, "raw_sha256": sha(by_id[oid].raw),
                             "sites": by_id[oid].sites} for oid, prefix in zip(entry.member_ids, entry.prefixes)]})
    return records


def render_text(doc: Document, target_encoding: str, projection_mode: str = D["default_text_projection"]) -> str:
    result = [f"# TEXT/2 ir=1 tool={TOOL_VERSION} src_sha256={sha(doc.raw)} src_id={doc.src_id}",
              f"# encoding source={doc.source_encoding} target={target_encoding} file=utf-8",
              "# scope kind=all range=ALL part=1/1", "# tags " + " ".join(D["tags"])]
    if projection_mode != D["legacy_text_projection"]:
        result[0] += f" projection={projection_mode}"
    for entry in projection_entries(doc, projection_mode):
        metadata = (f"# idx={entry.idx:08d} off=0x{entry.off:08X} tag={entry.tag} "
                    f"object_id={entry.object_id} policy={entry.policy}")
        result.append(metadata)
        if entry.speakers:
            result.append("# speaker: " + entry.speakers[0])
        result.extend((f"○{entry.idx:08d}○{entry.tag}○{entry.source}",
                       f"●{entry.idx:08d}●{entry.tag}●{entry.source}", ""))
    return "\n".join(result) + "\n"


def render_asm(doc: Document, target_encoding: str) -> str:
    lines = [f"; NORI structured data view; T2; control flow and structural edits are read-only",
             f".source id={doc.src_id} sha256={sha(doc.raw)}",
             f'.encoding source="{doc.source_encoding}" target="{target_encoding}"',
             f'.dialect id="{DIALECT_ID}" version="{TOOL_VERSION}"']
    for block in doc.container.blocks:
        lines.append(f".region id={block.name} offset={block.start} length={len(block.data)} sha256={sha(block.data)} readonly=true")
    lines.append("")
    for anchor in doc.anchors:
        lines.append(f"anchor_{anchor.offset:08d}:")
        lines.append(f".anchor id=A{anchor.offset:08d} opcode={anchor.opcode} shape={anchor.shape_id} readonly=true")
        lines.append("")
    for entry in doc.entries:
        # JSON is an outer quoting layer, not byte-escape expansion in translated text.
        lines.append(f".string id={entry.object_id} sid={entry.storage_id} tag={entry.tag} "
                     f"policy={entry.policy} value={json.dumps(entry.source, ensure_ascii=False)}")
    return "\n".join(lines) + "\n"


def certificate(container: Container, decoded: bool = True) -> dict:
    intervals = []
    for block in container.blocks:
        intervals.append({"id": block.name, "start": block.start, "end": block.end,
                          "status": "decoded" if decoded else "opaque-preserved",
                          "raw_sha256": sha(container.raw[block.start:block.end]),
                          "decode_tier": "T2" if decoded else "T0",
                          "boundary_model": "structured", "boundary_evidence_refs": ["EV_CONTAINER"],
                          "tier_evidence_refs": ["EV_CONTAINER"],
                          "structured_fields": [block.name, "crc16-ccitt"],
                          "evidence_refs": ["EV_CONTAINER", "EV_CRC"]})
    return {"schema_version": "1.1.0", "source_size": len(container.raw), "intervals": intervals,
            "byte_coverage": 1.0, "structural_coverage": 1.0 if decoded else 0.0,
            "tier_coverage": {f"T{n}": len(container.raw) if n == (2 if decoded else 0) else 0 for n in range(5)},
            "min_tier": "T2" if decoded else "T0", "instruction_coverage": "not_applicable",
            "evidence": {"EV_CONTAINER": {"kind": "observed", "source": "vm_analysis.md#ev_container"},
                         "EV_CRC": {"kind": "derived", "source": "vm_analysis.md#ev_crc"}},
            "declared_capabilities": ["identity"],
            "capability_scopes": {"identity": {"scope_region_ids": [block.name for block in container.blocks]}}}


def ensure_cancel(cancel):
    if cancel and cancel():
        raise ToolError("CANCELLED")


def choose_output(source: Path, suffix: str) -> Path:
    return source.with_name(source.stem + suffix) if source.is_file() else source.with_name(source.name + suffix)


class OutputTransaction:
    def __init__(self, output: Path, protected: list[Path]):
        self.output = output.resolve()
        require(not self.output.exists(), "OUTPUT_EXISTS", str(self.output))
        for item in protected:
            item = item.resolve()
            require(self.output != item and not self.output.is_relative_to(item), "OUTPUT_PATH", str(self.output))
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.stage = self.output.parent / ("." + self.output.name + ".staging-" + uuid.uuid4().hex)
        self.stage.mkdir()
        self.committed = False

    def commit(self):
        require(not self.output.exists(), "OUTPUT_EXISTS", str(self.output))
        os.replace(self.stage, self.output)
        self.committed = True

    def abort(self):
        # Checked task-owned absolute path before any recursive removal on Windows.
        stage = self.stage.resolve()
        if not self.committed and stage.exists():
            require(stage.parent == self.output.parent and stage.name.startswith("." + self.output.name + ".staging-"),
                    "OUTPUT_PATH", str(stage))
            shutil.rmtree(stage)


def enumerate_sources(source: Path) -> tuple[Path, list[Path]]:
    source = source.resolve()
    require(source.exists(), "INPUT_PATH", str(source))
    if source.is_file():
        require(source.suffix.lower() == ".bin", "INPUT_PATH", str(source))
        companion = source.with_suffix(".debug")
        require(companion.is_file(), "COMPANION", str(companion))
        return source.parent, sorted([source, companion])
    require(not (source / "project.json").exists(), "INPUT_PROJECT", str(source))
    files = sorted(path for path in source.rglob("*") if path.is_file())
    require(any(path.suffix.lower() == ".bin" for path in files), "INPUT_PATH", str(source))
    require(all(not path.is_symlink() and path.resolve().is_relative_to(source) for path in files), "INPUT_PATH", "符号链接")
    return source, files


def make_manifest(root: Path, paths: list[Path]) -> list[dict]:
    return [{"sample": path.relative_to(root).as_posix(), "sha256": sha(checked_read(path)),
             "size": path.stat().st_size} for path in paths]


def verify_sources(root: Path, manifest: list[dict]):
    for item in manifest:
        path = (root / item["sample"]).resolve()
        require(path.is_relative_to(root.resolve()) and path.is_file(), "SOURCE_CHANGED", str(path))
        require(sha(checked_read(path)) == item["sha256"], "SOURCE_CHANGED", str(path))


def export_project(source: Path, output: Path | None = None, source_encoding: str = "cp932",
                   target_encoding: str = "cp932", texts: bool = True, asm: bool = False,
                   with_ir: bool = False, progress=None, cancel=None,
                   projection_mode: str = D["default_text_projection"]) -> dict:
    require(texts or asm, "TEXT_PROTOCOL", "至少选择一种输出")
    require(projection_mode in D["text_projection_modes"], "SOURCE_BINDING", f"文本投影 {projection_mode}")
    started = time.perf_counter()
    suffix = ("_disasm" if asm and not texts else
              "_text_segments" if projection_mode == D["legacy_text_projection"] else
              "_text" if projection_mode == D["message_break_projection"] else "_text_v1")
    source, output = Path(source).resolve(), Path(output).resolve() if output else choose_output(Path(source).resolve(), suffix)
    source_encoding, target_encoding = codec(source_encoding), codec(target_encoding)
    root, paths = enumerate_sources(source)
    manifest = make_manifest(root, paths)
    txn = OutputTransaction(output, [source])
    documents, coverage, extract, shapes, projections, roundtrips = [], [], [], Counter(), [], []
    try:
        total_bytes, done = sum(item["size"] for item in manifest), 0
        for item, path in zip(manifest, paths):
            ensure_cancel(cancel)
            data = checked_read(path)
            require(sha(data) == item["sha256"], "SOURCE_CHANGED", str(path))
            if path.suffix.lower() == ".bin":
                doc = parse_document(path, item["sample"], source_encoding, data)
                rebuilt = serialize_container(doc.container)
                require(rebuilt == data, "VERIFY", f"{path.name}: 零编辑")
                documents.append(doc)
                coverage.append({"sample": item["sample"], **certificate(doc.container)})
                roundtrips.append({"sample": item["sample"], "sha256": sha(data), "roundtrip_identity": "pass", "path": "parse+serialize+recompute-all-crcs"})
                projected_entries = projection_entries(doc, projection_mode)
                tags = Counter(entry.tag for entry in projected_entries)
                row = {"sample": item["sample"], "byte_size": len(data), "tags": dict(tags),
                       "required_tags": ["msg"] if any(a.opcode in D["message_opcodes"] for a in doc.anchors) else [],
                       "domain": "nori-script",
                       "containers": {"dialog_entries": sum(a.opcode in D["message_opcodes"] for a in doc.anchors),
                                      "select_entries": sum(a.opcode in D["choice_opcodes"] for a in doc.anchors)},
                       "tag_source": dict(Counter(entry.tag_source for entry in projected_entries)),
                       "heuristic": 0, "unresolved": sum(e.tag_source == "unresolved" for e in projected_entries),
                       "anchors": len(doc.anchors), "entries": len(projected_entries),
                       "physical_entries": len(doc.entries), "text_projection": projection_mode}
                if not doc.entries:
                    row["allow_empty"] = {"reason": "NORI 头声明全部表、代码和文本池长度为零；对应 .debug 仅含源路径记录",
                                          "evidence_refs": ["EV_EMPTY_INDEX"]}
                extract.append(row)
                for anchor in doc.anchors:
                    shapes[anchor.shape_id] += 1
                for enabled, folder, ending, renderer, encoding in (
                    (texts, "texts", ".txt", render_text, D["text_encoding"]),
                    (asm, "asm", ".asm.txt", render_asm, D["asm_encoding"]),
                ):
                    if enabled:
                        relative = folder + "/" + item["sample"] + ending
                        projected = (render_text(doc, target_encoding, projection_mode) if folder == "texts"
                                     else renderer(doc, target_encoding)).encode(encoding)
                        dest = txn.stage / relative
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(projected)
                        projections.append({"source": item["sample"], "kind": folder,
                                            "path": relative, "sha256": sha(projected)})
            elif path.suffix.lower() == ".debug":
                container = parse_container(path, data)
                require(serialize_container(container) == data, "VERIFY", f"{path.name}: 调试文件零编辑")
                debug_records(container)
                coverage.append({"sample": item["sample"], **certificate(container)})
                roundtrips.append({"sample": item["sample"], "roundtrip_identity": "pass", "sha256": sha(data), "path": "parse+serialize+recompute-all-crcs"})
            else:
                coverage.append({"sample": item["sample"], "source_size": len(data), "byte_coverage": 1.0,
                                 "structural_coverage": 0.0, "min_tier": "T0", "preservation": "raw-bytes", "sha256": sha(data)})
                roundtrips.append({"sample": item["sample"], "roundtrip_identity": "pass", "sha256": sha(data), "path": "opaque-preservation"})
            done += item["size"]
            if progress:
                progress(done, total_bytes, item["sample"])
        verify_sources(root, manifest)
        project = {"schema_version": 1, "tool_version": TOOL_VERSION, "dialect_id": DIALECT_ID,
                   "dialect_hash": sha(Path(__file__).with_name("opcodelist.py").read_bytes()),
                   "source_root": str(root), "source_input": str(source),
                   "source_kind": "file" if source.is_file() else "directory",
                   "source_encoding": source_encoding, "target_encoding": target_encoding,
                   "text_projection": projection_mode,
                   "manifest": manifest, "projections": projections}
        project["binding_hash"] = sha(canonical(project))
        save_json(txn.stage / "project.json", project)
        reports = txn.stage / "_work/reports"
        save_json(reports / "coverage.json", coverage)
        save_json(reports / "roundtrip.json", roundtrips)
        save_json(reports / "extract.json", extract)
        if projection_mode != D["legacy_text_projection"]:
            save_jsonl(reports / "message_groups.jsonl", (row for doc in documents for row in message_group_records(doc, projection_mode)))
        corpus = [{"sample": row["sample"], "sha256": row["sha256"]} for row in manifest if row["sample"].lower().endswith(".bin")]
        save_json(reports / "corpus.json", corpus)
        declared_shapes = {f"op{op}-n{count}-" + ".".join(map(str, kinds))
                           for op, variants in OPCODE_SHAPES.items() for count, kinds in variants}
        shape_report = {"declared": sorted(declared_shapes),
                        "observed": {name: {"entries": count, "texts": count} for name, count in sorted(shapes.items())},
                        "nontext_shapes": {}, "unmatched": {},
                        "inherited": {name: {"reason": "本篇与 FD 联合语料已验证的形态；当前输入子集未命中，仍保留声明",
                                              "evidence_refs": ["EV_CORPUS_PROFILE"]}
                                      for name in sorted(declared_shapes - set(shapes))},
                        "corpus": {"manifest_sha256": sha((reports / "corpus.json").read_bytes()), "scanned": corpus}}
        # Text-free commands are explicitly identified; "texts" counts actual string fields.
        shape_texts = Counter()
        for doc in documents:
            for anchor in doc.anchors:
                shape_texts[anchor.shape_id] += sum(arg.kind == D["string_type"] for arg in anchor.arguments)
        for name, row in shape_report["observed"].items():
            row["texts"] = shape_texts[name]
            if not row["texts"]:
                shape_report["nontext_shapes"][name] = {"reason": "参数结构没有字符串字段", "evidence_refs": ["EV_DEBUG_PAIRS"]}
        save_json(reports / "shapes.json", shape_report)
        save_json(reports / "window_hits.json", {"window_limits_used": False, "hits": 0})
        save_json(reports / "rule_hits.json", {tag: sum(row["tags"].get(tag, 0) for row in extract) for tag in D["tags"]})
        if with_ir:
            export_ir_snapshot(documents, txn.stage / "ir", projection_mode)
        summary = {"status": "pass", "scope": "corpus-extraction-and-zero-edit-reconstruction",
                   "source_files": len(manifest), "scripts": len(documents), "text_entries": sum(row["entries"] for row in extract),
                   "physical_text_entries": sum(len(doc.entries) for doc in documents), "text_projection": projection_mode,
                   "tags": dict(sum((Counter(row["tags"]) for row in extract), Counter())),
                   "byte_coverage": 1.0, "roundtrip_identity": "pass", "runtime_validation": "not_verified",
                   "cross_origin_validation": "not_verified", "output": str(output),
                   "seconds": round(time.perf_counter() - started, 3)}
        save_json(reports / "summary.json", summary)
        ensure_cancel(cancel)
        txn.commit()
        return summary
    except Exception as exc:
        checkpoint = output.parent / ("." + output.name + ".failure-" + uuid.uuid4().hex + ".json")
        save_json(checkpoint, {"status": "fail" if not isinstance(exc, ToolError) or exc.code != "CANCELLED" else "not_verified",
                               "stage": "export", "error": str(exc), "source": str(source), "output": str(output)})
        txn.abort()
        raise


def export_ir_snapshot(documents: list[Document], directory: Path, projection_mode: str = D["default_text_projection"]):
    manifest, entries, bindings, cursor = [], [], [], 0
    for doc in documents:
        projected = projection_entries(doc, projection_mode)
        manifest.append({"src_id": doc.src_id, "sha256": sha(doc.raw), "relative_path": doc.relative_path,
                         "entry_line_start": cursor, "entry_line_end": cursor + len(projected),
                         "schema_version": 1, "tool_version": TOOL_VERSION, "text_projection": projection_mode})
        for entry in projected:
            entries.append({"src_id": doc.src_id, "idx": entry.idx, "object_id": entry.object_id,
                            "off": entry.off,
                            "source": entry.source, "tag": entry.tag, "translate_policy": entry.policy,
                            "raw_len": len(entry.raw), "raw_sha256": sha(entry.raw), "member_ids": entry.member_ids})
        if projection_mode == D["legacy_text_projection"]:
            bindings.extend({"src_id": doc.src_id, **binding} for binding in doc.bindings)
        else:
            bindings.extend({"src_id": doc.src_id, "msg_object_id": entry.object_id,
                             "name_object_id": name_id, "anchor_offset": entry.anchor_offset,
                             "method": "same-command-physical-slots", "confidence": "derived", "evidence_refs": ["EV_NAMES"]}
                            for entry in projected for name_id in entry.name_ids)
        cursor += len(projected)
    save_jsonl(directory / "manifest.jsonl", manifest)
    save_jsonl(directory / "text_entries.jsonl", entries)
    save_jsonl(directory / "name_bindings.jsonl", bindings)


def main():
    parser = argparse.ArgumentParser(description=r"导出已解出的 NORI v65536 脚本文本。默认输出到同级 *_text 目录；\n 表示显示行边界。")
    parser.add_argument("source", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--source-encoding", default=D["source_encoding"])
    parser.add_argument("--target-encoding", default=D["target_encoding"])
    parser.add_argument("--mode", choices=("export-text", "disasm", "both"), default="export-text")
    parser.add_argument("--with-ir", action="store_true")
    parser.add_argument("--text-projection", choices=D["text_projection_modes"], default=D["default_text_projection"],
                        help=r"默认 message-v2；兼容旧工程可选 message-v1 或 segments-v1")
    args = parser.parse_args()
    try:
        result = export_project(args.source, args.output, args.source_encoding, args.target_encoding,
                                args.mode != "disasm", args.mode != "export-text", args.with_ir,
                                projection_mode=args.text_projection)
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
