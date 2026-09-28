#!/usr/bin/env python3
"""Extract indexed dialogue from Interheart SPT + PTR/TXD, not a raw string scan."""

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import struct
from opcodelist import DIALECT


ANCHOR = re.compile(DIALECT["text_rules"]["anchor_regex"])
SELECTION = re.compile(DIALECT["text_rules"]["selection_regex"])
NAME_ID_BASE = DIALECT["text_rules"]["name_id_base"]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def scene_source_identity(scene_name, spt, source, ptr, txd):
    """Hash a versioned, unambiguous virtual source bundle, including all inputs."""
    h = hashlib.sha256()
    h.update(DIALECT["text_rules"]["source_identity_domain"].encode("ascii") + b"\0")
    for part in (scene_name.encode("utf-8"), spt, source, ptr, txd):
        h.update(struct.pack("<Q", len(part)))
        h.update(part)
    return h.hexdigest()


def read_ptr(path, txd):
    raw = path.read_bytes()
    profile = DIALECT["ptr"]
    if len(raw) < profile["header_size"] or raw[:4] != profile["signature"].encode("ascii"):
        raise ValueError("not a PTR index")
    count, reserved0, reserved1 = struct.unpack_from("<III", raw, 4)
    if reserved0 or reserved1 or len(raw) != profile["header_size"] + profile["record_size"] * count:
        raise ValueError("unexpected PTR header or length")
    entries = {}
    cursor = 0
    for index in range(count):
        ident, offset, size = struct.unpack_from(profile["record_format"], raw,
                                                  profile["header_size"] + profile["record_size"] * index)
        if ident != index + 1 or offset != cursor or offset + size > len(txd):
            raise ValueError(f"PTR gap, duplicate ID, or invalid range at row {index}")
        text = txd[offset:offset + size].decode("utf-8", "strict")
        if "," not in text or "\n" in text or "\r" in text:
            raise ValueError(f"unexpected TXD record framing at ID {ident}")
        speaker, body = text.split(",", 1)
        if not body:
            raise ValueError(f"empty TXD body at ID {ident}")
        entries[ident] = (speaker, body, offset, size)
        cursor += size
    if cursor != len(txd):
        raise ValueError("unindexed TXD bytes")
    return raw, entries


def selection_ranges(lines):
    # The source compiler uses ***SS_<scene>_<option-count>_<branch...>.
    headers = [(i, line) for i, line in enumerate(lines)
               if line.startswith(("***SC_", "***SS_"))]
    tagged = {}
    sections = 0
    for n, (start, heading) in enumerate(headers):
        if not heading.startswith("***SS_"):
            continue
        m = SELECTION.match(heading)
        if not m:
            raise ValueError(f"unrecognized choice header at line {start + 1}")
        scene, option_count = m.group(1), int(m.group(2))
        end = headers[n + 1][0] if n + 1 < len(headers) else len(lines)
        ids = []
        for line in lines[start + 1:end]:
            if not line.lstrip().startswith("//"):
                ids.extend(int(match.group(1)) for match in ANCHOR.finditer(line))
        if len(ids) != option_count + 1:
            raise ValueError(f"choice count mismatch for {scene}: {len(ids)}")
        for pos, ident in enumerate(ids):
            if ident in tagged:
                raise ValueError(f"duplicate choice ID {ident}")
            tagged[ident] = (scene, "prompt" if pos == 0 else "option")
        sections += 1
    return tagged, sections


def parse_spt(path):
    raw = path.read_bytes()
    profile = DIALECT["spt"]
    if len(raw) < profile["header_size"]:
        raise ValueError(f"short SPT: {path}")
    count = struct.unpack_from("<I", raw)[0]
    if len(raw) != profile["header_size"] + profile["record_size"] * count:
        raise ValueError(f"SPT record size/count mismatch: {path}")
    return raw, [struct.unpack_from(profile["field_format"], raw,
                                   profile["header_size"] + profile["record_size"] * i)
                 for i in range(count)]


def examine(data_dir):
    data_dir = Path(data_dir)
    source_raw = (data_dir / "ACT_A.txt").read_bytes()
    txd = (data_dir / "ACT_A_JA.TXD").read_bytes()
    lines = source_raw.decode("utf-8", "strict").splitlines()
    ptr_raw, indexed = read_ptr(data_dir / "ACT_A_JA.PTR", txd)
    if len(indexed) >= NAME_ID_BASE:
        raise ValueError("PTR ID space conflicts with name identities")
    selections, selection_count = selection_ranges(lines)
    files = sorted(data_dir.glob("*.spt"))
    if not files:
        raise ValueError("no SPT files")
    bindings = {}
    by_file = defaultdict(list)
    scene_hashes = {}
    source_identities = {}
    shape = Counter()
    for path in files:
        raw, records = parse_spt(path)
        scene_hashes[path.name] = digest(raw)
        source_identities[path.name] = scene_source_identity(
            path.name, raw, source_raw, ptr_raw, txd)
        for record_no, row in enumerate(records):
            opcode, mode, voice, unused, line0, line_count, kind, value = row
            shape[(opcode, kind)] += 1
            if opcode != DIALECT["spt"]["text_opcode"]:
                continue
            if kind != DIALECT["spt"]["text_kind"] or value not in indexed or value in bindings:
                raise ValueError(f"unresolved/duplicate SPT text reference {path}:{record_no}")
            if line0 < 0 or line_count <= 0 or line0 + line_count > len(lines):
                raise ValueError(f"invalid source line span {path}:{record_no}")
            speaker, body, offset, size = indexed[value]
            source_line = lines[line0]
            marks = list(ANCHOR.finditer(source_line))
            if len(marks) != 1 or int(marks[0].group(1)) != value:
                raise ValueError(f"SPT/source anchor mismatch at {path}:{record_no}")
            span = lines[line0:line0 + line_count]
            if speaker:
                if not source_line.startswith(speaker + "\u3000"):
                    raise ValueError(f"speaker mismatch at TXD ID {value}")
                source_body = r"\n".join(span[1:])
            else:
                stripped_first = source_line[:marks[0].start()] + source_line[marks[0].end():]
                source_body = r"\n".join([stripped_first] + span[1:])
            if source_body != body:
                raise ValueError(f"SPT/source/TXD text mismatch at ID {value}")
            choice = selections.get(value)
            if choice and choice[0] != path.stem:
                raise ValueError(f"choice scene mismatch at ID {value}")
            bindings[value] = {
                "id": value, "scene": path.name, "record": record_no,
                "spt_offset": 4 + 32 * record_no, "source_line": line0 + 1,
                "ptr_offset": 16 + 12 * (value - 1), "txd_offset": offset,
                "txd_size": size, "speaker": speaker, "text": body,
                "name_id": NAME_ID_BASE + value if speaker else None,
                "name_txd_size": len(speaker.encode("utf-8")),
                "tag": "choice" if choice else "msg",
                "subtype": choice[1] if choice else "dialogue",
                "mode": mode, "voice": voice,
            }
            by_file[path.name].append(bindings[value])
    if set(bindings) != set(indexed):
        raise ValueError(f"unbound TXD records: {sorted(set(indexed) - set(bindings))[:10]}")
    if set(selections) - set(bindings):
        raise ValueError("choice text not referenced by SPT")
    return {
        "data_dir": data_dir, "files": files, "by_file": by_file,
        "bindings": bindings, "scene_hashes": scene_hashes,
        "source_identities": source_identities,
        "shape": shape, "selection_count": selection_count,
        "source_hashes": {
            "ACT_A.txt": digest(source_raw),
            "ACT_A_JA.PTR": digest(ptr_raw),
            "ACT_A_JA.TXD": digest(txd),
        },
        "source_sizes": {
            "ACT_A.txt": len(source_raw),
            "ACT_A_JA.PTR": len(ptr_raw),
            "ACT_A_JA.TXD": len(txd),
        },
    }


def render_scene(entries, source_hash, scene_id, *, source_encoding="utf-8",
                 target_encoding="utf-8"):
    head = [
        f"# TEXT/2 ir=1 tool=interheart-extract-1 src_sha256={source_hash} src_id={scene_id}",
        f"# encoding source={source_encoding} target={target_encoding} file=utf-8",
        "# scope kind=all range=ALL part=1/1",
        "# tags name msg choice label ui system ruby misc",
    ]
    for entry in sorted(entries, key=lambda e: e["record"]):
        if entry["name_id"] is not None:
            name_idx = f'{entry["name_id"]:08d}'
            head.extend([
                f"# idx={name_idx} tag=name",
                f"○{name_idx}○name○{entry['speaker']}",
                f"●{name_idx}●name●{entry['speaker']}",
                "",
            ])
        idx = f'{entry["id"]:08d}'
        tag = entry["tag"]
        speaker = f' speaker={entry["speaker"]}' if entry["speaker"] else ""
        head.extend([
            f"# idx={idx} tag={tag}{speaker}",
            f"○{idx}○{tag}○{entry['text']}",
            f"●{idx}●{tag}●{entry['text']}",
            "",
        ])
    return ("\n".join(head) + "\n").encode("utf-8")


def export(data_dir, output):
    result = examine(data_dir)
    output = Path(output)
    if output.exists():
        raise ValueError("output directory already exists")
    if output.resolve().is_relative_to(result["data_dir"].resolve()):
        raise ValueError("output directory must not be inside the input data")
    output.mkdir(parents=True)
    (output / "texts").mkdir()
    entries = result["bindings"]
    present = result["by_file"]
    name_count = sum(e["name_id"] is not None for e in entries.values())
    index_lines = ["id\tscene\tspt_record\tspt_offset\tsource_line\tptr_offset\t"
                   "txd_offset\ttxd_size\tname_idx\tname_txd_size\ttag\tsubtype\tspeaker"]
    for ident in sorted(entries):
        e = entries[ident]
        index_lines.append("\t".join("" if e[k] is None else str(e[k]) for k in
                           ("id", "scene", "record", "spt_offset", "source_line",
                            "ptr_offset", "txd_offset", "txd_size", "name_id",
                            "name_txd_size", "tag",
                            "subtype", "speaker")))
    (output / "index.tsv").write_bytes(("\n".join(index_lines) + "\n").encode("utf-8"))
    for name, items in sorted(present.items()):
        (output / "texts" / (name + ".txt")).write_bytes(
            render_scene(items, result["source_identities"][name], name))
    report = {
        "status": "pass", "input": str(result["data_dir"].resolve()),
        "scope": "text extraction and projection only; no text import/repack",
        "source_identity": "SHA-256 of INTERHEART-TEXT-SOURCE/1 NUL plus "
                           "length-prefixed scene name, SPT, ACT_A.txt, PTR, TXD",
        "source_sha256": result["source_hashes"],
        "source_sizes": result["source_sizes"], "spt_files_scanned": len(result["files"]),
        "spt_files_with_text": len(present),
        "spt_files_without_text": [p.name for p in result["files"]
                                    if p.name not in present],
        "spt_shapes": {f"opcode={a},kind={b}": c
                       for (a, b), c in sorted(result["shape"].items())},
        "selection_sections": result["selection_count"],
        "text_entries": len(entries) + name_count,
        "body_entries": len(entries), "name_entries": name_count,
        "distinct_name_values": len({e["speaker"] for e in entries.values()
                                     if e["speaker"]}),
        "tag_counts": dict(sorted((Counter(e["tag"] for e in entries.values())
                                   + Counter({"name": name_count})).items())),
        "choice_subtypes": dict(sorted(Counter(e["subtype"] for e in entries.values()
                                            if e["tag"] == "choice").items())),
        "tag_source_counts": {"structural": name_count, "anchor": len(entries),
                              "binding": 0, "heuristic": 0, "user": 0,
                              "unresolved": 0},
        "txd_byte_coverage": 1.0,
        "ptr_entry_coverage": 1.0,
        "spt_text_reference_coverage": 1.0,
        "source_annotation_coverage": 1.0,
        "understanding": "T2: text-pool boundary and SPT-to-PTR/TXD join; "
                         "non-text SPT opcode semantics not claimed",
        "text_repack": "not_implemented",
        "runtime_load": "not_verified",
        "cross_game_validation": "not_verified",
    }
    (output / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    report = export(args.data, args.output)
    print(json.dumps({k: report[k] for k in
                      ("status", "spt_files_scanned", "spt_files_with_text",
                       "text_entries", "name_entries", "tag_counts",
                       "selection_sections")},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
