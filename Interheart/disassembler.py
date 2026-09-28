#!/usr/bin/env python3
"""Evidence-bound Interheart SPT/PTR/TXD projection (TEXT/2 and read-only cells)."""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import time

from extract_text import digest, examine, parse_spt, render_scene
from fpk_repack import build as build_archive, verify as verify_archive
from opcodelist import DIALECT


class ToolError(Exception):
    def __init__(self, code, detail):
        self.code, self.detail = code, str(detail)
        super().__init__(f"{code}: {detail}")


def input_paths(source):
    """Accept the extracted data directory, its FPK sibling, or an SPT inside it."""
    path = Path(source).resolve()
    if path.is_file() and path.suffix.lower() == ".fpk":
        data = path.with_suffix("")
        archive = path
    elif path.is_file() and path.suffix.lower() == ".spt":
        data = path.parent
        archive = data.parent / (data.name + ".fpk")
    else:
        data = path
        archive = data.parent / (data.name + ".fpk")
    if not data.is_dir() or not archive.is_file():
        raise ToolError("INPUT_MISSING", f"需要配套的目录和归档：{data} / {archive}")
    return data, archive


def default_output(data, suffix):
    return data.with_name(data.name + suffix)


def _json(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def render_asm(name, raw, rows, entries, source_hash, target_encoding):
    """One deterministic line per record; unknown opcodes are cells, not instructions."""
    head = [
        "; Interheart SPT and text-pool audit view; only .string value is editable",
        f'.dialect "{DIALECT["engine_id"]}"',
        f'.source "{source_hash}"',
        f'.encoding "{target_encoding}"',
        '.tier "T2 text / T1 other records"',
        f'.region id=SPT size={len(raw)} count={len(rows)}',
        "",
        "spt_header:",
        f"    .field id=COUNT offset=0x00000000 type=u32 value={len(rows)} ; readonly",
    ]
    for record, row in enumerate(rows):
        off = 4 + 32 * record
        head.extend([
            "",
            f"loc_{off:08X}:",
            f"    .cell id=R{record:06d} offset=0x{off:08X} "
            f"fields={','.join(map(str, row))} ; readonly, opcode semantics not asserted",
        ])
    if entries:
        head.extend(["", "text_pool:"])
    for e in sorted(entries, key=lambda item: item["record"]):
        ident = e["id"]
        if e["speaker"]:
            head.append(
                f'    .string id=N{ident:08d} sid=NAME{ident:08d} '
                f'offset=0x{e["txd_offset"]:08X} value={_json(e["speaker"])}')
        head.append(
            f'    .string id=T{ident:08d} sid=BODY{ident:08d} '
            f'offset=0x{e["txd_offset"] + e["name_txd_size"] + 1:08X} '
            f'value={_json(e["text"])}')
        head.append(f'    .ref id=P{ident:08d} spt=R{e["record"]:06d} '
                    f'ptr=0x{e["ptr_offset"]:08X} target=BODY{ident:08d} ; readonly')
    return ("\n".join(head) + "\n").encode("utf-8")


def _cert(source, kind, intervals):
    raw = source.read_bytes()
    pos = 0
    for seg in intervals:
        if seg["start"] != pos or seg["end"] > len(raw):
            raise ToolError("COVERAGE_GAP", str(source))
        seg["raw_sha256"] = digest(raw[pos:seg["end"]])
        tier = seg["decode_tier"]
        refs = seg.pop("evidence_refs")
        seg["tier_evidence_refs"] = refs
        seg["status"] = ("opaque-preserved" if tier == "T0" else
                         "structured-unknown" if tier == "T1" else "decoded")
        seg["kind"] = kind
        if tier == "T1":
            seg.update(cell_size=4, cell_count=(seg["end"]-seg["start"])//4,
                       endianness="little")
        if tier == "T2":
            seg["boundary_model"] = "structured"
            seg["boundary_evidence_refs"] = refs
            seg["structured_fields"] = (
                ["record_count"] if seg["id"] == "header" and kind == "SPT record stream"
                else ["id", "offset", "size"] if kind == "PTR index"
                else ["speaker", "body"] if kind == "UTF-8 name,body records"
                else ["opcode", "kind", "text_id", "source_line", "line_count"])
        pos = seg["end"]
    if pos != len(raw):
        raise ToolError("COVERAGE_GAP", str(source))
    tier_coverage = {tier: sum(seg["end"] - seg["start"] for seg in intervals
                               if seg["decode_tier"] == tier)
                     for tier in ("T0", "T1", "T2", "T3", "T4")}
    return {
        "schema_version": "1.1.0",
        "source": source.name, "source_sha256": digest(raw), "source_size": len(raw),
        "kind": kind, "byte_coverage": 1.0, "intervals": intervals,
        "gaps": [], "overlaps": [], "tier_coverage": tier_coverage,
        "min_tier": min((seg["decode_tier"] for seg in intervals), default=None),
        "structural_coverage": (tier_coverage["T1"]+tier_coverage["T2"]) / len(raw),
        "instruction_coverage": 0.0 if kind == "SPT record stream" else "not_applicable",
        "declared_capabilities": [],
        "evidence": {
            "EV_SPT_32": {"kind": "observed", "source": "SPT count x 32-byte records"},
            "EV_TEXT_JOIN": {"kind": "derived", "source": "SPT ID, PTR row and ACT_A.txt [ID]"},
            "EV_PTR_TXD": {"kind": "observed", "source": "PTR count/ID/offset/size and TXD boundaries"},
            "EV_NAME": {"kind": "derived", "source": "TXD comma-separated speaker/body and source speaker"},
            "EV_CHOICE": {"kind": "derived", "source": "ACT_A.txt ***SS_ choice-section count"},
        },
    }


def certificates(data, analysis):
    result = []
    result.append(_cert(data / "ACT_A.txt", "UTF-8 annotated source lines", [
        {"id": "source-lines", "start": 0,
         "end": analysis["source_sizes"]["ACT_A.txt"], "decode_tier": "T0",
         "evidence_refs": []},
    ]))
    result.append(_cert(data / "ACT_A_JA.PTR", "PTR index", [
        {"id": "header", "start": 0, "end": 16, "decode_tier": "T2",
         "evidence_refs": ["EV_PTR_TXD"]},
        *({"id": f"row-{i}", "start": 16 + 12*i, "end": 28 + 12*i,
           "decode_tier": "T2", "evidence_refs": ["EV_PTR_TXD", "EV_TEXT_JOIN"]}
          for i in range(len(analysis["bindings"]))),
    ]))
    result.append(_cert(data / "ACT_A_JA.TXD", "UTF-8 name,body records", [
        {"id": f"entry-{e['id']}", "start": e["txd_offset"],
         "end": e["txd_offset"] + e["txd_size"], "decode_tier": "T2",
         "evidence_refs": ["EV_PTR_TXD", "EV_NAME"]}
        for e in sorted(analysis["bindings"].values(), key=lambda item: item["id"])
    ]))
    for path in analysis["files"]:
        raw, rows = parse_spt(path)
        intervals = [{"id": "header", "start": 0, "end": 4,
                      "decode_tier": "T2", "evidence_refs": ["EV_SPT_32"]}]
        for i, row in enumerate(rows):
            known = row[0] == 1 and row[6] == 7
            intervals.append({
                "id": f"row-{i}", "start": 4 + 32*i, "end": 4 + 32*(i+1),
                "decode_tier": "T2" if known else "T1",
                "evidence_refs": ["EV_TEXT_JOIN"] if known else ["EV_SPT_32"],
            })
        result.append(_cert(path, "SPT record stream", intervals))
    return result


def _optional_ir(root, analysis, certs):
    ir = root / "ir"
    ir.mkdir()
    manifest, entries, bindings = [], [], []
    for name in sorted(analysis["by_file"]):
        items = analysis["by_file"][name]
        manifest.append({"src_id": name, "relative_path": name,
                         "sha256": analysis["source_identities"][name],
                         "entry_start": len(entries),
                         "entry_end": len(entries) + len(items) +
                                      sum(bool(e["speaker"]) for e in items)})
        for e in items:
            if e["speaker"]:
                entries.append({"src_id": name, "idx": e["name_id"], "tag": "name",
                                "source": e["speaker"], "translate_policy": "translatable",
                                "object_id": f"N{e['id']:08d}"})
                bindings.append({"src_id": name, "msg_entry_idx": e["id"],
                                 "name_entry_idx": e["name_id"],
                                 "method": "slot-ordinal", "confidence": "derived",
                                 "evidence_refs": ["EV_NAME", "EV_TEXT_JOIN"]})
            entries.append({"src_id": name, "idx": e["id"], "tag": e["tag"],
                            "source": e["text"], "translate_policy": "translatable",
                            "object_id": f"T{e['id']:08d}"})
    for filename, rows in (("manifest.jsonl", manifest),
                           ("text_entries.jsonl", entries),
                           ("name_bindings.jsonl", bindings)):
        (ir / filename).write_text("".join(_json(row) + "\n" for row in rows),
                                    encoding="utf-8")


def export(source, output=None, *, texts=True, asm=False, with_ir=False,
           source_encoding="utf-8", target_encoding="utf-8",
           progress=None, cancelled=None, overwrite=False):
    if not (texts or asm):
        raise ToolError("NO_PROJECTION", "至少选择双行文本或 ASM")
    if source_encoding.lower().replace("_", "-") != "utf-8":
        raise ToolError("ENCODING_UNSUPPORTED", "本样本源文本已证明为 UTF-8")
    if target_encoding.lower().replace("_", "-") != "utf-8":
        raise ToolError("ENCODING_UNSUPPORTED", "本样本目标文本池已证明为 UTF-8")
    data, archive = input_paths(source)
    dest = Path(output).resolve() if output else default_output(data, "_text")
    if dest == data or dest.is_relative_to(data) or dest == archive:
        raise ToolError("OUTPUT_UNSAFE", str(dest))
    if dest.exists() and not overwrite:
        raise ToolError("OUTPUT_EXISTS", str(dest))
    dest.parent.mkdir(parents=True, exist_ok=True)
    src_archive_hash = digest(archive.read_bytes())
    checked = verify_archive(archive, data)
    if checked["status"] != "pass":
        raise ToolError("SOURCE_MISMATCH", str(checked["mismatches"]))
    analysis = examine(data)
    certs = certificates(data, analysis)
    stage = Path(tempfile.mkdtemp(prefix="._text-", dir=dest.parent))
    backup = None
    try:
        if texts:
            (stage / "texts").mkdir()
        if asm:
            (stage / "asm").mkdir()
        total_bytes = sum(p.stat().st_size for p in analysis["files"])
        processed_bytes = 0
        for i, path in enumerate(analysis["files"], 1):
            if cancelled and cancelled.is_set():
                raise ToolError("CANCELLED", "已取消，未提交临时输出")
            name = path.name
            items = analysis["by_file"].get(name, [])
            if texts and items:
                (stage / "texts" / (name + ".txt")).write_bytes(
                    b"\xef\xbb\xbf" + render_scene(
                        items, analysis["source_identities"][name], name,
                        source_encoding=source_encoding, target_encoding=target_encoding))
            if asm:
                raw, rows = parse_spt(path)
                (stage / "asm" / (name + ".asm.txt")).write_bytes(render_asm(
                    name, raw, rows, items, analysis["source_identities"][name],
                    target_encoding))
            if progress:
                processed_bytes += path.stat().st_size
                progress(processed_bytes, total_bytes, name)
        (stage / "_work" / "reports").mkdir(parents=True)
        identity_path = stage / "_work" / "identity.fpk"
        identity = build_archive(archive, data, None, identity_path)
        if not identity["byte_identical"]:
            raise ToolError("IDENTITY_FAILED", "零编辑归档与源不一致")
        identity_path.unlink()
        report = {
            "status": "pass", "dialect": DIALECT["engine_id"],
            "archive_sha256": src_archive_hash,
            "source_hashes": analysis["source_hashes"],
            "scene_count": len(analysis["files"]),
            "text_scenes": len(analysis["by_file"]),
            "body_entries": len(analysis["bindings"]),
            "name_entries": sum(bool(e["speaker"]) for e in analysis["bindings"].values()),
            "tag_counts": dict(sorted((Counter(e["tag"] for e in analysis["bindings"].values())
                                       + Counter({"name": sum(bool(e["speaker"]) for e in
                                                              analysis["bindings"].values())})).items())),
            "tag_source_counts": {
                "structural": sum(bool(e["speaker"]) for e in analysis["bindings"].values()),
                "anchor": len(analysis["bindings"]), "heuristic": 0, "unresolved": 0},
            "byte_coverage": 1.0,
            "structural_coverage": sum(
                c["tier_coverage"]["T1"] + c["tier_coverage"]["T2"] for c in certs
            ) / sum(c["source_size"] for c in certs),
            "tier_coverage": {
                tier: sum(c["tier_coverage"][tier] for c in certs)
                for tier in ("T0", "T1", "T2", "T3", "T4")},
            "min_tier": "T0", "instruction_coverage": 0.0,
            "roundtrip_identity": True,
            "runtime_validation": "not_verified", "cross_game_validation": "not_verified",
            "projections": {"texts": texts, "asm": asm},
            "spt_shapes": {f"opcode={a},kind={b}": count
                           for (a, b), count in sorted(analysis["shape"].items())},
        }
        manifest = {
            "dialect": DIALECT["engine_id"], "data": str(data),
            "archive": str(archive), "archive_sha256": src_archive_hash,
            "source_hashes": analysis["source_hashes"],
            "source_encoding": source_encoding, "target_encoding": target_encoding,
            "texts": texts, "asm": asm,
            "scenes": {name: analysis["source_identities"][name]
                       for name in sorted(analysis["source_identities"])},
        }
        (stage / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (stage / "_work" / "reports" / "coverage_certificate.json").write_text(
            json.dumps(certs, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        cert_dir = stage / "_work" / "reports" / "coverage"
        cert_dir.mkdir()
        for cert in certs:
            (cert_dir / (cert["source"] + ".json")).write_text(
                json.dumps(cert, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (stage / "_work" / "reports" / "extract_report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (stage / "_work" / "reports" / "rule_hits.json").write_text(
            json.dumps({"choice": report["tag_counts"].get("choice", 0),
                        "name": report["name_entries"],
                        "message": report["tag_counts"]["msg"]},
                       ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (stage / "_work" / "reports" / "window_hits.json").write_text(
            json.dumps({"fixed_lookahead_windows": [], "hits": 0},
                       ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if with_ir:
            _optional_ir(stage, analysis, certs)
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
    return report


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", nargs="?", type=Path, help="data directory or data.fpk")
    p.add_argument("--data", type=Path, help="same as positional source")
    p.add_argument("-o", "--output", type=Path)
    p.add_argument("--texts", action="store_true")
    p.add_argument("--asm", action="store_true")
    p.add_argument("--with-ir", action="store_true")
    p.add_argument("--overwrite", action="store_true",
                   help="save old output to a timestamped sibling backup")
    p.add_argument("--source-encoding", default=DIALECT["source_encoding"])
    p.add_argument("--target-encoding", default=DIALECT["target_encoding"])
    args = p.parse_args(argv)
    if args.data is None and args.source is None:
        p.error("provide source data directory or data.fpk")
    try:
        report = export(args.data or args.source, args.output,
                        texts=args.texts or not args.asm, asm=args.asm,
                        with_ir=args.with_ir, source_encoding=args.source_encoding,
                        target_encoding=args.target_encoding, overwrite=args.overwrite)
    except ToolError as exc:
        print(f"{exc}", file=__import__("sys").stderr)
        return 1
    except (ValueError, OSError, UnicodeError) as exc:
        print(f"FORMAT_ERROR: {exc}", file=__import__("sys").stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
