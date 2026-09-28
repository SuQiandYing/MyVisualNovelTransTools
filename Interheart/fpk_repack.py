#!/usr/bin/env python3
"""Repack this game's encrypted-index FPK without changing the source archive.

Format based on GARbro ArcFormats/Interheart/ArcFPK.cs (MIT). An unchanged
archive entry keeps its original stored/compressed bytes. Changed entries use
valid ZLC2 literal blocks, not an unproven approximation of the original
compressor's token choices.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
from opcodelist import DIALECT


RECORD_SIZE = DIALECT["fpk"]["record_size"]
NAME_SIZE = DIALECT["fpk"]["name_size"]
MAX_DECOMPRESSED = 256 * 1024 * 1024
ZLC2_MAGIC = DIALECT["fpk"]["zlc2_magic"].encode("ascii")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def decode_zlc2(blob):
    for layer in range(16):
        if len(blob) <= 8 or blob[:4] != ZLC2_MAGIC:
            return blob
        expected = struct.unpack_from("<I", blob, 4)[0]
        if expected > MAX_DECOMPRESSED:
            raise ValueError("ZLC2 output exceeds safety limit")
        result = bytearray()
        pos = 8
        while pos < len(blob) and len(result) < expected:
            control = blob[pos]
            pos += 1
            for mask in (128, 64, 32, 16, 8, 4, 2, 1):
                if pos >= len(blob) or len(result) >= expected:
                    break
                if control & mask:
                    if pos + 2 > len(blob):
                        raise ValueError("truncated ZLC2 back-reference")
                    distance = blob[pos] | ((blob[pos + 1] & DIALECT["fpk"]["backref_high_mask"]) << 4)
                    count = (blob[pos + 1] & 15) + 3
                    pos += 2
                    if distance == 0:
                        distance = 4096
                    if distance > len(result):
                        raise ValueError("ZLC2 back-reference before beginning")
                    for _ in range(min(count, expected - len(result))):
                        result.append(result[-distance])
                else:
                    result.append(blob[pos])
                    pos += 1
        if len(result) != expected:
            raise ValueError(f"truncated ZLC2 output: {len(result)} != {expected}")
        blob = bytes(result)
    raise ValueError("too many nested ZLC2 layers")


def encode_zlc2_literal(data):
    if len(data) > 0xFFFFFFFF:
        raise ValueError("ZLC2 length overflows 32 bits")
    out = bytearray(ZLC2_MAGIC + struct.pack("<I", len(data)))
    for pos in range(0, len(data), 8):
        out.append(0)  # MSB-first control flags; zero denotes eight literals.
        out.extend(data[pos:pos + 8])
    return bytes(out)


class Archive:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        b = self.data
        if len(b) < 12:
            raise ValueError("FPK archive too short")
        raw_count = struct.unpack_from("<I", b)[0]
        if not raw_count & DIALECT["fpk"]["encrypted_count_flag"]:
            raise ValueError("only this sample's encrypted-index FPK is supported")
        count = raw_count & DIALECT["fpk"]["count_mask"]
        if count == 0 or count > 100000:
            raise ValueError("invalid FPK entry count")
        self.index_offset = struct.unpack_from("<I", b, len(b) - 4)[0]
        self.key = b[-8:-4]
        index_end = self.index_offset + count * RECORD_SIZE
        if self.index_offset < 4 or index_end > len(b) - 8:
            raise ValueError("FPK index lies outside archive")
        cipher = b[self.index_offset:index_end]
        plain = bytes(c ^ self.key[i % 4] for i, c in enumerate(cipher))
        self.entries = []
        seen = set()
        spans = [(self.index_offset, index_end, "index"),
                 (len(b) - 8, len(b), "trailer")]
        for i in range(count):
            record = plain[i * RECORD_SIZE:(i + 1) * RECORD_SIZE]
            offset, size = struct.unpack_from("<II", record)
            name_bytes = record[8:8 + NAME_SIZE].split(b"\0", 1)[0]
            name = name_bytes.decode("cp932", "strict")
            if not name or name in (".", "..") or "/" in name or "\\" in name:
                raise ValueError(f"unsafe/empty FPK entry name {name!r}")
            if name.casefold() in seen:
                raise ValueError(f"duplicate FPK entry {name!r}")
            seen.add(name.casefold())
            if offset < 4 or offset + size > len(b) - 8:
                raise ValueError(f"FPK entry outside archive: {name}")
            self.entries.append((name, offset, size, record))
            spans.append((offset, offset + size, name))
        spans.sort()
        for first, second in zip(spans, spans[1:]):
            if first[1] > second[0]:
                raise ValueError(f"overlapping FPK regions: {first[2]}, {second[2]}")

    def decoded(self, entry):
        _, offset, size, _ = entry
        return decode_zlc2(self.data[offset:offset + size])

    def identity_chunks(self):
        """Re-encode the parsed index while replaying unchanged stored blocks."""
        b = self.data
        count = len(self.entries)
        index_end = self.index_offset + count * RECORD_SIZE
        plain = b"".join(entry[3] for entry in self.entries)
        index = bytes(c ^ self.key[i % 4] for i, c in enumerate(plain))
        regions = [(0, 4, b[:4]), (self.index_offset, index_end, index),
                   (len(b) - 8, len(b),
                    self.key + struct.pack("<I", self.index_offset))]
        regions.extend((offset, offset + size, b[offset:offset + size])
                       for _, offset, size, _ in self.entries)
        cursor = 0
        for start, end, content in sorted(regions):
            if start != cursor or len(content) != end - start:
                raise ValueError(f"unowned/overlapping FPK bytes at {cursor}")
            yield content
            cursor = end
        if cursor != len(b):
            raise ValueError(f"unowned FPK trailer at {cursor}")


def build(archive, input_dir, overlay_dir, output):
    src = Archive(archive)
    inp = Path(input_dir)
    overlay = Path(overlay_dir) if overlay_dir else None
    expected = {entry[0] for entry in src.entries}
    actual = {p.name for p in inp.iterdir() if p.is_file()}
    if expected != actual:
        raise ValueError(f"input directory differs from FPK: missing="
                         f"{sorted(expected - actual)}, extra={sorted(actual - expected)}")
    if overlay:
        extras = {p.name for p in overlay.iterdir() if p.is_file()} - expected
        if extras:
            raise ValueError(f"unknown overlay entries: {sorted(extras)}")
    prepared = []
    changed = []
    for entry in src.entries:
        name, offset, size, record = entry
        candidate = overlay / name if overlay and (overlay / name).is_file() else inp / name
        replacement = candidate.read_bytes()
        if replacement == src.decoded(entry):
            stored = src.data[offset:offset + size]
        else:
            # GARbro only enters the decoder when stored length is > 8.
            stored = encode_zlc2_literal(replacement) if replacement else b""
            changed.append(name)
        prepared.append((name, record, stored, replacement))

    dest = Path(output)
    if dest.resolve() == src.path.resolve():
        raise ValueError("cannot overwrite source archive")
    if dest.exists():
        raise ValueError("output already exists")
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".fpk-", dir=dest.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            if not changed:
                for chunk in src.identity_chunks():
                    f.write(chunk)
            else:
                f.write(src.data[:4])
                records = []
                for name, record, stored, _ in prepared:
                    offset = f.tell()
                    if offset + len(stored) > 0xFFFFFFFF:
                        raise ValueError("FPK offset/size overflows 32 bits")
                    f.write(stored)
                    records.append(struct.pack("<II", offset, len(stored)) + record[8:])
                index_offset = f.tell()
                plain = b"".join(records)
                f.write(bytes(c ^ src.key[i % 4] for i, c in enumerate(plain)))
                f.write(src.key + struct.pack("<I", index_offset))
            f.flush()
            os.fsync(f.fileno())
        rebuilt = Archive(tmp)
        for (name, _, _, expected_bytes), actual_entry in zip(prepared, rebuilt.entries):
            if name != actual_entry[0] or expected_bytes != rebuilt.decoded(actual_entry):
                raise ValueError(f"rebuilt entry mismatch: {name}")
        if not changed and rebuilt.data != src.data:
            raise ValueError("identity rebuild is not byte-identical")
        os.replace(tmp, dest)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return {"archive": str(src.path.resolve()), "output": str(dest.resolve()),
            "source_sha256": sha256(src.data), "output_sha256": sha256(rebuilt.data),
            "entries_verified": len(prepared), "changed": changed,
            "byte_identical": rebuilt.data == src.data}


def verify(archive, input_dir):
    src = Archive(archive)
    inp = Path(input_dir)
    failures = []
    for entry in src.entries:
        name = entry[0]
        p = inp / name
        if not p.is_file() or p.read_bytes() != src.decoded(entry):
            failures.append(name)
    return {"archive": str(src.path.resolve()), "archive_sha256": sha256(src.data),
            "entries": len(src.entries), "mismatches": failures,
            "status": "pass" if not failures else "fail"}


def inspect(archive, entry_name):
    src = Archive(archive)
    matching = [entry for entry in src.entries if entry[0] == entry_name]
    if len(matching) != 1:
        raise ValueError(f"entry not found: {entry_name}")
    content = src.decoded(matching[0])
    return {"entry": entry_name, "length": len(content), "sha256": sha256(content)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("inspect")
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--entry", required=True)
    for cmd in ("verify", "build"):
        p = sub.add_parser(cmd)
        p.add_argument("--archive", type=Path, required=True)
        p.add_argument("--input", type=Path, required=True, help="full unpacked directory")
        if cmd == "build":
            p.add_argument("--overlay", type=Path, help="optional sparse edited entries")
            p.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "build":
        report = build(args.archive, args.input, args.overlay, args.output)
    elif args.command == "verify":
        report = verify(args.archive, args.input)
    else:
        report = inspect(args.archive, args.entry)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if report.get("status") == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
