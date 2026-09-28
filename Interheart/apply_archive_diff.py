#!/usr/bin/env python3
"""Apply a bounded FPK entry-replacement patch against a verified source."""

import argparse
import base64
import json
from pathlib import Path
import tempfile

from fpk_repack import Archive, build, sha256


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--diff", type=Path, required=True)
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    patch = json.loads(args.diff.read_text(encoding="utf-8"))
    source = Archive(args.archive)
    if patch["format"] != "interheart-fpk-entry-diff/1":
        raise ValueError("unknown patch format")
    if sha256(source.data) != patch["source_sha256"]:
        raise ValueError("source archive hash mismatch")
    indexed = {entry[0]: entry for entry in source.entries}
    with tempfile.TemporaryDirectory(prefix="fpk-overlay-") as temporary:
        overlay = Path(temporary)
        seen = set()
        for change in patch["changes"]:
            name = change["name"]
            if name in seen or name not in indexed or "/" in name or "\\" in name:
                raise ValueError(f"invalid/duplicate entry name: {name}")
            seen.add(name)
            if sha256(source.decoded(indexed[name])) != change["original_sha256"]:
                raise ValueError(f"entry hash mismatch: {name}")
            payload = base64.b64decode(change["replacement_base64"], validate=True)
            (overlay / name).write_bytes(payload)
        report = build(args.archive, args.input, overlay, args.output)
    if report["output_sha256"] != patch["modified_sha256"]:
        Path(args.output).unlink()
        raise ValueError("rebuilt archive differs from patch target")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
