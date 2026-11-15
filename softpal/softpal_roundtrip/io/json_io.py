from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable


def json_dump(path: Path, payload: object) -> None:
    # surrogateescape preserves undecodable source bytes in memory. JSON's
    # Unicode escapes preserve those values without producing invalid UTF-8.
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8", errors="backslashreplace")


def jsonl_dump(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", errors="backslashreplace", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False))
            handle.write("\n")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows
