from __future__ import annotations

from pathlib import Path
from typing import Any

from .profiles import load_profile
from .workflows.scenario_workflow import export_scenario_split_command, import_scenario_split_command
from .workflows.rebuild_workflow import (
    rebuild_auto_command as _rebuild_auto_command,
    rebuild_inplace_command as _rebuild_inplace_command,
    rebuild_lossless_command as _rebuild_lossless_command,
    rebuild_relocate_command as _rebuild_relocate_command,
    rebuild_with_pointer_table_command as _rebuild_with_pointer_table_command,
    auto_find_anchor_idx as _auto_find_anchor_idx,
)
from .workflows.translation_workflow import (
    export_translation_command,
    import_translation_command,
)
from .workflows.dump_workflow import dump_command as modular_dump_command


def dump_command(
    script_path: Path,
    text_path: Path,
    out_dir: Path,
    *,
    text_codec: str = "cp932",
    profile_name: str = "classic-softpal",
):
    profile = load_profile(profile_name)
    result = modular_dump_command(
        script_path,
        text_path,
        out_dir,
        profile=profile,
        text_codec=text_codec,
    )
    return result.manifest


def rebuild_lossless_command(
    dump_dir: Path,
    out_dir: Path,
    *,
    encrypt_output: bool = False,
    replace_plain_with_encrypted: bool = False,
):
    return _rebuild_lossless_command(
        dump_dir,
        out_dir,
        encrypt_output=encrypt_output,
        replace_plain_with_encrypted=replace_plain_with_encrypted,
    )


def rebuild_inplace_command(
    dump_dir: Path,
    out_dir: Path,
    *,
    edited_encoding: str = "cp932",
    encrypt_output: bool = False,
    replace_plain_with_encrypted: bool = False,
):
    return _rebuild_inplace_command(
        dump_dir,
        out_dir,
        edited_encoding=edited_encoding,
        encrypt_output=encrypt_output,
        replace_plain_with_encrypted=replace_plain_with_encrypted,
    )


def rebuild_relocate_command(
    dump_dir: Path,
    out_dir: Path,
    *,
    edited_encoding: str,
    encrypt_output: bool = False,
    replace_plain_with_encrypted: bool = False,
    audit_log: bool = False,
):
    return _rebuild_relocate_command(
        dump_dir,
        out_dir,
        edited_encoding=edited_encoding,
        encrypt_output=encrypt_output,
        replace_plain_with_encrypted=replace_plain_with_encrypted,
        audit_log=audit_log,
    )


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
):
    return _rebuild_with_pointer_table_command(
        dump_dir,
        script_path,
        text_path,
        out_dir,
        edited_encoding=edited_encoding,
        encrypt_output=encrypt_output,
        replace_plain_with_encrypted=replace_plain_with_encrypted,
        start_idx=start_idx,
        script_scan_start=script_scan_start,
        audit_log=audit_log,
    )


def rebuild_auto_command(
    dump_dir: Path,
    script_path: Path,
    text_path: Path,
    out_dir: Path,
    *,
    edited_encoding: str,
    encrypt_output: bool = False,
    replace_plain_with_encrypted: bool = False,
    audit_log: bool = False,
):
    return _rebuild_auto_command(
        dump_dir,
        out_dir,
        script_path=script_path,
        text_path=text_path,
        edited_encoding=edited_encoding,
        encrypt_output=encrypt_output,
        replace_plain_with_encrypted=replace_plain_with_encrypted,
        audit_log=audit_log,
    )


def normalize_idx_range(
    idx_start: int | None,
    idx_end: int | None,
):
    from .io.compat_text import normalize_idx_range as _normalize_idx_range

    return _normalize_idx_range(idx_start, idx_end)


def summary_command(dump_dir: Path) -> dict[str, Any]:
    from .workflows.summary_workflow import summary_command as _summary_command

    return _summary_command(dump_dir)

def auto_find_anchor_idx(script_path: Path, text_path: Path, start_idx: int = 0) -> tuple[int, int]:
    from .engine.text_dat_parser import load_text_dat_auto
    from .profiles import load_profile
    
    with open(script_path, "rb") as f:
        script_data = f.read()
    
    profile = load_profile("classic-softpal")
    archive = load_text_dat_auto(text_path, profile)
    
    idx, pos = _auto_find_anchor_idx(archive.normalized_data, script_data, start_idx=start_idx)
    return idx, pos
