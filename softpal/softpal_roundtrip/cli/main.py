from __future__ import annotations

import argparse
import json
from pathlib import Path

from .. import (
    dump_command,
    export_scenario_split_command,
    export_translation_command,
    import_scenario_split_command,
    import_translation_command,
    rebuild_auto_command,
    rebuild_inplace_command,
    rebuild_lossless_command,
    rebuild_relocate_command,
    rebuild_with_pointer_table_command,
    summary_command,
)
from ..gui import main as gui_main
from ..profiles import PROFILE_REGISTRY


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Modular SoftPal SCRIPT.SRC / TEXT.DAT round-trip toolkit"
    )
    parser.add_argument(
        "--profile",
        default="classic-softpal",
        choices=sorted(PROFILE_REGISTRY),
        help="Game profile / adapter to inject into the workflow",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    dump_parser = subparsers.add_parser(
        "dump",
        help="Parse SCRIPT.SRC and TEXT.DAT through the selected game profile",
    )
    dump_parser.add_argument("--script", default=Path("SCRIPT.SRC"), type=Path)
    dump_parser.add_argument("--text", default=Path("TEXT.DAT"), type=Path)
    dump_parser.add_argument("--out", default=Path("disasm_out"), type=Path)
    dump_parser.add_argument(
        "--text-codec",
        default=None,
        help="Override the text codec exposed by the selected profile",
    )

    rebuild_lossless = subparsers.add_parser("rebuild-lossless")
    rebuild_lossless.add_argument("--dump", default=Path("disasm_out"), type=Path)
    rebuild_lossless.add_argument("--out", default=Path("rebuild_lossless"), type=Path)
    rebuild_lossless.add_argument("--encrypt-output", action="store_true")
    rebuild_lossless.add_argument("--replace-plain-with-encrypted", action="store_true")

    rebuild_inplace = subparsers.add_parser("rebuild-inplace")
    rebuild_inplace.add_argument("--dump", default=Path("disasm_out"), type=Path)
    rebuild_inplace.add_argument("--out", default=Path("rebuild_inplace"), type=Path)
    rebuild_inplace.add_argument("--edited-encoding", default="cp932")
    rebuild_inplace.add_argument("--encrypt-output", action="store_true")
    rebuild_inplace.add_argument("--replace-plain-with-encrypted", action="store_true")

    rebuild_relocate = subparsers.add_parser("rebuild-relocate")
    rebuild_relocate.add_argument("--dump", default=Path("disasm_out"), type=Path)
    rebuild_relocate.add_argument("--out", default=Path("rebuild_relocate"), type=Path)
    rebuild_relocate.add_argument("--edited-encoding", default="cp932")
    rebuild_relocate.add_argument("--encrypt-output", action="store_true")
    rebuild_relocate.add_argument("--replace-plain-with-encrypted", action="store_true")
    rebuild_relocate.add_argument("--audit-log", action="store_true", help="Write detailed reference and relocation logs")

    rebuild_pointer_table = subparsers.add_parser("rebuild-pointer-table")
    rebuild_pointer_table.add_argument("--dump", default=Path("disasm_out"), type=Path)
    rebuild_pointer_table.add_argument("--script", default=Path("SCRIPT.SRC"), type=Path)
    rebuild_pointer_table.add_argument("--text", default=Path("TEXT.DAT"), type=Path)
    rebuild_pointer_table.add_argument("--out", default=Path("rebuild_relocate"), type=Path)
    rebuild_pointer_table.add_argument("--edited-encoding", default="cp932")
    rebuild_pointer_table.add_argument("--encrypt-output", action="store_true")
    rebuild_pointer_table.add_argument("--replace-plain-with-encrypted", action="store_true")
    rebuild_pointer_table.add_argument("--audit-log", action="store_true", help="Write detailed reference and relocation logs")

    rebuild_auto = subparsers.add_parser("rebuild-auto")
    rebuild_auto.add_argument("--dump", default=Path("disasm_out"), type=Path)
    rebuild_auto.add_argument("--script", default=Path("SCRIPT.SRC"), type=Path)
    rebuild_auto.add_argument("--text", default=Path("TEXT.DAT"), type=Path)
    rebuild_auto.add_argument("--out", default=Path("rebuild_auto"), type=Path)
    rebuild_auto.add_argument("--edited-encoding", default="cp932")
    rebuild_auto.add_argument("--encrypt-output", action="store_true")
    rebuild_auto.add_argument("--replace-plain-with-encrypted", action="store_true")
    rebuild_auto.add_argument("--audit-log", action="store_true", help="Write detailed logs when a relocation strategy is selected")

    export_translation = subparsers.add_parser("export-translation")
    export_translation.add_argument("--dump", default=Path("disasm_out"), type=Path)
    export_translation.add_argument("--out", default=Path("translate_dump.txt"), type=Path)
    export_translation.add_argument("--file-encoding", default="utf-16")
    export_translation.add_argument("--idx-start", type=int, default=None)
    export_translation.add_argument("--idx-end", type=int, default=None)

    import_translation = subparsers.add_parser("import-translation")
    import_translation.add_argument("--dump", default=Path("disasm_out"), type=Path)
    import_translation.add_argument("--infile", default=Path("translate_dump.txt"), type=Path)
    import_translation.add_argument("--idx-start", type=int, default=None)
    import_translation.add_argument("--idx-end", type=int, default=None)

    export_scenarios = subparsers.add_parser("export-scenarios")
    export_scenarios.add_argument("--dump", default=Path("disasm_out"), type=Path)
    export_scenarios.add_argument("--out", default=Path("scenario_txt"), type=Path)
    export_scenarios.add_argument("--file-encoding", default="utf-16")

    import_scenarios = subparsers.add_parser("import-scenarios")
    import_scenarios.add_argument("--dump", default=Path("disasm_out"), type=Path)
    import_scenarios.add_argument("--scenario-dir", default=Path("scenario_txt"), type=Path)

    summary = subparsers.add_parser("summary")
    summary.add_argument("--dump", default=Path("disasm_out"), type=Path)

    subparsers.add_parser("gui", help="Launch the Tkinter GUI")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "dump":
        payload = dump_command(
            args.script,
            args.text,
            args.out,
            text_codec=args.text_codec,
            profile_name=args.profile,
        )
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    if args.command == "rebuild-lossless":
        print(json.dumps(rebuild_lossless_command(args.dump, args.out, encrypt_output=args.encrypt_output, replace_plain_with_encrypted=args.replace_plain_with_encrypted), ensure_ascii=False, indent=2))
        return
    if args.command == "rebuild-inplace":
        print(json.dumps(rebuild_inplace_command(args.dump, args.out, edited_encoding=args.edited_encoding, encrypt_output=args.encrypt_output, replace_plain_with_encrypted=args.replace_plain_with_encrypted), ensure_ascii=False, indent=2))
        return
    if args.command == "rebuild-relocate":
        print(json.dumps(rebuild_relocate_command(args.dump, args.out, edited_encoding=args.edited_encoding, encrypt_output=args.encrypt_output, replace_plain_with_encrypted=args.replace_plain_with_encrypted, audit_log=args.audit_log), ensure_ascii=False, indent=2))
        return
    if args.command == "rebuild-pointer-table":
        print(json.dumps(rebuild_with_pointer_table_command(args.dump, args.script, args.text, args.out, edited_encoding=args.edited_encoding, encrypt_output=args.encrypt_output, replace_plain_with_encrypted=args.replace_plain_with_encrypted, audit_log=args.audit_log), ensure_ascii=False, indent=2))
        return
    if args.command == "rebuild-auto":
        print(json.dumps(rebuild_auto_command(args.dump, args.script, args.text, args.out, edited_encoding=args.edited_encoding, encrypt_output=args.encrypt_output, replace_plain_with_encrypted=args.replace_plain_with_encrypted, audit_log=args.audit_log), ensure_ascii=False, indent=2))
        return
    if args.command == "export-translation":
        print(json.dumps(export_translation_command(args.dump, args.out, file_encoding=args.file_encoding, idx_start=args.idx_start, idx_end=args.idx_end), ensure_ascii=False, indent=2))
        return
    if args.command == "import-translation":
        print(json.dumps(import_translation_command(args.dump, args.infile, idx_start=args.idx_start, idx_end=args.idx_end), ensure_ascii=False, indent=2))
        return
    if args.command == "export-scenarios":
        print(json.dumps(export_scenario_split_command(args.dump, args.out, file_encoding=args.file_encoding), ensure_ascii=False, indent=2))
        return
    if args.command == "import-scenarios":
        print(json.dumps(import_scenario_split_command(args.dump, args.scenario_dir), ensure_ascii=False, indent=2))
        return
    if args.command == "summary":
        print(json.dumps(summary_command(args.dump), ensure_ascii=False, indent=2))
        return
    if args.command == "gui":
        gui_main()
        return
    parser.error(f"unknown command: {args.command}")


if __name__ == "__main__":
    main()
