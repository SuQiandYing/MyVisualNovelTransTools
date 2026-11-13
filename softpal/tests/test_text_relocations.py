from __future__ import annotations

import json
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace


TOOL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_ROOT))

from softpal_roundtrip.engine.text_dat_parser import load_text_dat_auto
from softpal_roundtrip.gui.actions import GuiActionsMixin
from softpal_roundtrip.io.json_io import jsonl_dump
from softpal_roundtrip.profiles.classic_softpal import ClassicSoftPalProfile
from softpal_roundtrip.workflows.dump_workflow import dump_command
from softpal_roundtrip.workflows.rebuild_workflow import (
    _commit_outputs,
    auto_find_anchor_idx,
    rebuild_auto_command,
    rebuild_relocate_command,
    rebuild_with_pointer_table_command,
)


PUSH = 0x1001F
CALL = 0x10017
MOVE = 0x10001


class TextRelocationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.profile = ClassicSoftPalProfile()
        self.original_texts = ["本編", "Ｈシーン１", "Ｈシーン２", "本文"]
        self.header = b"$TEXT_LIST__" + struct.pack("<I", len(self.original_texts))
        parts = [self.header]
        self.entry_offsets = []
        cursor = len(self.header)
        for idx, text in enumerate(self.original_texts):
            self.entry_offsets.append(cursor)
            entry = struct.pack("<I", idx) + text.encode("cp932") + b"\0"
            parts.append(entry)
            cursor += len(entry)
        self.text_data = b"".join(parts)
        self.words = list(struct.unpack("<3I", b"Sv20" + bytes(8))) + [0x10020, 0]
        self.menu_sites = []
        for offset in self.entry_offsets[:3]:
            self.menu_sites.append(self.append_call([0x40000000, offset], 0x60002)[1])
        self.last_site = self.append_call([self.entry_offsets[3]], 0xF0001)[0]
        self.repeat_site = self.append_call([0x40000000, self.entry_offsets[2]], 0x60002)[1]
        self.function_site = (len(self.words) + 1) * 4
        self.words += [0x1000B, self.entry_offsets[2]]
        self.coordinate_site = (len(self.words) + 2) * 4
        self.words += [MOVE, 0x40000003, self.entry_offsets[2]]
        # Sprite call parameters and message line numbers can equal text offsets.
        self.numeric_sites = self.append_call([0, 1, self.entry_offsets[2], 3, 4, 5, 6], 0x80003)
        self.message_sites = self.append_call([0, self.entry_offsets[3], 0x0FFFFFFF, self.entry_offsets[2]], 0x20002)
        self.script_data = struct.pack(f"<{len(self.words)}I", *self.words)
        self.script_path = self.root / "SCRIPT.SRC"
        self.text_path = self.root / "TEXT.DAT"
        self.script_path.write_bytes(self.script_data)
        self.text_path.write_bytes(self.text_data)
        self.dump_dir = self.root / "dump"
        artifacts = dump_command(self.script_path, self.text_path, self.dump_dir, profile=self.profile)
        self.rows = artifacts.text_rows

    def append_call(self, arguments: list[int], call_id: int) -> list[int]:
        sites = []
        for argument in arguments:
            sites.append((len(self.words) + 1) * 4)
            self.words += [PUSH, argument]
        self.words += [CALL, call_id, 0]
        return sites

    def redump_script(self) -> None:
        self.script_data = struct.pack(f"<{len(self.words)}I", *self.words)
        self.script_path.write_bytes(self.script_data)
        self.rows = dump_command(self.script_path, self.text_path, self.dump_dir, profile=self.profile).text_rows

    def rebuild(self, *, backend: str = "gui", start_idx: int = 0, scan_start: int = 0, **flags):
        jsonl_dump(self.dump_dir / "text_entries.jsonl", self.rows)
        output = self.root / f"out_{backend}"
        if backend == "gui":
            report = rebuild_with_pointer_table_command(
                self.dump_dir, self.script_path, self.text_path, output,
                edited_encoding="cp932", start_idx=start_idx,
                script_scan_start=scan_start, **flags,
            )
        else:
            report = rebuild_relocate_command(self.dump_dir, output, edited_encoding="cp932", **flags)
        script_data = (output / "SCRIPT.SRC").read_bytes()
        text = load_text_dat_auto(output / "TEXT.DAT", self.profile)
        return script_data, text, report

    @staticmethod
    def value(data: bytes, site: int) -> int:
        return struct.unpack_from("<I", data, site)[0]

    @staticmethod
    def displayed(data: bytes, reference: int) -> str:
        start = reference + 4
        end = data.index(b"\0", start)
        return data[start:end].decode("cp932")

    def test_shorter_preceding_translation_keeps_first_character_before_anchor(self) -> None:
        self.rows[1]["text"] = "Ｈ劇情１"
        self.rows[2]["text"] = "Ｈ劇情２"
        script, text, _ = self.rebuild(start_idx=3, scan_start=self.last_site)
        self.assertEqual(
            self.displayed(text.normalized_data, self.value(script, self.menu_sites[2])),
            "Ｈ劇情２",
        )
        self.assertEqual(self.value(script, self.menu_sites[2]), text.entries[2].entry_offset)

    def test_longer_preceding_translation_updates_all_shared_references(self) -> None:
        self.rows[1]["text"] = "Ｈ劇情第一章"
        script, text, _ = self.rebuild()
        expected = text.entries[2].entry_offset
        self.assertEqual(self.value(script, self.menu_sites[2]), expected)
        self.assertEqual(self.value(script, self.repeat_site), expected)
        self.assertEqual(self.displayed(text.normalized_data, expected), self.original_texts[2])

    def test_numeric_value_collisions_survive_both_backends(self) -> None:
        self.rows[1]["text"] = "Ｈ劇情１"
        for backend in ("gui", "cli"):
            with self.subTest(backend=backend):
                script, text, _ = self.rebuild(backend=backend)
                for site in (self.function_site, self.coordinate_site, self.numeric_sites[2], self.message_sites[3]):
                    self.assertEqual(self.value(script, site), self.entry_offsets[2], f"numeric collision at {site:#x}")
                self.assertEqual(self.value(script, self.message_sites[1]), text.entries[3].entry_offset)
                self.assertEqual(self.value(script, self.repeat_site), text.entries[2].entry_offset)

    def test_auto_anchor_uses_parsed_entry_start_and_structural_reference(self) -> None:
        idx, site = auto_find_anchor_idx(self.text_data, self.script_data)
        self.assertEqual(idx, 0)
        self.assertEqual(site, self.menu_sites[0])
        self.assertEqual(self.value(self.script_data, site), self.entry_offsets[idx])
        self.assertEqual(site % 4, 0)

    def test_zero_edit_rebuild_is_byte_identical(self) -> None:
        for backend in ("gui", "cli"):
            with self.subTest(backend=backend):
                script, text, _ = self.rebuild(backend=backend)
                self.assertEqual(script, self.script_data)
                self.assertEqual(text.normalized_data, self.text_data)

    def test_encryption_preserves_text_and_correct_menu_reference(self) -> None:
        self.rows[1]["text"] = "Ｈ劇情１"
        script, text, _ = self.rebuild(start_idx=3, scan_start=self.last_site, encrypt_output=True, replace_plain_with_encrypted=True)
        self.assertTrue(text.was_encrypted)
        self.assertEqual(self.displayed(text.normalized_data, self.value(script, self.menu_sites[2])), self.original_texts[2])

    def test_variable_text_argument_relocates_the_literal_assignment(self) -> None:
        assignment_site = (len(self.words) + 2) * 4
        self.words += [MOVE, 0x40000003, self.entry_offsets[2], MOVE, 0x40000000, 0x40000003, PUSH, 0x40000000]
        self.words += [0x10008, 0x40000000, 0x40000000, PUSH, 0x40000000, CALL, 0x12003B, 0]
        self.redump_script()
        self.rows[1]["text"] = "Ｈ劇情１"
        script, text, _ = self.rebuild()
        self.assertEqual(self.value(script, assignment_site), text.entries[2].entry_offset)
        self.assertEqual(self.value(script, assignment_site + 12), 0x40000003)

    def test_printf_text_arguments_relocate_while_numeric_arguments_stay_unchanged(self) -> None:
        offset = self.entry_offsets[3]
        self.text_data = self.text_data[:offset + 4] + b"%d %t\0"
        self.text_path.write_bytes(self.text_data)
        arguments = [0x0FFFFFFF] * 6 + [self.entry_offsets[2], self.entry_offsets[2], offset, 0]
        sites = self.append_call(arguments, 0x120009)
        self.redump_script()
        self.rows[1]["text"] = "Ｈ劇情１"
        script, text, _ = self.rebuild()
        self.assertEqual(self.value(script, sites[6]), text.entries[2].entry_offset)
        self.assertEqual(self.value(script, sites[7]), self.entry_offsets[2])

    def test_unknown_reference_layout_fails_before_replacing_existing_outputs(self) -> None:
        self.words = [0x77770001 if value == 0x60002 else value for value in self.words]
        self.redump_script()
        self.rows[1]["text"] = "Ｈ劇情１"
        output = self.root / "out_gui"
        output.mkdir()
        (output / "SCRIPT.SRC").write_bytes(b"previous script")
        (output / "TEXT.DAT").write_bytes(b"previous text")
        with self.assertRaisesRegex(ValueError, "缺少已证明的引用"):
            self.rebuild()
        self.assertEqual((output / "SCRIPT.SRC").read_bytes(), b"previous script")
        self.assertEqual((output / "TEXT.DAT").read_bytes(), b"previous text")
        self.assertFalse((output / "rebuild_report.json").exists())

    def test_source_hash_mismatch_is_rejected(self) -> None:
        modified = bytearray(self.script_data)
        struct.pack_into("<I", modified, self.function_site, 999)
        self.script_path.write_bytes(modified)
        self.rows[1]["text"] = "Ｈ劇情１"
        with self.assertRaisesRegex(ValueError, "源哈希不一致"):
            self.rebuild()
        self.assertFalse((self.root / "out_gui").exists())

    def test_gui_saved_anchor_does_not_limit_relocation(self) -> None:
        self.rows[1]["text"] = "Ｈ劇情１"
        jsonl_dump(self.dump_dir / "text_entries.jsonl", self.rows)
        settings = SimpleNamespace(
            anchor_idx=SimpleNamespace(get=lambda: "7"),
            script_offset=SimpleNamespace(get=lambda: "0x276c"),
        )
        output = self.root / "out_gui_settings"
        label, report = GuiActionsMixin._run_selected_rebuild_backend(
            settings, self.dump_dir, self.script_path, self.text_path, output,
            edited_encoding="cp932", encrypt_output=False,
            replace_plain_with_encrypted=False,
        )
        script = (output / "SCRIPT.SRC").read_bytes()
        text = load_text_dat_auto(output / "TEXT.DAT", self.profile)
        self.assertEqual(self.value(script, self.menu_sites[2]), text.entries[2].entry_offset)
        self.assertEqual(label, "rebuild_verified_references")
        self.assertEqual(report["reference_scope"], "entire_script")

    def test_auto_backend_selects_verified_relocation_for_variable_length_text(self) -> None:
        self.rows[1]["text"] = "Ｈ劇情１"
        jsonl_dump(self.dump_dir / "text_entries.jsonl", self.rows)
        output = self.root / "out_auto"
        report = rebuild_auto_command(
            self.dump_dir, output, script_path=self.script_path, text_path=self.text_path,
            edited_encoding="cp932",
        )
        script = (output / "SCRIPT.SRC").read_bytes()
        text = load_text_dat_auto(output / "TEXT.DAT", self.profile)
        self.assertEqual(report["selected_strategy"], "relocate")
        self.assertEqual(len(report["auto_attempts"]), 3)
        self.assertEqual(self.value(script, self.repeat_site), text.entries[2].entry_offset)

    def test_partial_commit_error_restores_the_previous_output_pair(self) -> None:
        import os

        output = self.root / "out_rollback"
        output.mkdir()
        (output / "SCRIPT.SRC").write_bytes(b"previous script")
        (output / "TEXT.DAT").write_bytes(b"previous text")
        replace = os.replace
        calls = 0

        def fail_second_replace(source, destination):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("simulated TEXT.DAT replacement failure")
            return replace(source, destination)

        with patch("softpal_roundtrip.workflows.rebuild_workflow.os.replace", side_effect=fail_second_replace):
            with self.assertRaisesRegex(OSError, "simulated"):
                _commit_outputs(output, {"SCRIPT.SRC": b"new script", "TEXT.DAT": b"new text"})
        self.assertEqual((output / "SCRIPT.SRC").read_bytes(), b"previous script")
        self.assertEqual((output / "TEXT.DAT").read_bytes(), b"previous text")

    def test_optional_audit_logs_preserve_outputs_and_default_run_removes_stale_logs(self) -> None:
        import softpal_roundtrip as toolkit

        self.rows[1]["text"] = "Ｈ劇情１"
        jsonl_dump(self.dump_dir / "text_entries.jsonl", self.rows)
        output = self.root / "out_audit"
        report = toolkit.rebuild_with_pointer_table_command(
            self.dump_dir, self.script_path, self.text_path, output,
            edited_encoding="cp932", audit_log=True,
        )
        script = (output / "SCRIPT.SRC").read_bytes()
        text = (output / "TEXT.DAT").read_bytes()
        references = [json.loads(line) for line in (output / "reference_sites.jsonl").read_text(encoding="utf-8").splitlines()]
        relocations = [json.loads(line) for line in (output / "relocation_log.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(references), report["verified_reference_sites"])
        self.assertEqual(len(relocations), report["rewritten_script_words"])
        reference_by_site = {row["site_offset"]: row for row in references}
        for row in relocations:
            self.assertEqual(self.value(self.script_data, row["site_offset"]), row["old_offset"])
            self.assertEqual(self.value(script, row["site_offset"]), row["new_offset"])
            self.assertEqual(reference_by_site[row["site_offset"]]["text_idx"], row["text_idx"])
        (output / "keep.txt").write_bytes(b"user file")
        report = toolkit.rebuild_with_pointer_table_command(
            self.dump_dir, self.script_path, self.text_path, output, edited_encoding="cp932",
        )
        self.assertFalse(report["audit_log"])
        self.assertEqual((output / "SCRIPT.SRC").read_bytes(), script)
        self.assertEqual((output / "TEXT.DAT").read_bytes(), text)
        self.assertEqual((output / "keep.txt").read_bytes(), b"user file")
        self.assertFalse((output / "reference_sites.jsonl").exists())
        self.assertFalse((output / "relocation_log.jsonl").exists())

    def test_log_cleanup_failure_restores_previous_outputs_and_audit_logs(self) -> None:
        output = self.root / "out_log_rollback"
        output.mkdir()
        previous = {
            "SCRIPT.SRC": b"previous script", "TEXT.DAT": b"previous text",
            "reference_sites.jsonl": b"previous reference log",
            "relocation_log.jsonl": b"previous relocation log",
        }
        for name, data in previous.items():
            (output / name).write_bytes(data)
        unlink = Path.unlink

        def fail_last_log(path, *args, **kwargs):
            if path == output / "relocation_log.jsonl":
                raise OSError("simulated log cleanup failure")
            return unlink(path, *args, **kwargs)

        with patch.object(Path, "unlink", fail_last_log):
            with self.assertRaisesRegex(OSError, "simulated"):
                _commit_outputs(
                    output, {"SCRIPT.SRC": b"new script", "TEXT.DAT": b"new text"},
                    remove_names=("reference_sites.jsonl", "relocation_log.jsonl"),
                )
        for name, data in previous.items():
            self.assertEqual((output / name).read_bytes(), data)

    def test_cli_audit_flag_reaches_all_relocation_entry_points(self) -> None:
        self.rows[1]["text"] = "Ｈ劇情１"
        jsonl_dump(self.dump_dir / "text_entries.jsonl", self.rows)
        for command in ("rebuild-relocate", "rebuild-pointer-table", "rebuild-auto"):
            with self.subTest(command=command):
                output = self.root / command
                arguments = [
                    sys.executable, "-X", "utf8", "-B", "-m", "softpal_roundtrip", command,
                    "--dump", str(self.dump_dir), "--out", str(output), "--audit-log",
                ]
                if command != "rebuild-relocate":
                    arguments.extend(["--script", str(self.script_path), "--text", str(self.text_path)])
                result = subprocess.run(arguments, cwd=TOOL_ROOT, capture_output=True, text=True, encoding="utf-8", timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertTrue(report["audit_log"])
                self.assertEqual(report["validation"], "pass")
                self.assertTrue((output / "reference_sites.jsonl").is_file())
                self.assertTrue((output / "relocation_log.jsonl").is_file())
                script = (output / "SCRIPT.SRC").read_bytes()
                text = load_text_dat_auto(output / "TEXT.DAT", self.profile)
                self.assertEqual(self.value(script, self.repeat_site), text.entries[2].entry_offset)


if __name__ == "__main__":
    unittest.main()
