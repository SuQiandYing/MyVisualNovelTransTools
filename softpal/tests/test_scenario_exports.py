from __future__ import annotations

import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path


TOOL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_ROOT))

from softpal_roundtrip.io.compat_text import read_text_auto
from softpal_roundtrip.io.json_io import jsonl_dump, load_jsonl
from softpal_roundtrip.io.translation_workflow_support import (
    annotate_scenario_export_tags,
    build_translate_blocks,
    build_translation_header,
    export_tag_for_row,
)
from softpal_roundtrip.profiles.classic_softpal import ClassicSoftPalProfile
from softpal_roundtrip.workflows.dump_workflow import dump_command
from softpal_roundtrip.workflows.rebuild_workflow import rebuild_lossless_command
from softpal_roundtrip.workflows.scenario_workflow import (
    export_scenario_split_command,
    import_scenario_split_command,
)
from softpal_roundtrip.workflows.translation_workflow import (
    export_translation_command,
    import_translation_command,
)


INTERNAL_TAIL = (
    "eyecatch_ST%02d",
    "roll_ST%02d_1",
    "roll_ST%02d_2",
    "roll_ST%02d_3",
    "roll_ST%02d_4",
    "StaffRoll(%d) START",
    "StaffRoll(%d) END",
)


class ScenarioExportTests(unittest.TestCase):
    def setUp(self) -> None:
        entries = [
            ("config", "Sce5_11"),
            ("msg", "「Ready %02d」"),
            ("name", "エマ"),
            ("asset", "background.bin"),
            ("choice", "Continue"),
            ("ui", "Save"),
            ("display", "Episode %02d"),
            ("system", "Proceed?"),
            ("chapter_title", "Chapter 2"),
            ("label_text", "Branch A"),
            ("msg", "roll_ST%02d_1"),
            ("misc", "Yes."),
            ("font", "Example Font"),
            ("config", "control_id"),
            ("unused", "orphan"),
            ("symbol", "---"),
            ("kana", "あ"),
            ("label_internal", "#subroutine"),
            ("misc", "unknown_internal"),
        ] + [("debug", text) for text in INTERNAL_TAIL]
        self.rows = [
            {
                "idx": idx,
                "order": idx,
                "entry_offset": 0x100 + idx * 0x40,
                "entry_offset_hex": f"0x{0x100 + idx * 0x40:08X}",
                "raw_text_hex": text.encode("cp932").hex(),
                "original_text": text,
                "text": text,
                "export_tag": tag,
                "ref_count": 1,
                "direct_call_ids_hex": [],
            }
            for idx, (tag, text) in enumerate(entries)
        ]
        self.rows[0]["direct_call_ids_hex"] = ["0x000F0002"]
        for row in self.rows[-7:-2]:
            row["direct_call_ids_hex"] = ["0x00120009"]
        for row in self.rows[-2:]:
            row["direct_call_ids_hex"] = ["0x000F0004"]
        self.messages = [self.message(1, 2), self.message(10), self.message(11)]
        self.visible_idxs = {0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11}

    def message(self, text_idx: int, name_idx: int | None = None) -> dict:
        return {
            "text_idx": text_idx,
            "name_idx": name_idx,
            "text": self.rows[text_idx]["original_text"],
            "name": None if name_idx is None else self.rows[name_idx]["original_text"],
            "kind": "narration" if name_idx is None else "spoken",
            "call_offset_hex": f"0x{0x200 + text_idx * 0x40:08X}",
            "line_id_hex": "0x00000001",
        }

    def make_dump(self, root: Path) -> Path:
        dump = root / "dump"
        dump.mkdir()
        jsonl_dump(dump / "text_entries.jsonl", self.rows)
        jsonl_dump(dump / "messages.jsonl", self.messages)
        return dump

    def exported_idxs(self, content: str) -> set[int]:
        return {int(line.split("○")[1]) for line in content.splitlines() if line.startswith("○")}

    def legacy_file(self, path: Path) -> None:
        # These are the exact old tags for this fixture, including its UI rows.
        legacy_rows = [dict(row) for row in self.rows]
        for row in legacy_rows[1:]:
            if row["export_tag"] not in {"name", "choice", "msg"}:
                row["scenario_export_tag"] = "msg"
        content = "\n".join(build_translation_header(None, None) + build_translate_blocks(legacy_rows, self.messages))
        path.write_text(content, encoding="utf-8", newline="\n")

    def test_scene_export_filters_internal_rows_and_keeps_visible_formatted_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dump = self.make_dump(root)
            out = root / "scenes"
            report = export_scenario_split_command(dump, out, file_encoding="utf-8")
            content = read_text_auto(out / "Sce5_11.txt")
            self.assertEqual(self.exported_idxs(content), self.visible_idxs)
            self.assertIn("○00000010○msg○roll_ST%02d_1", content)
            for tag, text in (("choice", "Continue"), ("ui", "Save"), ("display", "Episode %02d"), ("system", "Proceed?")):
                self.assertIn(f"○{tag}○{text}", content)
            self.assertEqual(report["excluded_internal_rows"], len(self.rows) - len(self.visible_idxs))

    def test_full_export_preserves_internal_rows_and_their_tags(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dump = self.make_dump(root)
            path = root / "translate_dump.txt"
            report = export_translation_command(dump, path, file_encoding="utf-8")
            content = read_text_auto(path)
            self.assertEqual(report["rows"], len(self.rows))
            for row in self.rows[-7:]:
                self.assertIn(f"○{row['idx']:08d}○debug○{row['original_text']}", content)
            self.assertIn("○00000005○ui○Save", content)

    def test_annotation_uses_message_membership_and_removes_stale_promotions(self) -> None:
        self.rows[2]["export_tag"] = "config"
        self.rows[10]["export_tag"] = "debug"
        self.rows[-7]["scenario_export_tag"] = "msg"
        annotated = annotate_scenario_export_tags(self.rows, self.messages)
        self.assertEqual(export_tag_for_row(annotated[2]), "name")
        self.assertEqual(export_tag_for_row(annotated[10]), "msg")
        self.assertEqual(export_tag_for_row(annotated[11]), "msg")
        self.assertEqual(export_tag_for_row(annotated[-7]), "debug")
        self.assertEqual(export_tag_for_row(annotated[3]), "asset")

    def test_scene_import_changes_visible_text_and_preserves_omitted_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dump = self.make_dump(root)
            scenes = root / "scenes"
            export_scenario_split_command(dump, scenes, file_encoding="utf-8")
            path = scenes / "Sce5_11.txt"
            content = read_text_auto(path).replace("●00000001●msg●「Ready %02d」", "●00000001●msg●「準備 %02d」")
            path.write_text(content, encoding="utf-8", newline="\n")
            report = import_scenario_split_command(dump, scenes)
            imported = load_jsonl(dump / "text_entries.jsonl")
            self.assertEqual(imported[1]["text"], "「準備 %02d」")
            self.assertEqual(report["updated_idxs"], len(self.visible_idxs))
            for row, original in zip(imported, self.rows):
                if int(row["idx"]) not in self.visible_idxs:
                    self.assertEqual(row, original)

    def test_legacy_exports_import_without_changing_internal_classification(self) -> None:
        for scene_mode in (False, True):
            with self.subTest(scene_mode=scene_mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                dump = self.make_dump(root)
                scenes = root / "scenes"
                scenes.mkdir()
                path = scenes / "Sce5_11.txt"
                self.legacy_file(path)
                content = read_text_auto(path).replace("●00000001●msg●「Ready %02d」", "●00000001●msg●「準備 %02d」")
                path.write_text(content, encoding="utf-8", newline="\n")
                report = import_scenario_split_command(dump, scenes) if scene_mode else import_translation_command(dump, path)
                self.assertGreater(report["legacy_tag_rows"], 0)
                imported = load_jsonl(dump / "text_entries.jsonl")
                self.assertEqual(imported[1]["text"], "「準備 %02d」")
                self.assertEqual([row["export_tag"] for row in imported], [row["export_tag"] for row in self.rows])
                self.assertEqual([row["raw_text_hex"] for row in imported], [row["raw_text_hex"] for row in self.rows])

    def test_legacy_compatibility_rejects_other_tags_and_modified_originals(self) -> None:
        for scene_mode in (False, True):
            for bad_original in (False, True):
                with self.subTest(scene_mode=scene_mode, bad_original=bad_original), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    dump = self.make_dump(root)
                    before = (dump / "text_entries.jsonl").read_bytes()
                    scenes = root / "scenes"
                    scenes.mkdir()
                    path = scenes / "Sce5_11.txt"
                    self.legacy_file(path)
                    content = read_text_auto(path)
                    idx = len(self.rows) - 7
                    if bad_original:
                        content = content.replace(f"○{idx:08d}○msg○eyecatch_ST%02d", f"○{idx:08d}○msg○wrong_original")
                    else:
                        content = content.replace(f"{idx:08d}○msg○", f"{idx:08d}○name○").replace(f"{idx:08d}●msg●", f"{idx:08d}●name●")
                    path.write_text(content, encoding="utf-8", newline="\n")
                    with self.assertRaisesRegex(ValueError, "原文|标签不匹配"):
                        if scene_mode:
                            import_scenario_split_command(dump, scenes)
                        else:
                            import_translation_command(dump, path)
                    self.assertEqual((dump / "text_entries.jsonl").read_bytes(), before)

    def test_filtered_scene_zero_edit_rebuild_keeps_all_dat_and_script_bytes(self) -> None:
        profile = ClassicSoftPalProfile()
        instructions = profile.get_instruction_set()
        texts = ("Sce5_11", "Ready %02d", "エマ") + INTERNAL_TAIL
        text_data = b"$TEXT_LIST__" + struct.pack("<I", len(texts))
        offsets = []
        for idx, text in enumerate(texts):
            offsets.append(len(text_data))
            text_data += struct.pack("<I", idx) + text.encode("cp932") + b"\x00"
        words = []

        def call(arguments: list[int], call_id: int) -> None:
            for argument in arguments:
                words.extend([instructions.push_immediate_opcode, argument])
            words.extend([instructions.call_opcode, call_id, 0])

        call([offsets[0]], 0x000F0002)
        call([0, offsets[1], offsets[2], 100], 0x00020002)
        for offset in offsets[3:8]:
            call([offset, 1], 0x00120009)
        for offset in offsets[8:]:
            call([offset], 0x000F0004)
        script_data = struct.pack(f"<{len(words)}I", *words)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script_path, text_path = root / "SCRIPT.SRC", root / "TEXT.DAT"
            script_path.write_bytes(script_data)
            text_path.write_bytes(text_data)
            dump, scenes = root / "dump", root / "scenes"
            dump_command(script_path, text_path, dump, profile=profile)
            export_scenario_split_command(dump, scenes, file_encoding="utf-8")
            self.assertEqual(self.exported_idxs(read_text_auto(scenes / "Sce5_11.txt")), {0, 1, 2})
            import_scenario_split_command(dump, scenes)
            rebuilt = root / "rebuilt"
            rebuild_lossless_command(dump, rebuilt)
            self.assertEqual((rebuilt / "SCRIPT.SRC").read_bytes(), script_data)
            self.assertEqual((rebuilt / "TEXT.DAT").read_bytes(), text_data)

    def test_optional_scene_corpus_excludes_reported_tail(self) -> None:
        source_directory = os.environ.get("SOFTPAL_TEST_SCENE_CORPUS")
        if not source_directory:
            self.skipTest("Set SOFTPAL_TEST_SCENE_CORPUS to run the optional scene check")
        source = Path(source_directory)
        with tempfile.TemporaryDirectory() as directory:
            scenes = Path(directory)
            report = export_scenario_split_command(source / "disasm_out", scenes, file_encoding="utf-8")
            content = read_text_auto(scenes / "Sce5_11.txt")
            indexes = self.exported_idxs(content)
            self.assertEqual(max(indexes), 54833)
            self.assertTrue(set(range(54834, 54841)).isdisjoint(indexes))
            # Two internal branch identifiers also occur inside earlier scenes.
            self.assertEqual(report["excluded_internal_rows"], 9)
            self.assertEqual(report["files_written"], 116)


if __name__ == "__main__":
    unittest.main()
