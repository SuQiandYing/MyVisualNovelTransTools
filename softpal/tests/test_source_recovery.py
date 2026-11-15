from __future__ import annotations

import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from softpal_roundtrip.crypto.softpal import softpal_decrypt_bytes, softpal_encrypt_bytes
from softpal_roundtrip.engine.script_parser import ParsedScript
from softpal_roundtrip.engine.text_dat_parser import load_text_dat_auto
from softpal_roundtrip.engine.text_references import find_text_reference_sites
from softpal_roundtrip.io.compat_text import read_text_auto
from softpal_roundtrip.io.json_io import jsonl_dump, load_jsonl
from softpal_roundtrip.profiles.classic_softpal import ClassicSoftPalProfile
from softpal_roundtrip.workflows.dump_workflow import dump_command
from softpal_roundtrip.workflows.rebuild_workflow import (
    rebuild_lossless_command,
    rebuild_with_pointer_table_command,
)
from softpal_roundtrip.workflows.scenario_workflow import (
    export_scenario_split_command,
    import_scenario_split_command,
)
from softpal_roundtrip.workflows.translation_workflow import (
    export_translation_command,
    import_translation_command,
)


class SourceRecoveryTests(unittest.TestCase):
    texts = (
        "共通00", "原文一。", "共通01_01", "「こんにちは」", "エマ",
        "「元気？」", "リリィ", "共通01_02", "「次の場面」", "エマ",
        "おまけ", "end_id",
    )
    pasted = (
        "共通00", "原文一を長く編集。", "共通01_01", "エマ「こんにちは」",
        "リリィ「元気？」", "共通01_02", "エマ「次の場面」", "おまけ", "end_id",
    )

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = self.root / "data"
        self.data.mkdir()
        self.profile = ClassicSoftPalProfile()
        self.original_text, offsets = self.make_dat(self.texts)
        words = list(struct.unpack("<3I", b"Sv20" + bytes(8))) + [0x10020, 0]
        self.message_sites = []

        def call(arguments, call_id):
            sites = []
            for value in arguments:
                sites.append((len(words) + 1) * 4)
                words.extend((0x1001F, value))
            words.extend((0x10017, call_id, 0))
            return sites

        for boundary, messages in ((0, [(1, None)]), (2, [(3, 4), (5, 6)]), (7, [(8, 9)]), (10, [])):
            call([0, offsets[boundary]], 0xF0002)
            for body, name in messages:
                self.message_sites.append(call([0, offsets[body], 0x0FFFFFFF if name is None else offsets[name], 100 + body], 0x20002))
        self.original_script = struct.pack(f"<{len(words)}I", *words)
        self.pac = self.root / "data.pac"
        self.write_pac(self.pac, {"SCRIPT.SRC": self.original_script, "TEXT.DAT": softpal_encrypt_bytes(self.original_text)})
        self.write_inputs(self.pasted)

    @staticmethod
    def make_dat(texts):
        data = b"$TEXT_LIST__" + struct.pack("<I", len(texts))
        offsets = []
        for idx, text in enumerate(texts):
            offsets.append(len(data))
            data += struct.pack("<I", idx) + text.encode("cp932") + b"\0"
        return data, offsets

    @staticmethod
    def write_pac(path, files):
        header = bytearray(0x804)
        header[:4] = b"PAC "
        struct.pack_into("<I", header, 8, len(files))
        table, payload = bytearray(), bytearray()
        for name, data in files.items():
            table += name.encode("ascii").ljust(32, b"\0")
            table += struct.pack("<II", len(data), 0x804 + 40 * len(files) + len(payload))
            payload += data
        path.write_bytes(header + table + payload)

    def write_inputs(self, pasted):
        texts = list(self.texts)
        texts[:len(pasted)] = pasted
        text_data, offsets = self.make_dat(texts)
        # The broken importer retained IDs and relocated by them, while
        # pasting a shorter display list into the original DAT slot list.
        original_path = self.root / "baseline.dat"
        original_path.write_bytes(self.original_text)
        archive = load_text_dat_auto(original_path, self.profile)
        sites = find_text_reference_sites(ParsedScript.from_bytes(self.original_script), archive.entries)
        script = bytearray(self.original_script)
        for site in sites:
            struct.pack_into("<I", script, site.site_offset, offsets[site.text_idx])
        self.script_path, self.text_path = self.data / "SCRIPT.SRC", self.data / "TEXT.DAT"
        self.script_path.write_bytes(script)
        self.text_path.write_bytes(softpal_encrypt_bytes(text_data))

    def dump(self):
        return dump_command(self.script_path, self.text_path, self.root / "dump", profile=self.profile)

    def test_merged_dialogues_in_name_slots_fail_without_a_matching_baseline(self):
        self.pac.unlink()
        with self.assertRaisesRegex(ValueError, "人名.*正文|错位"):
            self.dump()
        self.assertFalse((self.root / "dump/manifest.json").exists())

    def test_dump_recovers_layout_and_preserves_existing_edit_and_sources(self):
        script_before, text_before = self.script_path.read_bytes(), self.text_path.read_bytes()
        artifacts = self.dump()
        report = artifacts.manifest["source_recovery"]
        self.assertEqual(report["preserved_edit_rows"], 1)
        self.assertEqual(artifacts.text_rows[1]["original_text"], self.pasted[1])
        self.assertEqual((artifacts.text_rows[3]["export_tag"], artifacts.text_rows[3]["original_text"]), ("msg", self.texts[3]))
        self.assertEqual((artifacts.text_rows[4]["export_tag"], artifacts.text_rows[4]["original_text"]), ("name", self.texts[4]))
        self.assertEqual(self.script_path.read_bytes(), script_before)
        self.assertEqual(self.text_path.read_bytes(), text_before)
        self.assertTrue((self.root / "dump" / report["script_file"]).is_file())
        self.assertTrue((self.root / "dump" / report["text_file"]).is_file())

    def test_scene_boundaries_include_empty_scenes_and_titles_without_digits(self):
        # These are healthy resources; scene splitting must still improve.
        self.script_path.write_bytes(self.original_script)
        self.text_path.write_bytes(self.original_text)
        self.dump()
        scenes = self.root / "scenes"
        report = export_scenario_split_command(self.root / "dump", scenes, file_encoding="utf-8")
        self.assertEqual(report["files_written"], 4)
        content = read_text_auto(scenes / "共通01_01.txt")
        self.assertIn("○00000003○msg○「こんにちは」", content)
        self.assertIn("○00000004○name○エマ", content)
        self.assertNotIn("次の場面", content)
        self.assertTrue((scenes / "おまけ.txt").is_file())

    def test_export_import_and_edited_rebuild_resolve_recovered_sources(self):
        self.dump()
        dump = self.root / "dump"
        path = self.root / "translate_dump.txt"
        export_translation_command(dump, path, file_encoding="utf-8")
        content = read_text_auto(path).replace("●00000003●msg●「こんにちは」", "●00000003●msg●「こんにちは、こちらへどうぞ」")
        content = content.replace("●00000004●name●エマ", "●00000004●name●エリカ")
        path.write_text(content, encoding="utf-8", newline="\n")
        self.assertEqual(import_translation_command(dump, path)["changed_rows"], 2)
        output = self.root / "rebuilt"
        report = rebuild_with_pointer_table_command(dump, self.script_path, self.text_path, output, edited_encoding="cp932")
        archive = load_text_dat_auto(output / "TEXT.DAT", self.profile)
        self.assertEqual(archive.entries[3].original_text, "「こんにちは、こちらへどうぞ」")
        self.assertEqual(archive.entries[4].original_text, "エリカ")
        self.assertEqual(report["validation"], "pass")
        self.assertEqual(struct.unpack_from("<I", (output / "SCRIPT.SRC").read_bytes(), self.message_sites[1][1])[0], archive.entries[3].entry_offset)

    def test_scene_zero_edit_roundtrip_equals_recovered_plain_and_encrypted_sources(self):
        artifacts = self.dump()
        dump, scenes, output = self.root / "dump", self.root / "scenes", self.root / "rebuilt"
        export_scenario_split_command(dump, scenes, file_encoding="utf-8")
        import_scenario_split_command(dump, scenes)
        report = rebuild_lossless_command(dump, output, encrypt_output=True)
        recovery = artifacts.manifest["source_recovery"]
        self.assertTrue(report["script_matches_original"] and report["text_matches_original"])
        self.assertEqual((output / "SCRIPT.SRC").read_bytes(), (dump / recovery["script_file"]).read_bytes())
        self.assertEqual((output / "TEXT.DAT.en").read_bytes(), (dump / recovery["text_file"]).read_bytes())
        self.assertEqual(softpal_decrypt_bytes((output / "TEXT.DAT.en").read_bytes()), (output / "TEXT.DAT").read_bytes())

    def test_script_edits_outside_text_references_stop_recovery_before_writes(self):
        script = bytearray(self.script_path.read_bytes())
        struct.pack_into("<I", script, self.message_sites[1][0], 1)
        self.script_path.write_bytes(script)
        with self.assertRaisesRegex(ValueError, "基准|脚本|引用"):
            self.dump()
        self.assertFalse((self.root / "dump/manifest.json").exists())

    def test_explicit_pac_and_existing_translations_survive_reexport(self):
        reference = self.root / "original.pac"
        self.pac.rename(reference)
        dump = self.root / "dump"
        artifacts = dump_command(self.script_path, self.text_path, dump, profile=self.profile, reference_pac=reference)
        rows = artifacts.text_rows
        rows[3]["text"] = "「こんにちは、また会いましたね」"
        jsonl_dump(dump / "text_entries.jsonl", rows)
        path = self.root / "translate_dump.txt"
        export_translation_command(dump, path, file_encoding="utf-8")
        content = read_text_auto(path)
        self.assertIn("○00000003○msg○「こんにちは」", content)
        self.assertIn("●00000003●msg●「こんにちは、また会いましたね」", content)

    def test_old_corrupted_dump_export_fails_before_writing_translation(self):
        dump = self.root / "old_dump"
        dump.mkdir()
        jsonl_dump(dump / "text_entries.jsonl", [])
        jsonl_dump(dump / "messages.jsonl", [{
            "text_idx": 3, "name_idx": 4, "text": "エマ「こんにちは」", "name": "リリィ「元気？」",
        }])
        path = self.root / "translate_dump.txt"
        path.write_bytes(b"existing translation")
        with self.assertRaisesRegex(ValueError, "错位|人名"):
            export_translation_command(dump, path)
        self.assertEqual(path.read_bytes(), b"existing translation")

    def test_numeric_collision_and_register_scene_argument_use_real_instruction_sites(self):
        self.script_path.write_bytes(self.original_script)
        self.text_path.write_bytes(self.original_text)
        archive = load_text_dat_auto(self.text_path, self.profile)
        # The first literal only happens to equal a dialogue offset. The last
        # argument is copied through a register and is the actual scene label.
        words = [0x1001F, archive.entries[3].entry_offset,
                 0x10001, 0x40000000, archive.entries[10].entry_offset,
                 0x1001F, 0x40000000, 0x10017, 0xF0002, 0]
        self.script_path.write_bytes(self.original_script + struct.pack(f"<{len(words)}I", *words))
        artifacts = self.dump()
        self.assertFalse(artifacts.text_rows[3]["scenario_boundary_verified"])
        self.assertIsNone(artifacts.text_rows[3]["scenario_role"])
        self.assertTrue(artifacts.text_rows[10]["scenario_boundary_verified"])

    def test_legacy_boundary_tags_import_against_verified_new_boundaries(self):
        artifacts = self.dump()
        dump = self.root / "dump"
        path = self.root / "translate_dump.txt"
        export_translation_command(dump, path, file_encoding="utf-8")
        content = read_text_auto(path)
        for row in artifacts.text_rows:
            if row["scenario_boundary_verified"]:
                idx, tag = int(row["idx"]), row["source_boundary_tag"]
                content = content.replace(f"{idx:08d}○scenario○", f"{idx:08d}○{tag}○")
                content = content.replace(f"{idx:08d}●scenario●", f"{idx:08d}●{tag}●")
        path.write_text(content, encoding="utf-8", newline="\n")
        report = import_translation_command(dump, path)
        self.assertEqual(report["changed_rows"], 0)
        self.assertEqual(report["legacy_tag_rows"], 4)

    def test_recovery_failure_preserves_existing_dump_and_rebuild_protects_recovered_sources(self):
        artifacts = self.dump()
        dump = self.root / "dump"
        before = (dump / "text_entries.jsonl").read_bytes()
        recovered = dump / artifacts.manifest["source_recovery"]["script_file"]
        source_before = recovered.read_bytes()
        with self.assertRaisesRegex(ValueError, "恢复源"):
            rebuild_with_pointer_table_command(dump, self.script_path, self.text_path, recovered.parent, edited_encoding="cp932")
        self.assertEqual(recovered.read_bytes(), source_before)
        self.pac.unlink()
        with self.assertRaises(ValueError):
            self.dump()
        self.assertEqual((dump / "text_entries.jsonl").read_bytes(), before)

    def test_ambiguous_name_edit_and_missing_pasted_row_are_rejected(self):
        for pasted in (self.pasted[:6] + self.pasted[7:], self.pasted[:3] + ("エリカ「こんにちは」",) + self.pasted[4:]):
            with self.subTest(pasted=pasted):
                self.write_inputs(pasted)
                with self.assertRaisesRegex(ValueError, "恢复|对齐|合并|人名"):
                    self.dump()
                self.assertFalse((self.root / "dump/manifest.json").exists())

    def test_unrelated_archive_and_out_of_bounds_table_are_rejected(self):
        for invalid_table in (False, True):
            with self.subTest(invalid_table=invalid_table):
                self.write_pac(self.pac, {"SCRIPT.SRC": self.original_script, "TEXT.DAT": softpal_encrypt_bytes(self.original_text)})
                pac = bytearray(self.pac.read_bytes())
                if invalid_table:
                    struct.pack_into("<I", pac, 0x804 + 36, len(pac) + 1)
                else:
                    # Change the source fingerprint while keeping a valid VM.
                    script_offset = struct.unpack_from("<I", pac, 0x804 + 36)[0]
                    pac[script_offset + 4] = 1
                self.pac.write_bytes(pac)
                with self.assertRaisesRegex(ValueError, "PAC|基准|脚本"):
                    self.dump()
                self.assertFalse((self.root / "dump/manifest.json").exists())

    def test_optional_corrupted_corpus_recovers_all_slots_and_95_scenes(self):
        source = os.environ.get("SOFTPAL_TEST_RECOVERY_CORPUS")
        if not source:
            self.skipTest("Set SOFTPAL_TEST_RECOVERY_CORPUS for the optional recovery corpus check")
        source = Path(source)
        dump = self.root / "corpus_dump"
        artifacts = dump_command(source / "SCRIPT.SRC", source / "TEXT.DAT", dump, profile=self.profile)
        self.assertEqual(artifacts.manifest["text_entry_count"], 49843)
        self.assertEqual(artifacts.manifest["source_recovery"]["preserved_edit_rows"], 3)
        self.assertEqual(artifacts.manifest["source_recovery"]["reversed_joins"], 3)
        self.assertEqual(artifacts.text_rows[938]["original_text"], "「ののかー、もうそろそろいい時間よー」")
        self.assertEqual(artifacts.text_rows[939]["original_text"], "母")
        scenes = self.root / "corpus_scenes"
        report = export_scenario_split_command(dump, scenes, file_encoding="utf-8")
        self.assertEqual(report["files_written"], 95)
        self.assertEqual(report["sample_files"][1]["end_idx"], 1634)
        content = read_text_auto(scenes / "共通01_01.txt")
        self.assertNotIn("共通01_02", content)
        self.assertIn("○00000939○name○母", content)


if __name__ == "__main__":
    unittest.main()
