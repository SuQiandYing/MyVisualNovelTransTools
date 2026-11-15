from __future__ import annotations

import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path


TOOL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_ROOT))

from softpal_roundtrip.engine.script_parser import ParsedScript
from softpal_roundtrip.engine.text_dat_parser import load_text_dat_auto
from softpal_roundtrip.engine.text_references import find_text_reference_sites
from softpal_roundtrip.io.compat_text import read_text_auto
from softpal_roundtrip.io.json_io import json_dump, jsonl_dump, load_jsonl
from softpal_roundtrip.profiles.classic_softpal import ClassicSoftPalProfile
from softpal_roundtrip.workflows.dump_workflow import dump_command
from softpal_roundtrip.workflows.rebuild_workflow import rebuild_with_pointer_table_command
from softpal_roundtrip.workflows.scenario_workflow import export_scenario_split_command, import_scenario_split_command
from softpal_roundtrip.workflows.translation_workflow import export_translation_command, import_translation_command


ESCAPE_MARKER = "# SOFTPAL_TEXT_ESCAPE_V1"


class TextEncodingTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.profile = ClassicSoftPalProfile()
        self.raw_texts = [
            b"Scene01\x81",
            "「本文」".encode("cp932") + b"\x81",
            "テスト".encode("cp932"),
            b"literal\\x81, \\n, \\u2028",
            b"line\r\nnext\tline",
            b"Scene02",
            b"plain",
        ]
        self.script_path = self.root / "SCRIPT.SRC"
        self.text_path = self.root / "TEXT.DAT"

    def make_dump(self):
        parts = [b"$TEXT_LIST__" + struct.pack("<I", len(self.raw_texts))]
        offsets = []
        cursor = 16
        for idx, raw in enumerate(self.raw_texts):
            offsets.append(cursor)
            part = struct.pack("<I", idx) + raw + b"\0"
            parts.append(part)
            cursor += len(part)
        self.text_data = b"".join(parts)
        words = list(struct.unpack("<3I", b"Sv20" + bytes(8))) + [0x10020, 0]

        def call(arguments, call_id):
            for argument in arguments:
                words.extend((0x1001F, argument))
            words.extend((0x10017, call_id, 0))

        call([offsets[0]], 0xF0002)
        call([0, offsets[1], offsets[2], 1], 0x20002)
        for idx in (3, 4):
            call([offsets[idx]], 0xF0001)
        call([offsets[5]], 0xF0002)
        call([offsets[6]], 0xF0001)
        self.script_data = struct.pack(f"<{len(words)}I", *words)
        self.script_path.write_bytes(self.script_data)
        self.text_path.write_bytes(self.text_data)
        self.dump = self.root / "dump"
        return dump_command(self.script_path, self.text_path, self.dump, profile=self.profile)

    def rebuild(self, output_name="rebuilt"):
        output = self.root / output_name
        report = rebuild_with_pointer_table_command(
            self.dump, self.script_path, self.text_path, output,
            edited_encoding="cp932", encrypt_output=True, replace_plain_with_encrypted=True,
        )
        archive = load_text_dat_auto(output / "TEXT.DAT", self.profile)
        return output, archive, report

    def test_json_writers_preserve_undecodable_bytes_and_readable_unicode(self) -> None:
        row = {"text": "本文" + b"\x81".decode("cp932", errors="surrogateescape"), "literal": r"\x81"}
        json_path, jsonl_path = self.root / "row.json", self.root / "row.jsonl"
        json_dump(json_path, row)
        jsonl_dump(jsonl_path, [row])
        self.assertEqual(json.loads(json_path.read_text(encoding="utf-8")), row)
        self.assertEqual(load_jsonl(jsonl_path), [row])
        self.assertIn("本文".encode("utf-8"), json_path.read_bytes())
        self.assertIn(b"\\udc81", jsonl_path.read_bytes())

    def test_full_dump_and_double_line_import_preserve_bytes_in_both_encodings(self) -> None:
        artifacts = self.make_dump()
        self.assertEqual(artifacts.manifest["text_decode_issue_count"], 2)
        self.assertEqual(len(load_jsonl(self.dump / "script_words.jsonl")), len(self.script_data) // 4)
        for encoding in ("utf-8", "utf-16"):
            with self.subTest(encoding=encoding):
                path = self.root / "translate_dump.txt"
                export_translation_command(self.dump, path, file_encoding=encoding)
                content = read_text_auto(path)
                self.assertIn(ESCAPE_MARKER, content)
                self.assertIn("○00000001○msg○「本文」\\x81", content)
                self.assertIn(f"○00000003○{artifacts.text_rows[3]['export_tag']}○literal\\\\x81, \\\\n, \\\\u2028", content)
                self.assertIn("line\\r\\nnext\\tline", content)
                report = import_translation_command(self.dump, path)
                self.assertEqual(report["changed_rows"], 0)
                output, archive, _ = self.rebuild("zero_" + encoding)
                self.assertEqual(archive.normalized_data, self.text_data)
                self.assertEqual((output / "SCRIPT.SRC").read_bytes(), self.script_data)
        self.assertEqual(self.text_path.read_bytes(), self.text_data)

    def test_scene_export_with_undecodable_boundary_name_roundtrips(self) -> None:
        self.make_dump()
        scenes = self.root / "scenes"
        report = export_scenario_split_command(self.dump, scenes, file_encoding="utf-8")
        self.assertEqual(report["files_written"], 2)
        for path in scenes.glob("*.txt"):
            self.assertFalse(any(0xD800 <= ord(ch) <= 0xDFFF for ch in path.name))
        imported = import_scenario_split_command(self.dump, scenes)
        # A literal path is an internal asset; omitting it must preserve its
        # original bytes just as importing the visible rows does.
        self.assertEqual(imported["updated_idxs"], len(self.raw_texts) - 1)
        self.assertTrue(all(row["text"] == row["original_text"] for row in load_jsonl(self.dump / "text_entries.jsonl")))
        _, archive, _ = self.rebuild()
        self.assertEqual([entry.raw_text for entry in archive.entries], self.raw_texts)

    def test_edit_preserves_raw_suffix_and_relocates_all_text_references(self) -> None:
        self.make_dump()
        path = self.root / "translate_dump.txt"
        export_translation_command(self.dump, path, file_encoding="utf-8")
        lines = read_text_auto(path).splitlines()
        lines = ["●00000001●msg●「更新した本文です」\\x81" if line.startswith("●00000001●") else line for line in lines]
        path.write_text("\n".join(lines), encoding="utf-8")
        imported = import_translation_command(self.dump, path)
        self.assertEqual(imported["changed_rows"], 1)
        output, archive, _ = self.rebuild()
        self.assertEqual(archive.entries[1].raw_text, "「更新した本文です」".encode("cp932") + b"\x81")
        for idx in (0, 2, 3, 4, 5, 6):
            self.assertEqual(archive.entries[idx].raw_text, self.raw_texts[idx])
        before = find_text_reference_sites(ParsedScript.from_bytes(self.script_data), load_text_dat_auto(self.text_path, self.profile).entries)
        after = find_text_reference_sites(ParsedScript.from_bytes((output / "SCRIPT.SRC").read_bytes()), archive.entries)
        self.assertEqual({site.site_offset: site.text_idx for site in before}, {site.site_offset: site.text_idx for site in after})

    def test_legacy_files_keep_literal_backslash_sequences(self) -> None:
        self.raw_texts[0] = b"Scene01"
        self.raw_texts[1] = "「本文」".encode("cp932")
        self.raw_texts[4] = b"literal\\r\\n"
        self.make_dump()
        path = self.root / "translate_dump.txt"
        export_translation_command(self.dump, path, file_encoding="utf-8")
        self.assertNotIn(ESCAPE_MARKER, read_text_auto(path))
        self.assertEqual(import_translation_command(self.dump, path)["changed_rows"], 0)
        self.assertEqual(load_jsonl(self.dump / "text_entries.jsonl")[3]["text"], r"literal\x81, \n, \u2028")

    def test_invalid_escape_or_unknown_version_is_rejected_without_changing_dump(self) -> None:
        self.make_dump()
        path = self.root / "translate_dump.txt"
        export_translation_command(self.dump, path, file_encoding="utf-8")
        baseline = read_text_auto(path)
        original_dump = (self.dump / "text_entries.jsonl").read_bytes()
        for invalid_text in (r"\x00", r"\x7f", r"\q", r"\x8", r"\uDC81", "\0"):
            with self.subTest(invalid_text=invalid_text):
                lines = ["●00000001●msg●" + invalid_text if line.startswith("●00000001●") else line for line in baseline.splitlines()]
                path.write_text("\n".join(lines), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "转义"):
                    import_translation_command(self.dump, path)
                self.assertEqual((self.dump / "text_entries.jsonl").read_bytes(), original_dump)
        path.write_text(baseline.replace(ESCAPE_MARKER, "# SOFTPAL_TEXT_ESCAPE_V999"), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "转义"):
            import_translation_command(self.dump, path)
        self.assertEqual((self.dump / "text_entries.jsonl").read_bytes(), original_dump)

    def test_original_line_error_with_raw_bytes_can_be_shown_in_utf8_logs(self) -> None:
        self.make_dump()
        path = self.root / "translate_dump.txt"
        export_translation_command(self.dump, path, file_encoding="utf-8")
        content = read_text_auto(path).replace("○00000001○msg○「本文」\\x81", "○00000001○msg○changed\\x81")
        path.write_text(content, encoding="utf-8", newline="")
        baseline = (self.dump / "text_entries.jsonl").read_bytes()
        with self.assertRaisesRegex(ValueError, "第一行原文") as caught:
            import_translation_command(self.dump, path)
        str(caught.exception).encode("utf-8")
        self.assertEqual((self.dump / "text_entries.jsonl").read_bytes(), baseline)

    @unittest.skipUnless(os.environ.get("SOFTPAL_TEST_ENCODING_CORPUS"), "optional encoding corpus not configured")
    def test_actual_encoding_corpus_full_pipeline(self) -> None:
        source = Path(os.environ["SOFTPAL_TEST_ENCODING_CORPUS"])
        artifacts = dump_command(source / "SCRIPT.SRC", source / "TEXT.DAT", self.root / "corpus", profile=self.profile)
        self.assertGreater(artifacts.manifest["text_decode_issue_count"], 0)
        self.assertEqual(artifacts.manifest["text_entry_count"], 49843)
        path = self.root / "translate_dump.txt"
        export_translation_command(self.root / "corpus", path, file_encoding="utf-8")
        self.assertEqual(import_translation_command(self.root / "corpus", path)["changed_rows"], 0)
        scenes = self.root / "scenes"
        self.assertEqual(export_scenario_split_command(self.root / "corpus", scenes, file_encoding="utf-8")["files_written"], 95)
        import_scenario_split_command(self.root / "corpus", scenes)
        output = self.root / "rebuilt"
        report = rebuild_with_pointer_table_command(
            self.root / "corpus", source / "SCRIPT.SRC", source / "TEXT.DAT", output,
            edited_encoding="cp932", encrypt_output=True, replace_plain_with_encrypted=True,
        )
        self.assertEqual(report["changed_rows"], 0)
        self.assertEqual((output / "SCRIPT.SRC").read_bytes(), (source / "SCRIPT.SRC").read_bytes())
        self.assertEqual((output / "TEXT.DAT").read_bytes(), (source / "TEXT.DAT").read_bytes())


if __name__ == "__main__":
    unittest.main()
