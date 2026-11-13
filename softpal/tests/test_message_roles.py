from __future__ import annotations

import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path


TOOL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_ROOT))

from softpal_roundtrip.core.models import TextEntry
from softpal_roundtrip.engine.script_parser import ParsedScript
from softpal_roundtrip.engine.text_dat_parser import load_text_dat_auto
from softpal_roundtrip.io.compat_text import read_text_auto
from softpal_roundtrip.io.json_io import load_jsonl
from softpal_roundtrip.profiles.classic_softpal import ClassicSoftPalProfile
from softpal_roundtrip.workflows.dump_workflow import build_text_offset_map, dump_command
from softpal_roundtrip.workflows.rebuild_workflow import rebuild_lossless_command
from softpal_roundtrip.workflows.translation_workflow import (
    export_translation_command,
    import_translation_command,
)


class MessageRoleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = ClassicSoftPalProfile()
        self.instructions = self.profile.get_instruction_set()

    def entry(self, idx: int, offset: int, text: str) -> TextEntry:
        return TextEntry(idx, idx, offset, text.encode("cp932"), text)

    def extract(self, words: list[int], entries: list[TextEntry]):
        script = ParsedScript.from_bytes(
            struct.pack(f"<{len(words)}I", *words),
            instruction_set=self.instructions,
        )
        return self.profile.extract_message_events(script, build_text_offset_map(entries))

    def push_call(self, arguments: list[int], call_id: int = 0x00020002) -> list[int]:
        words = []
        for argument in arguments:
            words.extend([self.instructions.push_immediate_opcode, argument])
        return words + [self.instructions.call_opcode, call_id, 0]

    def param_call(
        self,
        arguments: dict[int, int],
        *,
        before: bool = False,
        call_id: int = 0x00020002,
    ) -> list[int]:
        words = []
        for ordinal, argument in arguments.items():
            words.extend([self.instructions.param_set_opcode, 0x30000000 | ordinal, argument])
        if before:
            return [self.instructions.call_opcode, call_id] + words
        return words + [self.instructions.call_opcode, call_id, 0]

    def test_reported_thoughts_keep_message_and_speaker_roles(self) -> None:
        for text in ("（行ってきます）", "（わたしにも威厳ってのものがあるんだから！）"):
            for call_id in (0x00020002, 0x0002000F):
                with self.subTest(text=text, call_id=call_id):
                    body = self.entry(2283, 0x11617, text)
                    name = self.entry(2284, 0x11648, "リリィ")
                    event, = self.extract(self.push_call([0, body.entry_offset, name.entry_offset, 1218], call_id), [body, name])
                    self.assertEqual((event.text_idx, event.name_idx), (2283, 2284))
                    self.assertEqual((event.text, event.name), (text, "リリィ"))

    def test_short_unquoted_messages_use_slots(self) -> None:
        for text in ("うん", "あ", "リリィ", "……", "！？"):
            with self.subTest(text=text):
                body = self.entry(10, 0x100, text)
                name = self.entry(11, 0x200, "エマ")
                event, = self.extract(self.push_call([0, 0x100, 0x200, 100]), [body, name])
                self.assertEqual((event.text_idx, event.name_idx), (10, 11))

    def test_numeric_flags_and_line_id_are_not_speakers(self) -> None:
        body = self.entry(10, 0x100, "「こんにちは」")
        name = self.entry(11, 0x200, "リリィ")
        collision = self.entry(12, 0x300, "背景")
        for arguments, expected_name in (
            ([0x300, 0x100, 0x200, 7], 11),
            ([0, 0x100, self.profile.get_no_name_sentinel(), 0x300], None),
        ):
            with self.subTest(arguments=arguments):
                event, = self.extract(self.push_call(arguments), [body, name, collision])
                self.assertEqual((event.text_idx, event.name_idx), (10, expected_name))
                self.assertEqual(event.line_id, arguments[3])

    def test_missing_message_slot_is_not_replaced_by_numeric_collision(self) -> None:
        collision = self.entry(12, 0x300, "背景")
        events = self.extract(self.push_call([0, 0x999, self.profile.get_no_name_sentinel(), 0x300]), [collision])
        self.assertEqual(events, [])

    def test_explicit_name_slot_does_not_depend_on_name_length_or_punctuation(self) -> None:
        body = self.entry(10, 0x100, "うん")
        name = self.entry(11, 0x200, "リリィ（魔王）" * 5)
        event, = self.extract(self.push_call([0, 0x100, 0x200, 7]), [body, name])
        self.assertEqual((event.text_idx, event.name_idx), (10, 11))

    def test_param_slots_work_before_and_after_call_and_in_any_write_order(self) -> None:
        body = self.entry(10, 0x100, "（行ってきます）")
        name = self.entry(11, 0x200, "リリィ")
        collision = self.entry(12, 0x300, "背景")
        for before in (False, True):
            for call_id in (0x00020002, 0x0002000F):
                with self.subTest(before=before, call_id=call_id):
                    words = self.param_call({2: 0x200, 0: 0x300, 3: 0x300, 1: 0x100}, before=before, call_id=call_id)
                    event, = self.extract(words, [body, name, collision])
                    self.assertEqual((event.text_idx, event.name_idx, event.line_id), (10, 11, 0x300))

    def test_other_call_shapes_disambiguate_against_the_other_text(self) -> None:
        body = self.entry(10, 0x100, "（行ってきます）")
        name = self.entry(11, 0x200, "リリィ")
        for arguments in ([0x100, 0x200], [0x200, 0x100]):
            with self.subTest(arguments=arguments):
                event, = self.extract(self.push_call(arguments, 0x00020010), [body, name])
                self.assertEqual((event.text_idx, event.name_idx), (10, 11))

    def test_ambiguous_short_texts_do_not_silently_pick_a_speaker(self) -> None:
        entries = [self.entry(10, 0x100, "エマ"), self.entry(11, 0x200, "リリィ")]
        with self.assertRaisesRegex(ValueError, "人名.*正文"):
            self.extract(self.push_call([0x100, 0x200], 0x00020010), entries)

    def test_more_than_two_untyped_texts_are_reported_as_ambiguous(self) -> None:
        entries = [self.entry(10, 0x100, "「こんにちは」"), self.entry(11, 0x200, "エマ"), self.entry(12, 0x300, "リリィ")]
        with self.assertRaisesRegex(ValueError, "人名.*正文"):
            self.extract(self.push_call([0x100, 0x200, 0x300], 0x00020010), entries)

    def test_repeated_reference_does_not_bind_a_text_to_itself(self) -> None:
        body = self.entry(10, 0x100, "「こんにちは」")
        event, = self.extract(self.push_call([0x100, 0x100], 0x00020010), [body])
        self.assertEqual((event.text_idx, event.name_idx, event.kind), (10, None, "narration"))

    def test_dump_export_import_and_zero_edit_rebuild(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            body_text, name_text = "（行ってきます）", "リリィ"
            text_data = b"$TEXT_LIST__" + struct.pack("<I", 2)
            body_offset = len(text_data)
            text_data += struct.pack("<I", 10) + body_text.encode("cp932") + b"\x00"
            name_offset = len(text_data)
            text_data += struct.pack("<I", 11) + name_text.encode("cp932") + b"\x00"
            words = self.push_call([0, body_offset, name_offset, 100])
            script_data = struct.pack(f"<{len(words)}I", *words)
            script_path, text_path = root / "SCRIPT.SRC", root / "TEXT.DAT"
            script_path.write_bytes(script_data)
            text_path.write_bytes(text_data)
            dump_dir = root / "dump"
            dump_command(script_path, text_path, dump_dir, profile=self.profile)
            translation = root / "translate_dump.txt"
            export_translation_command(dump_dir, translation, file_encoding="utf-8")
            exported = read_text_auto(translation)
            self.assertIn("○00000010○msg○" + body_text, exported)
            self.assertIn("○00000011○name○" + name_text, exported)
            self.assertIn("pair=11", exported)
            self.assertEqual(import_translation_command(dump_dir, translation)["changed_rows"], 0)
            rebuilt = root / "rebuilt"
            rebuild_lossless_command(dump_dir, rebuilt)
            self.assertEqual((rebuilt / "SCRIPT.SRC").read_bytes(), script_data)
            self.assertEqual((rebuilt / "TEXT.DAT").read_bytes(), text_data)

    def test_provided_corpus_roles_match_every_message_argument_slot(self) -> None:
        source_directory = os.environ.get("SOFTPAL_TEST_CORPUS")
        if not source_directory:
            self.skipTest("Set SOFTPAL_TEST_CORPUS to run the optional corpus check")
        source_root = Path(source_directory)
        if not (source_root / "SCRIPT.SRC").is_file() or not (source_root / "TEXT.DAT").is_file():
            self.skipTest("The supplied game corpus is not present")
        script = ParsedScript.from_bytes((source_root / "SCRIPT.SRC").read_bytes())
        text_map = build_text_offset_map(load_text_dat_auto(source_root / "TEXT.DAT", self.profile).entries)
        events = self.profile.extract_message_events(script, text_map)
        self.assertEqual(len(events), 1150)
        for event in events:
            with self.subTest(call_offset=f"0x{event.call_offset:08X}"):
                call_word = event.call_offset // 4
                self.assertEqual(event.text_offset, script.words[call_word - 5])
                name_offset = script.words[call_word - 3]
                expected_name = None if name_offset == self.profile.get_no_name_sentinel() else name_offset
                self.assertEqual(event.name_offset, expected_name)
                self.assertEqual(event.line_id, script.words[call_word - 1])


if __name__ == "__main__":
    unittest.main()
