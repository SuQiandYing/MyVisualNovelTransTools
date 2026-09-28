"""End-to-end checks against the supplied, read-only Interheart sample."""

import ast
import hashlib
from pathlib import Path
import shutil
import sys
import tempfile
import tkinter as tk
import time
import unittest
from unittest import mock

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import assembler
import disassembler
from extract_text import examine
from run_gui import App, MESSAGES


class InterheartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = TOOLS.parent / "data"
        cls.archive = TOOLS.parent / "data.fpk"
        if not cls.source.is_dir() or not cls.archive.is_file():
            raise unittest.SkipTest("local Interheart fixture not installed")
        cls.before = hashlib.sha256(cls.archive.read_bytes()).hexdigest()
        cls.temp = tempfile.TemporaryDirectory(prefix="interheart-test-")
        cls.root = Path(cls.temp.name)
        cls.base = cls.root / "base"
        cls.export_report = disassembler.export(cls.source, cls.base, texts=True, asm=True,
                                                with_ir=True)
        try:
            cls.gui_root = tk.Tk()
            cls.gui_root.withdraw()
        except tk.TclError:
            cls.gui_root = None

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "before"):
            assert cls.before == hashlib.sha256(cls.archive.read_bytes()).hexdigest()
            if cls.gui_root is not None:
                cls.gui_root.destroy()
            cls.temp.cleanup()

    def edits(self, name, *, text=True, asm=False):
        folder = self.root / name
        folder.mkdir()
        shutil.copyfile(self.base / "manifest.json", folder / "manifest.json")
        if text:
            shutil.copytree(self.base / "texts", folder / "texts")
        if asm:
            shutil.copytree(self.base / "asm", folder / "asm")
        return folder

    def edit_line(self, folder, prefix, replacement, *, asm=False):
        path = folder / ("asm" if asm else "texts") / (
            "A0100_100.spt.asm.txt" if asm else "A0100_100.spt.txt")
        lines = path.read_text("utf-8-sig").splitlines(keepends=True)
        matches = [i for i, line in enumerate(lines) if line.startswith(prefix)]
        self.assertEqual(len(matches), 1)
        index = matches[0]
        lines[index] = replacement(lines[index]) + "\n"
        path.write_bytes((b"" if asm else b"\xef\xbb\xbf") +
                         "".join(lines).encode("utf-8"))
        return path

    def test_export_name_bom_and_certificate(self):
        self.assertEqual((self.export_report["body_entries"],
                          self.export_report["name_entries"]), (7490, 4429))
        path = self.base / "texts" / "A0100_100.spt.txt"
        self.assertTrue(path.read_bytes().startswith(b"\xef\xbb\xbf"))
        self.assertIn("○10000017○name○トワ", path.read_text("utf-8-sig"))
        self.assertEqual(len(list((self.base / "texts").glob("*.txt"))), 89)
        self.assertEqual(len(list((self.base / "asm").glob("*.asm.txt"))), 147)
        self.assertTrue((self.base / "ir" / "name_bindings.jsonl").is_file())
        cert = self.base / "_work" / "reports" / "coverage" / "A0100_100.spt.json"
        self.assertTrue(cert.is_file())

    def test_identity(self):
        edits = self.edits("identity", text=True, asm=True)
        plan = assembler.prepare(self.source, edits)
        self.assertEqual(plan["selected_strategy"], "identity")
        report, backup = assembler.execute(plan, self.root / "identity_out")
        self.assertTrue(report["identity"])
        self.assertIsNone(backup)
        self.assertEqual((self.root / "identity_out" / "data.fpk").read_bytes(),
                         self.archive.read_bytes())

    def test_long_short_name(self):
        edits = self.edits("lengths")
        self.edit_line(edits, "●10000017●name●",
                       lambda _: "●10000017●name●小灯")
        self.edit_line(edits, "●00000017●msg●",
                       lambda line: line.rstrip("\n") + "——显著加长的中文译文。")
        self.edit_line(edits, "●00000020●msg●",
                       lambda _: "●00000020●msg●「好。」")
        plan = assembler.prepare(self.source, edits)
        self.assertEqual(plan["selected_strategy"], "pointer-rewrite")
        report, _ = assembler.execute(plan, self.root / "lengths_out")
        self.assertEqual(report["edited_entries"], 3)
        result = examine(self.root / "lengths_out" / "entries")["bindings"]
        original = examine(self.source)["bindings"]
        self.assertEqual(result[17]["speaker"], "小灯")
        self.assertTrue(result[17]["text"].endswith("显著加长的中文译文。"))
        self.assertEqual(result[20]["text"], "「好。」")
        for ident in original.keys() - {17, 20}:
            self.assertEqual((result[ident]["speaker"], result[ident]["text"]),
                             (original[ident]["speaker"], original[ident]["text"]))

    def test_asm_only_and_structural_rejection(self):
        edits = self.edits("asm_only", text=False, asm=True)
        path = self.edit_line(
            edits, "    .string id=T00000017 ",
            lambda line: line.split(" value=", 1)[0] + ' value="ASM新文本"',
            asm=True)
        plan = assembler.prepare(None, edits)
        self.assertEqual(plan["changes"], {17: "ASM新文本"})
        report, _ = assembler.execute(plan, self.root / "asm_out")
        self.assertEqual(report["edited_entries"], 1)
        self.assertEqual(examine(self.root / "asm_out" / "entries")["bindings"][17]["text"],
                         "ASM新文本")
        path.write_text(path.read_text("utf-8").replace(".cell id=", ".other id=", 1),
                        encoding="utf-8")
        with self.assertRaisesRegex(disassembler.ToolError, "TIER_TOO_LOW"):
            assembler.prepare(None, edits)

    def test_conflict_and_same_value(self):
        edits = self.edits("conflict", text=True, asm=True)
        self.edit_line(edits, "●00000017●msg●",
                       lambda _: "●00000017●msg●文本值")
        self.edit_line(edits, "    .string id=T00000017 ",
                       lambda line: line.split(" value=", 1)[0] + ' value="ASM值"',
                       asm=True)
        plan = assembler.prepare(None, edits)
        self.assertEqual(plan["conflicts"][17], {"texts": "文本值", "asm": "ASM值"})
        with self.assertRaisesRegex(disassembler.ToolError, "EDIT_CONFLICT"):
            assembler.execute(plan, self.root / "conflict_out")
        self.assertFalse((self.root / "conflict_out").exists())
        self.edit_line(edits, "    .string id=T00000017 ",
                       lambda line: line.split(" value=", 1)[0] + ' value="文本值"',
                       asm=True)
        plan = assembler.prepare(None, edits)
        self.assertEqual(plan["changes"], {17: "文本值"})

    def test_text_negative_cases(self):
        cases = (
            ("anchor", "○00000017○msg○", "○00000017○msg○假原文", "SOURCE_ANCHOR"),
            ("tag", "●00000017●msg●", "●00000017●ui●错误", "TEXT_TAG"),
            ("idx", "●00000017●msg●", "●00000018●msg●错误", "TEXT_ID"),
            ("empty", "●00000017●msg●", "●00000017●msg●", "EMPTY_TRANSLATION"),
            ("token", "●00000017●msg●", "●00000017●msg●{{00}}", "PLACEHOLDER_BROKEN"),
        )
        for name, prefix, replacement, code in cases:
            with self.subTest(name=name):
                edits = self.edits("bad_" + name)
                self.edit_line(edits, prefix, lambda _: replacement)
                with self.assertRaisesRegex(disassembler.ToolError, code):
                    assembler.prepare(None, edits)
        missing = self.edits("missing")
        (missing / "texts" / "A0100_100.spt.txt").unlink()
        with self.assertRaisesRegex(disassembler.ToolError, "TEXT_MISSING"):
            assembler.prepare(None, missing)

    def test_optional_modes_and_default_ir(self):
        text_path, asm_path = self.root / "text_only", self.root / "asm_export"
        disassembler.export(self.source, text_path, texts=True, asm=False)
        disassembler.export(self.source, asm_path, texts=False, asm=True)
        self.assertFalse((text_path / "asm").exists())
        self.assertFalse((asm_path / "texts").exists())
        self.assertFalse((text_path / "ir").exists())
        self.assertFalse((asm_path / "ir").exists())
        sample = "A0100_100.spt"
        self.assertEqual((text_path / "texts" / (sample + ".txt")).read_bytes(),
                         (self.base / "texts" / (sample + ".txt")).read_bytes())
        self.assertEqual((asm_path / "asm" / (sample + ".asm.txt")).read_bytes(),
                         (self.base / "asm" / (sample + ".asm.txt")).read_bytes())
        self.assertEqual(assembler.prepare(None, text_path)["selected_strategy"], "identity")
        self.assertEqual(assembler.prepare(None, asm_path)["selected_strategy"], "identity")

    def test_gui_paths_and_code_documentation(self):
        if self.gui_root is None:
            self.skipTest("Tk unavailable")
        root = tk.Toplevel(self.gui_root)
        root.withdraw()
        try:
            app = App(root)
            app.set_source(str(self.source))
            self.assertEqual(app.edits_from.get(), app.text_output.get())
            app.text_output.set(str(self.root / "linked"))
            self.assertEqual(app.edits_from.get(), str(self.root / "linked"))
            app.edits_from.set(str(self.root / "override"))
            app.text_output.set(str(self.root / "later"))
            self.assertEqual(app.edits_from.get(), str(self.root / "override"))
            app.want_text.set(False)
            app.want_asm.set(False)
            self.assertEqual(str(app.export_button.cget("state")), "disabled")
        finally:
            root.destroy()
        thrown = set()
        for name in ("assembler.py", "disassembler.py"):
            tree = ast.parse((TOOLS / name).read_text("utf-8"))
            thrown.update(node.args[0].value for node in ast.walk(tree)
                          if isinstance(node, ast.Call) and
                          isinstance(node.func, ast.Name) and node.func.id == "ToolError"
                          and node.args and isinstance(node.args[0], ast.Constant))
        thrown.add("FORMAT_ERROR")
        self.assertEqual(thrown, set(MESSAGES))
        readme = (TOOLS / "README.md").read_text("utf-8")
        error_section = readme.split("## 报错与处置", 1)[1].split("## 已知限制", 1)[0]
        listed = {line.split("|")[1].strip().strip("`") for line in error_section.splitlines()
                  if line.startswith("| `")}
        self.assertEqual(thrown, listed)
        for internal in ("decode_tier", "unpack_mode", "repack_strategy", "JoinSite"):
            self.assertNotIn(internal, readme)

    def test_gui_export_calls_same_core(self):
        if self.gui_root is None:
            self.skipTest("Tk unavailable")
        root = tk.Toplevel(self.gui_root)
        root.withdraw()
        try:
            app = App(root)
            app.set_source(str(self.source))
            destination = self.root / "gui_export"
            app.text_output.set(str(destination))
            app._start_export()
            deadline = time.monotonic() + 40
            while app._busy and time.monotonic() < deadline:
                root.update()
                time.sleep(0.03)
            root.update()
            self.assertFalse(app._busy, app.status.get())
            self.assertTrue(destination.is_dir(), app.status.get())
            source_texts = self.base / "texts"
            gui_texts = destination / "texts"
            self.assertEqual(
                {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in source_texts.iterdir()},
                {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in gui_texts.iterdir()})
            self.assertEqual(
                (self.base / "_work" / "reports" / "coverage_certificate.json").read_bytes(),
                (destination / "_work" / "reports" / "coverage_certificate.json").read_bytes())
        finally:
            root.destroy()

    def test_gui_unicode_drop_callback(self):
        import windnd
        if self.gui_root is None:
            self.skipTest("Tk unavailable")
        parent = self.root / "ガールズ・イン・ブラック"
        parent.mkdir()
        data = parent / "data"
        shutil.copytree(self.source, data)
        shutil.copyfile(self.archive, parent / "data.fpk")
        root = tk.Toplevel(self.gui_root)
        root.withdraw()
        try:
            with mock.patch.object(windnd, "hook_dropfiles") as hook:
                app = App(root)
                self.assertTrue(hook.call_args.kwargs["force_unicode"])
            app._dropped([str(data)])
            root.update()
            self.assertEqual(app.source.get(), str(data))
            self.assertEqual(app.edits_from.get(), str(parent / "data_text"))
        finally:
            root.destroy()


if __name__ == "__main__":
    unittest.main()
