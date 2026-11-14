from __future__ import annotations

from datetime import datetime
from pathlib import Path

import softpal_roundtrip as core_v1

from .constants import OUTPUT_MODE_LABELS


class GuiActionsMixin:
    def _auto_detect_from_project(self, silent: bool = False) -> None:
        base = Path(self.project_dir.get())
        if not base.exists():
            if not silent:
                self._log(f"项目目录不存在: {base}")
            return

        script = self._find_file_case_insensitive(base, "SCRIPT.SRC")
        text = self._find_file_case_insensitive(base, "TEXT.DAT")
        if script is not None:
            self.script_path.set(str(script))
        if text is not None:
            self.text_path.set(str(text))

        self.dump_dir.set(str(base / "disasm_out"))
        self.translation_path.set(str(base / "translate_dump.txt"))
        self.scenario_dir.set(str(base / "scenario_txt"))
        self.output_dir.set(str(base / "rebuild_relocate"))

        if not silent:
            self._log("已根据项目目录刷新默认路径。")

    def _require_paths(self, *names: str) -> dict[str, Path] | None:
        mapping = {
            "script": Path(self.script_path.get()),
            "text": Path(self.text_path.get()),
            "dump": Path(self.dump_dir.get()),
            "translation": Path(self.translation_path.get()),
            "scenario": Path(self.scenario_dir.get()),
            "output": Path(self.output_dir.get()),
        }
        for name in names:
            path = mapping[name]
            if not str(path):
                self._show_error("路径缺失", f"{name} 路径为空")
                return None
            if name in {"script", "text", "translation", "scenario"} and not path.exists():
                self._show_error("路径不存在", f"{path} 不存在")
                return None
        return mapping

    def _get_output_flags(self) -> tuple[bool, bool]:
        mode = OUTPUT_MODE_LABELS.get(self.output_mode.get(), "both")
        if mode == "plain_only":
            return False, False
        if mode == "encrypted_only":
            return True, True
        return True, False

    def _run_selected_rebuild_backend(
        self,
        dump_dir: Path,
        script_path: Path,
        text_path: Path,
        output_dir: Path,
        *,
        edited_encoding: str,
        encrypt_output: bool,
        replace_plain_with_encrypted: bool,
    ) -> tuple[str, dict]:
        idx_text = self.anchor_idx.get().strip()
        offset_text = self.script_offset.get().strip()
        start_idx = int(idx_text) if idx_text else 0

        script_scan_start = None
        if offset_text:
            try:
                script_scan_start = int(offset_text, 16) if offset_text.lower().startswith("0x") else int(offset_text)
            except ValueError:
                script_scan_start = None

        return "rebuild_verified_references", core_v1.rebuild_with_pointer_table_command(
            dump_dir,
            script_path,
            text_path,
            output_dir,
            edited_encoding=edited_encoding,
            encrypt_output=encrypt_output,
            replace_plain_with_encrypted=replace_plain_with_encrypted,
            start_idx=start_idx,
            script_scan_start=script_scan_start,
        )

    def _get_idx_range(self):
        start_text = self.idx_start.get().strip()
        end_text = self.idx_end.get().strip()
        try:
            idx_start = int(start_text) if start_text else None
            idx_end = int(end_text) if end_text else None
            return core_v1.normalize_idx_range(idx_start, idx_end)
        except Exception as exc:
            self._show_error("范围无效", str(exc))
            return None

    def _task_dump_and_export(self) -> None:
        paths = self._require_paths("script", "text")
        if paths is None:
            return

        def work() -> None:
            manifest = core_v1.dump_command(
                paths["script"],
                paths["text"],
                Path(self.dump_dir.get()),
                text_codec=self.text_codec.get(),
            )
            self._log(f"反汇编完成，共 {manifest.get('text_entry_count', 0)} 条文本。")

            try:
                auto_idx, script_offset = core_v1.auto_find_anchor_idx(
                    paths["script"],
                    paths["text"],
                    start_idx=0,
                )
                self.root.after(0, lambda: self.anchor_idx.set(str(auto_idx)))
                self.root.after(0, lambda: self.script_offset.set(hex(script_offset)))
                self._log(f"定位参考：idx={auto_idx}，地址={hex(script_offset)}。")
            except Exception as exc:
                self._log(f"定位参考未找到：{exc}")

        self._run_background("反汇编 + 分析", work)

    def _task_export_only(self) -> None:
        paths = self._require_paths("dump")
        if paths is None:
            return
        idx_range = self._get_idx_range()
        if idx_range is None:
            return
        idx_start, idx_end = idx_range

        def work() -> None:
            report = core_v1.export_translation_command(
                paths["dump"],
                Path(self.translation_path.get()),
                file_encoding=self.translation_file_encoding.get(),
                idx_start=idx_start,
                idx_end=idx_end,
            )
            self._log_report("export", report)

        self._run_background("导出译文", work)

    def _task_export_scenarios(self) -> None:
        paths = self._require_paths("dump")
        if paths is None:
            return

        def work() -> None:
            report = core_v1.export_scenario_split_command(
                paths["dump"],
                Path(self.scenario_dir.get()),
                file_encoding=self.translation_file_encoding.get(),
            )
            self._log_report("export_scenarios", report)

        self._run_background("按 scenario 导出", work)

    def _task_import_scenarios_and_rebuild_relocate(self) -> None:
        paths = self._require_paths("dump", "scenario", "output", "script", "text")
        if paths is None:
            return
        encrypt_output, replace_plain_with_encrypted = self._get_output_flags()

        def work() -> None:
            import_report = core_v1.import_scenario_split_command(paths["dump"], paths["scenario"])
            self._log_report("import_scenarios", import_report)
            rebuild_label, rebuild_report = self._run_selected_rebuild_backend(
                paths["dump"],
                paths["script"],
                paths["text"],
                paths["output"],
                edited_encoding=self.edited_encoding.get(),
                encrypt_output=encrypt_output,
                replace_plain_with_encrypted=replace_plain_with_encrypted,
            )
            self._log_report(rebuild_label, rebuild_report)

        self._run_background("scenario 导入 + 变长回封", work)

    def _task_import_and_rebuild_relocate(self) -> None:
        paths = self._require_paths("dump", "translation", "output", "script", "text")
        if paths is None:
            return
        idx_range = self._get_idx_range()
        if idx_range is None:
            return
        idx_start, idx_end = idx_range
        encrypt_output, replace_plain_with_encrypted = self._get_output_flags()

        def work() -> None:
            import_report = core_v1.import_translation_command(
                paths["dump"],
                paths["translation"],
                idx_start=idx_start,
                idx_end=idx_end,
            )
            self._log_report("import", import_report)
            rebuild_label, rebuild_report = self._run_selected_rebuild_backend(
                paths["dump"],
                paths["script"],
                paths["text"],
                paths["output"],
                edited_encoding=self.edited_encoding.get(),
                encrypt_output=encrypt_output,
                replace_plain_with_encrypted=replace_plain_with_encrypted,
            )
            self._log_report(rebuild_label, rebuild_report)

        self._run_background("导入 + 变长回封", work)

    def _run_background(self, title: str, worker) -> None:
        if self._busy:
            return
        self._set_busy(True, title)
        self._log(f"{title}：开始。")

        def task() -> None:
            status = f"{title} 完成"
            try:
                worker()
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
                status = f"{title} 失败"
                self._log(f"{status}：{error}")
                self.root.after(0, lambda: self._show_error("执行失败", f"{title} 失败:\n{error}"))
            finally:
                self.root.after(0, lambda: self._set_busy(False, status))

        import threading

        threading.Thread(target=task, daemon=True).start()

    def _log(self, message: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        self.root.after(0, lambda: self._append_log(f"[{stamp}] {message}\n"))

    def _log_report(self, label: str, payload: dict) -> None:
        if label == "export":
            message = f"译文已导出：{payload['rows']:,} 条，编码 {payload['file_encoding']}。"
        elif label == "export_scenarios":
            message = f"分场景导出完成：{payload['files_written']:,} 个文件。"
            if payload.get("excluded_internal_rows"):
                message += f" 已略过 {payload['excluded_internal_rows']:,} 条内部文本。"
        elif label == "import":
            message = f"译文已导入：{payload['imported_rows']:,} 条，其中 {payload['changed_rows']:,} 条与原文不同。"
        elif label == "import_scenarios":
            message = f"分场景导入完成：{payload['files']:,} 个文件，{payload['updated_idxs']:,} 条文本。"
        elif label.startswith("rebuild"):
            if payload.get("encrypted_replaces_plain"):
                output = "仅输出加密"
            elif payload.get("text_encrypted_path") or payload.get("text_encrypted"):
                output = "同时输出明文和加密"
            else:
                output = "仅输出明文"
            message = (
                f"回封完成：修改 {payload['changed_rows']:,} 条文本；"
                f"更新 {payload['rewritten_script_words']:,} 个引用"
                f"（核对 {payload['verified_reference_sites']:,} 个）；"
                f"数据校验通过；{output}。"
            )
        else:
            message = f"{label} 完成。"
        if label in {"import", "import_scenarios"} and payload.get("legacy_tag_rows"):
            message += f" 已兼容 {payload['legacy_tag_rows']:,} 条旧版导出标签。"
        self._log(message)
