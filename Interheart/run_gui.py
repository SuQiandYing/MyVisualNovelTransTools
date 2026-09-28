#!/usr/bin/env python3
"""Interheart two-button text export and repack window. Python 3.11+, Tk 8.6."""

import json
import os
from pathlib import Path
import queue
import threading
import traceback
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import assembler
import disassembler
from disassembler import ToolError
from opcodelist import DIALECT


CODECS = ("utf-8", "cp932", "gbk", "big5", "cp949")
STRATEGY_TEXT = {"identity": "原样重建", "in_place": "原位写入",
                 "pointer-rewrite": "更新文本索引"}
MESSAGES = {
    "INPUT_MISSING": "找不到配套的数据目录和 data.fpk，请选择原始脚本文件夹。",
    "NO_PROJECTION": "请至少选择一种输出；回封前请先输出并编辑文本。",
    "OUTPUT_EXISTS": "目标目录已存在，请选择备份覆盖或另存新目录。",
    "SOURCE_MISMATCH": "原文件与翻译文件的来源不一致，请重新导出文本。",
    "SOURCE_ANCHOR": "原文行或说话人标记被改过，只能改 ● 译文行。",
    "TEXT_ID": "文本编号重复、未知，或三行编号不一致。",
    "TEXT_TAG": "类别与原脚本不一致，请恢复类别标记。",
    "TEXT_MISSING": "译文文件或条目缺失；请使用完整的导出目录。",
    "TEXT_SYNTAX": "双行文本格式有误；○ 原文和 ● 译文要各占一行。",
    "TEXT_HEADER": "文本文件的版本、编码或范围声明不匹配。",
    "TEXT_ENCODING": "文本文件不是有效的 UTF-8，请用 UTF-8 保存。",
    "ASM_MISSING": "ASM 清单不完整，请恢复导出的文件。",
    "ASM_SYNTAX": "ASM 字符串须保留 JSON 引号与转义。",
    "EDIT_CONFLICT": "文本和 ASM 对同一条写了不同值，请先统一。",
    "EMPTY_TRANSLATION": "译文被清空，请恢复原文或写入译文。",
    "NAME_DELIMITER": "人名不能含逗号或全角空格。",
    "PLACEHOLDER_BROKEN": "换行或控制标记被改变，请恢复原有标记顺序。",
    "MARKER_REPAIR_CONFIRMATION": "请先预览并确认本次译文标记调整。",
    "SOURCE_LAYOUT": "译文改变了原脚本行数；请保留原有的字面 \\n 分行数。",
    "ENCODING_UNSUPPORTED": "本样本只验证了 UTF-8 源及目标编码。",
    "ENCODING_UNREPRESENTABLE": "译文包含目标编码不能表示的字符，请检查编码。",
    "TIER_TOO_LOW": "目前只能修改 ASM 中的字符串，不能安全修改脚本逻辑。",
    "CANCELLED": "已取消，未提交临时输出。",
    "VERIFY_FAILED": "回封后核对不通过，原始文件未被改动。",
    "IDENTITY_FAILED": "零编辑检查不通过，此游戏样本暂不支持回封。",
    "EDIT_LOST": "改动未进入结果，原始文件未被改动。",
    "OUTPUT_UNSAFE": "输出路径不能是原文件或原目录。",
    "POINTER_OVERFLOW": "修改后的文本池超过本格式的偏移上限。",
    "COVERAGE_GAP": "脚本字节范围存在无法复核的缺口。",
    "FORMAT_ERROR": "文件格式或读写异常，详见详情。",
}


def source_defaults(value):
    data, _ = disassembler.input_paths(value)
    return str(data), str(disassembler.default_output(data, "_text")), \
        str(disassembler.default_output(data, "_rebuilt"))


class App:
    def __init__(self, root):
        self.root = root
        root.title("Interheart 文本提取与回封")
        root.minsize(690, 670)
        self.source = tk.StringVar()
        self.text_output = tk.StringVar()
        self.edits_from = tk.StringVar()
        self.rebuilt_output = tk.StringVar()
        self.source_encoding = tk.StringVar(value=DIALECT["source_encoding"])
        self.target_encoding = tk.StringVar(value=DIALECT["target_encoding"])
        self.want_text = tk.BooleanVar(value=True)
        self.want_asm = tk.BooleanVar(value=False)
        self.want_ir = tk.BooleanVar(value=False)
        self.details_open = tk.BooleanVar(value=False)
        self._setting_from = False
        self._from_overridden = False
        self._busy = False
        self._repack_supported = True
        self._closed = False
        self._poll_after = None
        self.cancel_event = threading.Event()
        self.events = queue.Queue()
        self._build()
        self.text_output.trace_add("write", self._text_path_changed)
        self.edits_from.trace_add("write", self._from_path_changed)
        self.want_text.trace_add("write", lambda *_: self._controls())
        self.want_asm.trace_add("write", lambda *_: self._controls())
        self._poll_after = self.root.after(100, self._poll)
        self.root.bind("<Destroy>", self._on_destroy, add="+")
        self._install_drop()

    def _on_destroy(self, event):
        if event.widget is self.root:
            self._closed = True
            self.cancel_event.set()
            if self._poll_after is not None:
                try:
                    self.root.after_cancel(self._poll_after)
                except tk.TclError:
                    pass

    def _build(self):
        outer = ttk.Frame(self.root, padding=16)
        outer.pack(fill="both", expand=True)
        src = ttk.LabelFrame(outer, text="游戏脚本文件夹", padding=12)
        src.pack(fill="x")
        row = ttk.Frame(src)
        row.pack(fill="x")
        ttk.Entry(row, textvariable=self.source).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="浏览…", command=self._choose_source).pack(side="left", padx=5)
        ttk.Button(row, text="文件…", command=self._choose_file).pack(side="left")
        self.drop_label = ttk.Label(src, text="把文件夹拖进来，或点此选择")
        self.drop_label.pack(anchor="w", pady=(5, 0))
        enc = ttk.Frame(outer)
        enc.pack(fill="x", pady=13)
        ttk.Label(enc, text="原文编码").pack(side="left")
        ttk.Combobox(enc, textvariable=self.source_encoding, values=CODECS,
                     width=12).pack(side="left", padx=(6, 24))
        ttk.Label(enc, text="译文编码").pack(side="left")
        ttk.Combobox(enc, textvariable=self.target_encoding, values=CODECS,
                     width=12).pack(side="left", padx=6)
        exp = ttk.LabelFrame(outer, text="输出文本", padding=12)
        exp.pack(fill="x")
        self.export_button = ttk.Button(exp, text="输 出 文 本", command=self._start_export)
        self.export_button.pack(fill="x", pady=(0, 7))
        self._path_row(exp, "到", self.text_output, self._choose_text_output)
        opts = ttk.Frame(exp)
        opts.pack(fill="x", pady=(8, 0))
        ttk.Checkbutton(opts, text="双行文本（翻译用）", variable=self.want_text).pack(side="left")
        ttk.Checkbutton(opts, text="ASM 清单（改逻辑用）", variable=self.want_asm).pack(
            side="left", padx=18)
        rep = ttk.LabelFrame(outer, text="回封文本", padding=12)
        rep.pack(fill="x", pady=14)
        self.repack_button = ttk.Button(rep, text="回 封 文 本", command=self._start_preview)
        self.repack_button.pack(fill="x", pady=(0, 7))
        self._path_row(rep, "从", self.edits_from, self._choose_edits)
        self._path_row(rep, "到", self.rebuilt_output, self._choose_rebuilt)
        ttk.Label(outer, text="只改 ● 译文；○ 原文和编号不要改。回封结果不会覆盖游戏原件。").pack(
            anchor="w", pady=(1, 7))
        self.progress = ttk.Progressbar(outer, maximum=100)
        self.progress.pack(fill="x")
        status = ttk.Frame(outer)
        status.pack(fill="x", pady=6)
        self.status = tk.StringVar(value="请选择原始 data 文件夹")
        ttk.Label(status, textvariable=self.status, wraplength=490).pack(
            side="left", fill="x", expand=True)
        self.open_button = ttk.Button(status, text="打开", command=self._open_output)
        self.open_button.pack(side="right", padx=5)
        self.cancel_button = ttk.Button(status, text="取消", command=self._cancel)
        self.cancel_button.pack(side="right")
        self.details_toggle = ttk.Checkbutton(outer, text="详情", variable=self.details_open,
                                              command=self._toggle_details)
        self.details_toggle.pack(anchor="w", pady=(8, 0))
        self.details_frame = ttk.Frame(outer)
        ttk.Checkbutton(self.details_frame, text="同时导出 IR（排查用）",
                        variable=self.want_ir).pack(anchor="w")
        self.details = tk.Text(self.details_frame, height=10, state="disabled",
                               wrap="word", font=("Consolas", 9))
        self.details.pack(fill="both", expand=True)
        self._controls()

    def _path_row(self, parent, label, var, choose):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text=label, width=3).pack(side="left")
        ttk.Entry(row, textvariable=var).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="浏览…", command=choose).pack(side="left", padx=(5, 0))

    def _toggle_details(self):
        if self.details_open.get():
            self.details_frame.pack(fill="both", expand=True)
        else:
            self.details_frame.pack_forget()

    def _write_details(self, text):
        self.details.config(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("end", text)
        self.details.config(state="disabled")

    def _controls(self):
        self.export_button.config(state="normal" if not self._busy and
                                  (self.want_text.get() or self.want_asm.get()) else "disabled")
        edits = Path(self.edits_from.get()) if self.edits_from.get() else None
        available = edits is not None and ((edits / "texts").is_dir() or
                                            (edits / "asm").is_dir())
        self.repack_button.config(state="normal" if not self._busy and available and
                                  self._repack_supported else "disabled")
        self.cancel_button.config(state="normal" if self._busy else "disabled")
        if not self.want_text.get() and not self.want_asm.get() and not self._busy:
            self.status.set("请至少选择一种输出")

    def _text_path_changed(self, *_):
        if not self._from_overridden:
            self._setting_from = True
            self.edits_from.set(self.text_output.get())
            self._setting_from = False
        self._controls()

    def _from_path_changed(self, *_):
        if not self._setting_from:
            self._from_overridden = True
        self._controls()

    def set_source(self, path):
        try:
            data, text, rebuilt = source_defaults(path)
        except (ToolError, OSError) as exc:
            messagebox.showerror("路径错误", str(exc), parent=self.root)
            return
        self.source.set(data)
        self._from_overridden = False
        self.text_output.set(text)
        self.rebuilt_output.set(rebuilt)
        self.status.set("准备就绪")
        self._repack_supported = True
        self._controls()

    def _choose_source(self):
        selected = filedialog.askdirectory(parent=self.root)
        if selected:
            self.set_source(selected)

    def _choose_file(self):
        selected = filedialog.askopenfilename(parent=self.root,
                                              filetypes=[("游戏文件", "*.fpk *.spt"),
                                                         ("全部文件", "*.*")])
        if selected:
            self.set_source(selected)

    def _choose_text_output(self):
        selected = filedialog.askdirectory(parent=self.root, mustexist=False)
        if selected:
            self.text_output.set(selected)

    def _choose_edits(self):
        selected = filedialog.askdirectory(parent=self.root)
        if selected:
            self.edits_from.set(selected)

    def _choose_rebuilt(self):
        selected = filedialog.askdirectory(parent=self.root, mustexist=False)
        if selected:
            self.rebuilt_output.set(selected)

    def _install_drop(self):
        if hasattr(self.root, "drop_target_register"):
            try:
                from tkinterdnd2 import DND_FILES
                self.root.drop_target_register(DND_FILES)
                self.root.dnd_bind("<<Drop>>", self._dropped_tk)
                self.drop_label.config(text="支持 Unicode 文件夹拖放（含日文路径）")
                return
            except (ImportError, RuntimeError, tk.TclError):
                pass
        self.drop_label.config(text="未安装 Unicode 拖放组件；点击「浏览…」可正常使用")

    def _dropped_tk(self, event):
        self._dropped(self.root.tk.splitlist(event.data))

    def _dropped(self, paths):
        if not paths:
            return
        item = paths[0]
        if not isinstance(item, str):
            self.root.after(0, lambda: messagebox.showerror(
                "拖放路径", "拖放通道没有返回 Unicode 路径，请改用「浏览…」。",
                parent=self.root))
            return
        if "?" in Path(item).name and not Path(item).exists():
            self.root.after(0, lambda: messagebox.showerror(
                "拖放路径", "拖放通道损坏了路径，请改用「浏览…」选择文件。",
                parent=self.root))
            return
        self.root.after(0, lambda: self.set_source(item))

    def _existing(self, output, var):
        if not Path(output).exists():
            return False
        answer = messagebox.askyesnocancel(
            "已有输出", "目标目录已有文件。\n是：先备份旧目录再覆盖\n否：另选新目录\n取消：停止",
            parent=self.root)
        if answer is None:
            return None
        if answer is False:
            selected = filedialog.askdirectory(parent=self.root, mustexist=False)
            if selected and not Path(selected).exists():
                var.set(selected)
                return False
            if selected:
                messagebox.showinfo("另存路径", "所选目录仍存在，请在路径框输入一个新目录名。",
                                    parent=self.root)
            return None
        return True

    def _submit(self, phase, func):
        self._busy = True
        self.cancel_event.clear()
        self.progress["value"] = 0
        self._controls()
        target = Path(self.rebuilt_output.get() if phase == "repack"
                      else self.text_output.get())
        log_path = target.with_name(target.name + ".gui.log")
        def task():
            try:
                value = func()
                self.events.put(("done", phase, value))
            except Exception as exc:
                stack = traceback.format_exc()
                try:
                    with log_path.open("a", encoding="utf-8") as log:
                        log.write(f"\n[{datetime.now().astimezone().isoformat()}] {phase}\n"
                                  f"{stack}\n")
                except OSError:
                    pass
                self.events.put(("error", phase, exc, stack, str(log_path)))
        threading.Thread(target=task, daemon=True).start()

    def _progress(self, current, total, name):
        self.events.put(("progress", current, total, name))

    def _start_export(self):
        if not self.source.get():
            messagebox.showerror("缺少源文件", "请选择原始脚本目录。", parent=self.root)
            return
        output = self.text_output.get()
        overwrite = self._existing(output, self.text_output)
        if overwrite is None:
            return
        output = self.text_output.get()
        source = self.source.get()
        want_text, want_asm, want_ir = (self.want_text.get(), self.want_asm.get(),
                                       self.want_ir.get())
        source_encoding, target_encoding = self.source_encoding.get(), self.target_encoding.get()
        self.status.set("正在核对源文件与归档…")
        self._submit("export", lambda: disassembler.export(
            source, output, texts=want_text, asm=want_asm, with_ir=want_ir,
            source_encoding=source_encoding,
            target_encoding=target_encoding, overwrite=overwrite,
            progress=self._progress, cancelled=self.cancel_event))

    def _start_preview(self):
        source, edits, encoding = (self.source.get(), self.edits_from.get(),
                                   self.target_encoding.get())
        self.status.set("正在检查译文、冲突与回封路径…")
        self._submit("preview", lambda: assembler.prepare(
            source, edits, target_encoding=encoding))

    def _confirm_preview(self, text):
        dialog = tk.Toplevel(self.root)
        dialog.title("回封预览")
        dialog.transient(self.root)
        dialog.minsize(680, 380)
        dialog.geometry("860x600")
        body = ttk.Frame(dialog, padding=12)
        body.pack(fill="both", expand=True)
        scroll = ttk.Scrollbar(body)
        scroll.pack(side="right", fill="y")
        detail = tk.Text(body, wrap="word", yscrollcommand=scroll.set)
        detail.pack(side="left", fill="both", expand=True)
        scroll.config(command=detail.yview)
        detail.insert("1.0", text)
        detail.config(state="disabled")
        result = [False]

        def finish(approved=False):
            result[0] = approved
            dialog.destroy()

        actions = ttk.Frame(dialog, padding=(12, 0, 12, 12))
        actions.pack(fill="x")
        ttk.Button(actions, text="取消", command=finish).pack(side="right")
        ttk.Button(actions, text="确认并回封",
                   command=lambda: finish(True)).pack(side="right", padx=8)
        dialog.protocol("WM_DELETE_WINDOW", finish)
        dialog.grab_set()
        self.root.wait_window(dialog)
        return result[0]

    def _show_preview(self, plan):
        if plan["conflicts"]:
            lines = [f"{idx:08d}: 文本={values['texts']!r} / ASM={values['asm']!r}"
                     for idx, values in list(sorted(plan["conflicts"].items()))[:12]]
            messagebox.showerror("译文冲突", "两处编辑不同，无法执行：\n" + "\n".join(lines),
                                 parent=self.root)
            self.status.set(f"发现 {len(plan['conflicts'])} 处冲突，尚未写入文件")
            return
        output = self.rebuilt_output.get()
        text = (f"将回封 {len(plan['analysis']['files'])} 个脚本\n"
                f"改动 {len(plan['changes'])} 条，文本池字节变化 {plan['txd_delta']:+d}\n"
                f"方式 {STRATEGY_TEXT[plan['selected_strategy']]}\n"
                f"冲突 0\n输出到 {output}")
        if plan["marker_repairs"]:
            text += ("\n\n以下标记位置按原文比例生成建议，可能不符合译文断句。"
                     "\n请逐条核对；不合适就取消并在 ● 译文行自行放置 \\n / &heart;。"
                     "\n确认只更改本次回封结果，原 data_text 文件保持不变：\n")
            for item in plan["marker_repairs"]:
                text += (f"\n{item['scene']} idx={item['idx']}\n"
                         f"原译文：{item['before']}\n"
                         f"回封值：{item['after']}\n")
        text += "\n执行吗？"
        if not self._confirm_preview(text):
            self.status.set("已取消预览，没有写入回封产物")
            return
        overwrite = self._existing(output, self.rebuilt_output)
        if overwrite is None:
            return
        output = self.rebuilt_output.get()
        self.status.set("正在重建并重新读取全部文本…")
        self._submit("repack", lambda: assembler.execute(
            plan, output, overwrite=overwrite, progress=self._progress,
            cancelled=self.cancel_event, accept_marker_repairs=True))

    def _poll(self):
        if self._closed:
            return
        try:
            while True:
                event = self.events.get_nowait()
                if event[0] == "progress":
                    _, current, total, name = event
                    self.progress["value"] = int(100 * current / total) if total else 100
                    self.status.set(f"正在处理 {name}  {self.progress['value']}% "
                                    f"({current}/{total} 字节)")
                elif event[0] == "error":
                    _, phase, exc, stack, log_path = event
                    self._busy = False
                    self._controls()
                    code = exc.code if isinstance(exc, ToolError) else "FORMAT_ERROR"
                    if code == "IDENTITY_FAILED":
                        self._repack_supported = False
                    summary = MESSAGES.get(code, "处理失败，详情中有完整原因。")
                    self.status.set(summary)
                    self._write_details(f"{code}: {exc}\n日志：{log_path}\n\n{stack}")
                    messagebox.showerror("处理失败", f"{summary}\n{exc}", parent=self.root)
                elif event[0] == "done":
                    _, phase, value = event
                    self._busy = False
                    self._controls()
                    if phase == "preview":
                        self._show_preview(value)
                    else:
                        report = value[0] if phase == "repack" else value
                        dest = self.rebuilt_output.get() if phase == "repack" \
                            else self.text_output.get()
                        self.status.set(
                            (f"✓ 已回封 {report['edited_entries']} 条到 {dest}" if phase == "repack"
                             else f"✓ 已导出 {report['body_entries']} 条正文、"
                                  f"{report['name_entries']} 条人名到 {dest}"))
                        self.progress["value"] = 100
                        self._write_details(json.dumps(report, ensure_ascii=False, indent=2))
        except queue.Empty:
            pass
        if not self._closed:
            self._poll_after = self.root.after(100, self._poll)

    def _cancel(self):
        self.cancel_event.set()
        self.status.set("正在取消；已提交的结果不会删除…")

    def _open_output(self):
        path = self.rebuilt_output.get() if Path(self.rebuilt_output.get()).is_dir() \
            else self.text_output.get()
        if path and Path(path).is_dir():
            os.startfile(path)


def main():
    try:
        from tkinterdnd2 import TkinterDnD
        root = TkinterDnD.Tk()
    except (ImportError, RuntimeError, tk.TclError):
        root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
