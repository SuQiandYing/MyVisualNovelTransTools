"""Translator-facing two-action GUI. All parsing and rebuilding is in the core."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from opcodelist import DIALECT as D
from disassembler import export_project, ToolError
from assembler import prepare_project, execute_prepared


class Application:
    def __init__(self, root: tk.Tk, source: str = ""):
        self.root = root
        root.title("Xuse/Eternal resource archive 脚本提取与回封")
        root.geometry("850x730")
        root.minsize(740, 660)  # dialect-literal-ok: minimum GUI dimensions in logical pixels
        self.events = queue.Queue()
        self.cancelled = threading.Event()
        self.busy = False
        self.follow_import = True
        self.syncing = False
        self.last_output = None
        self.prepared = None
        self.source = tk.StringVar()
        self.text_out = tk.StringVar()
        self.text_in = tk.StringVar()
        self.rebuilt_out = tk.StringVar()
        self.source_encoding = tk.StringVar(value=D["source_encoding"])
        self.target_encoding = tk.StringVar(value=D["target_encoding"])
        self.texts = tk.BooleanVar(value=True)
        self.asm = tk.BooleanVar(value=False)
        self.with_ir = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value="选择原始脚本，输出文本后即可开始翻译。")
        self.inventory = tk.StringVar(value="文件夹或单个 .bin 文件；需要对应的 .debug。")
        self.details_visible = False
        frame = ttk.Frame(root, padding=22)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="脚本数据目录", font=("Microsoft YaHei UI", 13, "bold")).pack(anchor="w", pady=(0, 8))
        source_line = ttk.Frame(frame)
        source_line.pack(fill="x")
        ttk.Entry(source_line, textvariable=self.source).pack(side="left", fill="x", expand=True)
        ttk.Button(source_line, text="文件夹…", command=self.browse_source).pack(side="left", padx=(8, 0))
        ttk.Button(source_line, text="文件…", command=lambda: self.browse_source(True)).pack(side="left", padx=(5, 0))
        ttk.Label(frame, textvariable=self.inventory).pack(anchor="w", pady=(7, 15))
        encodings = ttk.Frame(frame)
        encodings.pack(fill="x", pady=(0, 16))
        choices = ("cp932", "gbk", "big5", "cp949", "utf-8")
        ttk.Label(encodings, text="原文编码").pack(side="left")
        ttk.Combobox(encodings, textvariable=self.source_encoding, values=choices, width=13).pack(side="left", padx=(10, 32))
        ttk.Label(encodings, text="译文编码").pack(side="left")
        ttk.Combobox(encodings, textvariable=self.target_encoding, values=choices, width=13).pack(side="left", padx=10)
        export = ttk.LabelFrame(frame, text="输出文本", padding=15)
        export.pack(fill="x", pady=(0, 15))
        self.path_row(export, "到", self.text_out, lambda: self.browse_output(self.text_out))
        options = ttk.Frame(export)
        options.pack(fill="x", pady=(12, 10))
        ttk.Checkbutton(options, text=r"对话文本（支持 \n 行标记）", variable=self.texts, command=self.update_buttons).pack(side="left")
        ttk.Checkbutton(options, text="ASM 清单（有限字段编辑）", variable=self.asm, command=self.update_buttons).pack(side="left", padx=20)
        self.export_button = ttk.Button(export, text="输 出 文 本", command=self.export)
        self.export_button.pack(fill="x", ipady=5)
        rebuild = ttk.LabelFrame(frame, text="回封文本", padding=15)
        rebuild.pack(fill="x", pady=(0, 17))
        self.path_row(rebuild, "从", self.text_in, lambda: self.browse_output(self.text_in))
        self.path_row(rebuild, "到", self.rebuilt_out, lambda: self.browse_output(self.rebuilt_out), pady=9)
        self.rebuild_button = ttk.Button(rebuild, text="回 封 文 本", command=self.preview)
        self.rebuild_button.pack(fill="x", ipady=5, pady=(12, 0))
        self.progress = ttk.Progressbar(frame, maximum=100)
        self.progress.pack(fill="x")
        status_line = ttk.Frame(frame)
        status_line.pack(fill="x", pady=10)
        ttk.Label(status_line, textvariable=self.status, wraplength=600).pack(side="left", fill="x", expand=True)  # dialect-literal-ok: status label wrapping width in logical pixels
        self.open_button = ttk.Button(status_line, text="打开", command=self.open_output, state="disabled")
        self.open_button.pack(side="left", padx=6)
        self.cancel_button = ttk.Button(status_line, text="取消", command=self.cancelled.set, state="disabled")
        self.cancel_button.pack(side="left")
        self.details_button = ttk.Button(frame, text="▸ 详情", command=self.toggle_details)
        self.details_button.pack(anchor="w", pady=(2, 5))
        self.details_frame = ttk.Frame(frame)
        ttk.Checkbutton(self.details_frame, text="同时导出 IR（排查用）", variable=self.with_ir).pack(anchor="w")
        self.details = tk.Text(self.details_frame, height=7, wrap="word", font=("Consolas", 9), state="disabled")
        self.details.pack(fill="both", expand=True, pady=5)
        self.source.trace_add("write", self.source_changed)
        self.text_out.trace_add("write", self.output_changed)
        self.text_in.trace_add("write", self.import_changed)
        self.source.set(source)
        root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.after(80, self.drain)  # dialect-literal-ok: GUI queue polling interval in milliseconds
        self.install_drag_drop()
        self.update_buttons()

    def path_row(self, parent, label, variable, action, pady=0):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=(pady, 0))
        ttk.Label(row, text=label, width=3).pack(side="left")
        ttk.Entry(row, textvariable=variable).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="浏览…", command=action).pack(side="left", padx=(8, 0))

    def browse_source(self, single=False):
        value = filedialog.askopenfilename(filetypes=[("NORI v65536 脚本", "*.bin")]) if single else filedialog.askdirectory()
        if value:
            self.source.set(value)

    def browse_output(self, variable):
        value = filedialog.askdirectory(mustexist=False)
        if value:
            variable.set(value)

    def source_changed(self, *_):
        value = self.source.get()
        if value:
            source = Path(value)
            stem = source.stem if source.suffix.lower() == ".bin" else source.name
            self.follow_import = True
            self.text_out.set(str(source.with_name(stem + "_text")))
            self.rebuilt_out.set(str(source.with_name(stem + "_rebuilt")))
            self.inventory.set("正在清点脚本…")
            def count():
                try:
                    number = 1 if source.is_file() else sum(1 for _ in source.rglob("*.bin"))
                    self.events.put(("inventory", value, number))
                except OSError:
                    self.events.put(("inventory", value, 0))
            threading.Thread(target=count, daemon=True).start()

    def output_changed(self, *_):
        if self.follow_import:
            self.syncing = True
            self.text_in.set(self.text_out.get())
            self.syncing = False

    def import_changed(self, *_):
        if not self.syncing:
            self.follow_import = False

    def update_buttons(self):
        self.export_button.configure(state="disabled" if self.busy or not (self.texts.get() or self.asm.get()) else "normal")
        self.rebuild_button.configure(state="disabled" if self.busy else "normal")
        self.cancel_button.configure(state="normal" if self.busy else "disabled")
        if not self.texts.get() and not self.asm.get():
            self.status.set("请至少选择一种输出。")

    def available_output(self, variable):
        if not variable.get():
            raise ToolError("OUTPUT_PATH", "请选择输出目录")
        path = Path(variable.get()).resolve()
        if path.exists():
            index = 2
            candidate = path.with_name(path.name + f"_{index}")
            while candidate.exists():
                index += 1
                candidate = path.with_name(path.name + f"_{index}")
            if not messagebox.askyesno("另存新目录", f"输出目录已经存在。\n\n另存到：\n{candidate} ？"):
                return None
            variable.set(str(candidate))
            return candidate
        return path

    def launch(self, function, stage):
        self.busy = True
        self.cancelled.clear()
        self.status.set(stage)
        self.progress["value"] = 0
        self.update_buttons()
        def work():
            try:
                result = function()
                self.events.put(("result", stage, result))
            except Exception as exc:
                self.events.put(("error", exc))
        threading.Thread(target=work, daemon=True).start()

    def report_progress(self, done, total, name):
        self.events.put(("progress", done, total, name))

    def export(self):
        try:
            output = self.available_output(self.text_out)
            if output is None:
                return
            # Snapshot all Tk variables before entering the worker thread.
            args = (Path(self.source.get()), output, self.source_encoding.get(), self.target_encoding.get(),
                    self.texts.get(), self.asm.get(), self.with_ir.get())
            self.launch(lambda: export_project(*args, progress=self.report_progress, cancel=self.cancelled.is_set), "正在输出文本")
        except Exception as exc:
            self.show_error(exc)

    def preview(self):
        try:
            output = self.available_output(self.rebuilt_out)
            if output is None:
                return
            input_path = Path(self.text_in.get())
            self.launch(lambda: prepare_project(input_path, output, progress=self.report_progress,
                                                cancel=self.cancelled.is_set), "正在检查译文并准备预览")
        except Exception as exc:
            self.show_error(exc)

    def show_preview(self, prepared):
        self.prepared = prepared
        summary = prepared.summary
        window = tk.Toplevel(self.root)
        window.title("回封预览")
        window.transient(self.root)
        window.grab_set()
        content = ttk.Frame(window, padding=24)
        content.pack(fill="both", expand=True)
        is_whole = summary["text_projection"] != "segments-v1"
        change_line = (f"改动 {summary['logical_message_changes']} 条整句对话，涉及 {summary['changed_files']} 个脚本\n"
                      if is_whole else f"改动 {summary['changed_entries']} 条文本条目，涉及 {summary['changed_files']} 个脚本\n")
        text = (f"将回封 {summary['source_files']} 个文件\n\n" + change_line
                + f"共回写 {summary['changed_entries']} 个文本槽（含人名、选项等）\n"
                + f"其中 {summary['growing_entries']} 个槽加长，追加 {summary['append_bytes']} 字节\n"
                + f"冲突 0\n编码 {summary['source_encoding']} → {summary['target_encoding']}\n\n"
                + f"输出到：\n{prepared.output}")
        ttk.Label(content, text=text, wraplength=600, justify="left").pack(anchor="w")  # dialect-literal-ok: preview label wrapping width in logical pixels
        buttons = ttk.Frame(content)
        buttons.pack(fill="x", pady=(22, 0))
        def execute():
            window.destroy()
            self.launch(lambda: execute_prepared(prepared, self.report_progress, self.cancelled.is_set), "正在回封文本")
        ttk.Button(buttons, text="执行", command=execute).pack(side="right")
        ttk.Button(buttons, text="取消", command=window.destroy).pack(side="right", padx=10)

    def show_error(self, exc):
        self.busy = False
        self.status.set(str(exc))
        self.set_details(str(exc))
        self.update_buttons()
        messagebox.showerror("操作未完成", str(exc))

    def drain(self):
        try:
            while True:
                event = self.events.get_nowait()
                if event[0] == "inventory":
                    if self.source.get() == event[1]:
                        self.inventory.set(f"已找到 {event[2]} 个脚本文件")
                elif event[0] == "progress":
                    _, done, total, name = event
                    self.progress["value"] = done / max(total, 1) * 100
                    self.status.set(f"正在处理 {name}  {done}/{total}")
                elif event[0] == "error":
                    self.show_error(event[1])
                elif event[0] == "result":
                    self.busy = False
                    self.update_buttons()
                    result = event[2]
                    if hasattr(result, "plans"):
                        self.status.set("检查完成，请确认回封预览。")
                        self.show_preview(result)
                    else:
                        self.last_output = result["output"]
                        self.open_button.configure(state="normal")
                        self.progress["value"] = 100
                        self.status.set(f"✓ 已完成，输出到 {result['output']}")
                        self.set_details("\n".join(f"{key}: {value}" for key, value in result.items()))
        except queue.Empty:
            pass
        self.root.after(80, self.drain)  # dialect-literal-ok: GUI queue polling interval in milliseconds

    def set_details(self, text):
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def toggle_details(self):
        self.details_visible = not self.details_visible
        if self.details_visible:
            self.details_frame.pack(fill="both", expand=True)
        else:
            self.details_frame.pack_forget()
        self.details_button.configure(text="▾ 详情" if self.details_visible else "▸ 详情")

    def install_drag_drop(self):
        try:
            import windnd
        except ImportError:
            self.set_details("拖放组件 windnd 未安装；可直接使用『文件夹…』或『文件…』。\n核心功能只使用 Python 标准库。")
            return
        def dropped(paths):
            # Unicode API is mandatory. Invalid ANSI replacement is never repaired by guessing.
            values = [p.decode("utf-16-le") if isinstance(p, bytes) else str(p) for p in paths]
            if values:
                value = values[0].rstrip("\x00")
                if Path(value).exists():
                    self.source.set(value)
                else:
                    messagebox.showerror("路径不存在", f"收到的路径不存在：\n{value}\n请改用选择文件按钮。")
        windnd.hook_dropfiles(self.root, func=dropped, force_unicode=True)

    def open_output(self):
        if self.last_output:
            os.startfile(self.last_output)

    def close(self):
        if self.busy:
            self.cancelled.set()
            self.status.set("正在取消；结束后可关闭窗口。")
        else:
            self.root.destroy()


def main():
    parser = argparse.ArgumentParser(description="Xuse/Eternal resource archive 脚本文本提取与回封界面（处理已解出的 NORI v65536 容器）")
    parser.add_argument("source", nargs="?", default="")
    args = parser.parse_args()
    root = tk.Tk()
    Application(root, args.source)
    root.mainloop()


if __name__ == "__main__":
    main()
