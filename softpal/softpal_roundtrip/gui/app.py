from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError:
    DND_FILES = None
    TkinterDnD = None

from .actions import GuiActionsMixin
from .config import load_config, reset_config, save_config
from .constants import COMMON_CODECS, MAX_LOG_LINES, OUTPUT_MODE_VALUES


class SoftpalToolGUI(GuiActionsMixin):
    def __init__(self) -> None:
        root_cls = TkinterDnD.Tk if TkinterDnD is not None else tk.Tk
        self.root = root_cls()
        self.root.title("SoftPal 文本工具 GUI")
        self.root.geometry("1360x900")
        self.root.minsize(1120, 760)

        self.palette = {
            "bg": "#fff7fb",
            "bg_soft": "#fffbfd",
            "panel": "#fffdfd",
            "panel_edge": "#eadce5",
            "accent": "#f68bb9",
            "accent_soft": "#fbe2ec",
            "accent_deep": "#ea6ea4",
            "accent_blue": "#87b8ff",
            "text": "#5e4d62",
            "text_soft": "#93818f",
            "log_bg": "#fffefe",
            "log_edge": "#ead9e3",
        }

        self._setup_theme()

        cwd = Path.cwd()
        self._default_values = {
            "project_dir": str(cwd),
            "script_path": "",
            "text_path": "",
            "dump_dir": str(cwd / "disasm_out"),
            "translation_path": str(cwd / "translate_dump.txt"),
            "scenario_dir": str(cwd / "scenario_txt"),
            "output_dir": str(cwd / "rebuild_relocate"),
            "text_codec": "cp932",
            "edited_encoding": "cp932",
            "translation_file_encoding": "utf-8",
            "idx_start": "",
            "idx_end": "",
            "script_offset": "",
            "anchor_idx": "",
            "output_mode": OUTPUT_MODE_VALUES[-1] if OUTPUT_MODE_VALUES else "",
            "status_text": "待命中",
        }
        self.project_dir = tk.StringVar(value=str(cwd))
        self.script_path = tk.StringVar()
        self.text_path = tk.StringVar()
        self.dump_dir = tk.StringVar(value=str(cwd / "disasm_out"))
        self.translation_path = tk.StringVar(value=str(cwd / "translate_dump.txt"))
        self.scenario_dir = tk.StringVar(value=str(cwd / "scenario_txt"))
        self.output_dir = tk.StringVar(value=str(cwd / "rebuild_relocate"))
        self.text_codec = tk.StringVar(value="cp932")
        self.edited_encoding = tk.StringVar(value="cp932")
        self.translation_file_encoding = tk.StringVar(value="utf-8")
        self.idx_start = tk.StringVar(value="")
        self.idx_end = tk.StringVar(value="")
        self.script_offset = tk.StringVar(value="")
        self.anchor_idx = tk.StringVar(value="")
        self.output_mode = tk.StringVar(value="仅输出加密")
        self.status_text = tk.StringVar(value="待机中")

        self._action_buttons: list[tk.Widget] = []
        self._busy = False
        self._suspend_config_save = False

        self._load_config()
        for var in self._config_vars():
            var.trace_add("write", self._save_config)

        self._build_ui()
        self._auto_detect_from_project(silent=True)

    def _setup_theme(self) -> None:
        p = self.palette
        self.root.configure(bg=p["bg"])
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("App.TFrame", background=p["bg"])
        style.configure("Card.TFrame", background=p["panel"], relief="flat")
        style.configure("Header.TFrame", background=p["bg"])
        style.configure("Section.TLabelframe", background=p["panel"], borderwidth=1, relief="solid")
        style.configure("Section.TLabelframe.Label", background=p["panel"], foreground=p["accent_deep"], font=("Microsoft YaHei UI", 10, "bold"))
        style.configure("Title.TLabel", background=p["bg"], foreground=p["accent_deep"], font=("Microsoft YaHei UI", 22, "bold"))
        style.configure("SubTitle.TLabel", background=p["bg"], foreground=p["text_soft"], font=("Microsoft YaHei UI", 10))
        style.configure("CardTitle.TLabel", background=p["panel"], foreground=p["text"], font=("Microsoft YaHei UI", 11, "bold"))
        style.configure("CardHint.TLabel", background=p["panel"], foreground=p["text_soft"], font=("Microsoft YaHei UI", 9))
        style.configure("Badge.TLabel", background=p["accent_soft"], foreground=p["accent_deep"], font=("Microsoft YaHei UI", 9, "bold"), padding=(10, 4))
        style.configure("Status.TLabel", background=p["panel"], foreground=p["text"], font=("Microsoft YaHei UI", 10, "bold"))
        style.configure("FieldLabel.TLabel", background=p["panel"], foreground=p["text"], font=("Microsoft YaHei UI", 10, "bold"))
        style.configure("Primary.TButton", font=("Microsoft YaHei UI", 10, "bold"))
        style.configure("Tool.TNotebook", background=p["panel"], borderwidth=0, tabmargins=(0, 0, 0, 0))
        style.configure(
            "Tool.TNotebook.Tab",
            padding=(18, 10),
            font=("Microsoft YaHei UI", 10, "bold"),
            background="#f8eef4",
            foreground=p["text_soft"],
            borderwidth=0,
        )
        style.map(
            "Tool.TNotebook.Tab",
            background=[
                ("selected", p["panel"]),
                ("active", "#fff4f8"),
            ],
            foreground=[
                ("selected", p["accent_deep"]),
                ("active", p["text"]),
            ],
        )

        style.configure(
            "Soft.TButton",
            background=p["accent_soft"],
            foreground=p["text"],
            borderwidth=0,
            padding=(12, 9),
            focusthickness=0,
        )
        style.map(
            "Soft.TButton",
            background=[("active", "#fce9f1"), ("pressed", "#f7d4e3")],
            foreground=[("active", p["accent_deep"])],
        )
        style.configure(
            "Primary.TButton",
            background=p["accent"],
            foreground="#ffffff",
            borderwidth=0,
            padding=(12, 10),
            focusthickness=0,
        )
        style.map(
            "Primary.TButton",
            background=[("active", "#e5679d"), ("pressed", "#d95b91")],
            foreground=[("active", "#ffffff")],
        )
        style.configure(
            "Soft.TEntry",
            fieldbackground="#fffafd",
            foreground=p["text"],
            bordercolor=p["panel_edge"],
            lightcolor=p["panel_edge"],
            darkcolor=p["panel_edge"],
            padding=7,
        )
        style.map(
            "Soft.TEntry",
            fieldbackground=[("focus", "#ffffff")],
        )
        style.configure(
            "Soft.TCombobox",
            fieldbackground="#fffafd",
            foreground=p["text"],
            bordercolor=p["panel_edge"],
            lightcolor=p["panel_edge"],
            darkcolor=p["panel_edge"],
            background="#fbe7ef",
            borderwidth=1,
            relief="flat",
            padding=(10, 8, 34, 8),
            arrowsize=16,
            arrowcolor=p["accent_deep"],
            insertcolor=p["text"],
        )
        style.map(
            "Soft.TCombobox",
            fieldbackground=[
                ("readonly", "#fff7fb"),
                ("focus", "#ffffff"),
            ],
            background=[
                ("readonly", "#fbe7ef"),
                ("active", "#f7dce8"),
            ],
            foreground=[
                ("readonly", p["text"]),
                ("focus", p["text"]),
            ],
            arrowcolor=[
                ("readonly", p["accent_deep"]),
                ("active", p["accent_deep"]),
            ],
        )
        style.configure(
            "Action.Secondary.TButton",
            background="#f6d7e4",
            foreground=p["accent_deep"],
            borderwidth=0,
            padding=(14, 12),
            focusthickness=0,
            font=("Microsoft YaHei UI", 10, "bold"),
        )
        style.map(
            "Action.Secondary.TButton",
            background=[("active", "#efbfd3"), ("pressed", "#e9b0c8")],
            foreground=[("active", p["accent_deep"])],
        )
        style.configure(
            "Action.Primary.TButton",
            background="#f6d7e4",
            foreground=p["accent_deep"],
            borderwidth=0,
            padding=(14, 12),
            focusthickness=0,
            font=("Microsoft YaHei UI", 10, "bold"),
        )
        style.map(
            "Action.Primary.TButton",
            background=[("active", "#efbfd3"), ("pressed", "#e9b0c8")],
            foreground=[("active", p["accent_deep"])],
        )

    def _config_vars(self) -> list[tk.StringVar]:
        return [
            self.project_dir,
            self.script_path,
            self.text_path,
            self.dump_dir,
            self.translation_path,
            self.scenario_dir,
            self.output_dir,
            self.text_codec,
            self.edited_encoding,
            self.translation_file_encoding,
            self.idx_start,
            self.idx_end,
            self.script_offset,
            self.anchor_idx,
            self.output_mode,
        ]

    def _build_ui(self) -> None:
        shell = ttk.Frame(self.root, style="App.TFrame", padding=22)
        shell.pack(fill="both", expand=True)
        shell.columnconfigure(0, weight=1)
        shell.rowconfigure(1, weight=1)

        self._build_header(shell)

        content = ttk.Frame(shell, style="App.TFrame")
        content.grid(row=1, column=0, sticky="nsew", pady=(16, 0))
        content.columnconfigure(0, weight=38)
        content.columnconfigure(1, weight=62)
        content.rowconfigure(0, weight=1)

        self._build_left_panel(content)
        self._build_right_panel(content)

    def _build_header(self, parent: ttk.Frame) -> None:
        header = ttk.Frame(parent, style="Header.TFrame")
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)
        header.columnconfigure(1, weight=0)

        title_box = ttk.Frame(header, style="Header.TFrame")
        title_box.grid(row=0, column=0, sticky="w")

        top_line = ttk.Frame(title_box, style="Header.TFrame")
        top_line.pack(anchor="w")
        ttk.Label(top_line, text="SoftPal 文本工具箱", style="Title.TLabel").pack(side="left")

        deco = tk.Canvas(header, width=180, height=64, bg=self.palette["bg"], highlightthickness=0)
        deco.grid(row=0, column=1, sticky="e")
        deco.create_oval(10, 18, 36, 44, fill="#ffd6ea", outline="")
        deco.create_oval(42, 8, 68, 34, fill="#cfe3ff", outline="")
        deco.create_oval(74, 20, 102, 48, fill="#ffe8c7", outline="")
        deco.create_oval(110, 10, 156, 56, fill="#fff0f8", outline="#f7d5e6", width=1)
        deco.create_text(133, 33, text="★", fill=self.palette["accent_deep"], font=("Segoe UI Symbol", 16, "bold"))

    def _build_left_panel(self, parent: ttk.Frame) -> None:
        left = ttk.Frame(parent, style="Card.TFrame", padding=20)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        left.columnconfigure(0, weight=1)

        ttk.Label(left, text="项目与输入", style="CardTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(left, text="这里放路径、编码、范围和回封参数。", style="CardHint.TLabel").grid(row=1, column=0, sticky="w", pady=(2, 10))

        path_frame = ttk.LabelFrame(left, text="路径设置", style="Section.TLabelframe", padding=14)
        path_frame.grid(row=2, column=0, sticky="ew")
        path_frame.columnconfigure(0, minsize=92)
        path_frame.columnconfigure(1, weight=1)
        path_frame.columnconfigure(2, minsize=74)

        self._add_path_row(path_frame, 0, "项目目录", self.project_dir, browse=lambda: self._choose_dir(self.project_dir, auto_detect=True), drop_handler=self._handle_project_drop)
        self._add_path_row(path_frame, 1, "SCRIPT.SRC", self.script_path, browse=lambda: self._choose_file(self.script_path, [("SRC", "*.SRC"), ("All", "*.*")]), drop_handler=lambda p: self._set_path(self.script_path, p))
        self._add_path_row(path_frame, 2, "TEXT.DAT", self.text_path, browse=lambda: self._choose_file(self.text_path, [("DAT", "*.DAT"), ("All", "*.*")]), drop_handler=lambda p: self._set_path(self.text_path, p))
        self._add_path_row(path_frame, 3, "Dump 目录", self.dump_dir, browse=lambda: self._choose_dir(self.dump_dir), drop_handler=lambda p: self._set_path(self.dump_dir, p))
        self._add_path_row(path_frame, 4, "翻译文本", self.translation_path, browse=lambda: self._choose_file(self.translation_path, [("Text", "*.txt"), ("All", "*.*")]), drop_handler=lambda p: self._set_path(self.translation_path, p))
        self._add_path_row(path_frame, 5, "Scenario 目录", self.scenario_dir, browse=lambda: self._choose_dir(self.scenario_dir), drop_handler=lambda p: self._set_path(self.scenario_dir, p))
        self._add_path_row(path_frame, 6, "输出目录", self.output_dir, browse=lambda: self._choose_dir(self.output_dir), drop_handler=lambda p: self._set_path(self.output_dir, p))

        detect_bar = ttk.Frame(path_frame, style="Card.TFrame")
        detect_bar.grid(row=7, column=0, columnspan=3, sticky="ew", pady=(10, 0))
        ttk.Button(detect_bar, text="自动识别项目文件", command=self._auto_detect_from_project, style="Primary.TButton").pack(side="left")
        ttk.Button(detect_bar, text="重置配置", command=self._reset_gui_config, style="Soft.TButton").pack(side="left", padx=(8, 0))
        ttk.Label(detect_bar, text="支持拖放目录自动补全常用路径。", style="CardHint.TLabel").pack(side="left", padx=(10, 0))

        option_frame = ttk.LabelFrame(left, text="参数选项", style="Section.TLabelframe", padding=14)
        option_frame.grid(row=3, column=0, sticky="ew", pady=(14, 0))
        option_frame.columnconfigure(0, weight=0, minsize=96)
        option_frame.columnconfigure(1, weight=1, uniform="option_fields")
        option_frame.columnconfigure(2, weight=0, minsize=96)
        option_frame.columnconfigure(3, weight=1, uniform="option_fields")

        self._add_combo(option_frame, 0, 0, "提取解码", self.text_codec, COMMON_CODECS)
        self._add_combo(option_frame, 0, 2, "回封编码", self.edited_encoding, COMMON_CODECS)
        self._add_combo(option_frame, 1, 0, "翻译文本编码", self.translation_file_encoding, ["utf-16", "utf-8-sig", "utf-8"])
        self._add_combo(option_frame, 1, 2, "回封输出", self.output_mode, OUTPUT_MODE_VALUES, readonly=True)
        self._add_labeled_entry(option_frame, 2, 0, "起始 idx", self.idx_start)
        self._add_labeled_entry(option_frame, 2, 2, "结束 idx", self.idx_end)
        self._add_labeled_entry(option_frame, 3, 0, "脚本地址", self.script_offset)
        self._add_labeled_entry(option_frame, 3, 2, "锚点 idx", self.anchor_idx)

        status_card = ttk.LabelFrame(left, text="运行状态", style="Section.TLabelframe", padding=14)
        status_card.grid(row=4, column=0, sticky="ew", pady=(14, 0))
        status_card.columnconfigure(0, weight=1)
        self.progress = ttk.Progressbar(status_card, mode="indeterminate")
        self.progress.grid(row=0, column=0, sticky="ew")
        ttk.Label(status_card, textvariable=self.status_text, style="Status.TLabel").grid(row=1, column=0, sticky="w", pady=(10, 0))

    def _build_right_panel(self, parent: ttk.Frame) -> None:
        right = ttk.Frame(parent, style="Card.TFrame", padding=20)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)
        right.rowconfigure(2, weight=1)

        top_bar = ttk.Frame(right, style="Card.TFrame")
        top_bar.grid(row=0, column=0, sticky="ew")
        top_bar.columnconfigure(0, weight=1)
        ttk.Label(top_bar, text="工作台", style="CardTitle.TLabel").grid(row=0, column=0, sticky="w")

        self.notebook = ttk.Notebook(right, style="Tool.TNotebook")
        self.notebook.grid(row=1, column=0, sticky="nsew", pady=(14, 14))

        action_tab = ttk.Frame(self.notebook, style="Card.TFrame", padding=14)
        action_tab.columnconfigure(0, weight=1)
        action_tab.columnconfigure(1, weight=1)
        action_tab.columnconfigure(2, weight=1)
        self.notebook.add(action_tab, text="操作面板")

        help_tab = ttk.Frame(self.notebook, style="Card.TFrame", padding=14)
        help_tab.columnconfigure(0, weight=1)
        help_tab.rowconfigure(0, weight=1)
        self.notebook.add(help_tab, text="使用说明")

        self._build_action_cards(action_tab)
        self._build_help_tab(help_tab)

        log_frame = ttk.LabelFrame(right, text="日志输出", style="Section.TLabelframe", padding=10)
        log_frame.grid(row=2, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_text = tk.Text(
            log_frame,
            wrap="word",
            height=16,
            font=("Consolas", 10),
            bg=self.palette["log_bg"],
            fg=self.palette["text"],
            insertbackground=self.palette["accent_deep"],
            relief="flat",
            padx=12,
            pady=12,
            bd=0,
            highlightthickness=1,
            highlightbackground=self.palette["log_edge"],
        )
        self.log_text.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=scrollbar.set)

    def _build_action_cards(self, parent: ttk.Frame) -> None:
        cards = [
            ("反汇编与定位", "先解析 SCRIPT.SRC / TEXT.DAT，并自动尝试定位锚点。", [("1. 反汇编脚本", self._task_dump_and_export)]),
            ("导出文本", "导出整包译文，或按场景拆分导出。", [("2. 导出译文", self._task_export_only), ("3. 分场景导出", self._task_export_scenarios)]),
            ("导入并回封", "把修改后的文本导入并重新回封。", [("4. 导入并回封", self._task_import_and_rebuild_relocate), ("5. 分场景导入", self._task_import_scenarios_and_rebuild_relocate)]),
        ]

        for idx in range(3):
            parent.columnconfigure(idx, weight=1, uniform="action_cards")

        for idx, (title, hint, buttons) in enumerate(cards):
            card = ttk.LabelFrame(parent, text=title, style="Section.TLabelframe", padding=14)
            card.grid(row=0, column=idx, sticky="nsew", padx=(0 if idx == 0 else 10, 0))
            card.columnconfigure(0, weight=1)
            card.rowconfigure(0, weight=1, minsize=92)
            hint_label = ttk.Label(
                card,
                text=hint,
                style="CardHint.TLabel",
                wraplength=1,
                justify="left",
                anchor="nw",
            )
            hint_label.grid(row=0, column=0, sticky="nsew", pady=(0, 14))
            hint_label.bind(
                "<Configure>",
                lambda event, label=hint_label: label.configure(wraplength=max(event.width - 6, 60)),
            )
            for button_row, (text, command) in enumerate(buttons, start=1):
                style = "Action.Primary.TButton" if idx == 0 and button_row == 1 else "Action.Secondary.TButton"
                top_padding = 0 if button_row == 1 else 10
                self._add_action_button(card, button_row, text, command, style=style, pady=(top_padding, 0))

    def _build_help_tab(self, parent: ttk.Frame) -> None:
        help_text = tk.Text(
            parent,
            wrap="word",
            relief="flat",
            bg=self.palette["panel"],
            fg=self.palette["text"],
            font=("Microsoft YaHei UI", 10),
            padx=10,
            pady=10,
            bd=0,
            highlightthickness=1,
            highlightbackground=self.palette["log_edge"],
            insertbackground=self.palette["accent_deep"],
        )
        help_text.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=help_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        help_text.configure(yscrollcommand=scrollbar.set)

        help_text.insert(
            "1.0",
            "推荐流程\n\n"
            "1. 先选择项目目录，点“自动识别项目文件”。\n"
            "2. 点“1. 反汇编脚本”，生成 dump 并尝试自动定位。\n"
            "3. 按需要点“2. 导出译文”或“3. 分场景导出”。\n"
            "4. 修改文本后，再执行“4. 导入并回封”或“5. 分场景导入”。\n\n"
            "路径说明\n\n"
            "项目目录：自动识别路径时使用的根目录。\n"
            "SCRIPT.SRC：原始脚本文件，反汇编和回封都需要。\n"
            "TEXT.DAT：原始文本文件，反汇编和回封都需要。\n"
            "Dump 目录：反汇编后的中间数据目录，后续导出、导入、回封都依赖它。\n"
            "翻译文本：单文件导出/导入时使用的译文 txt 文件。\n"
            "Scenario 目录：按场景拆分导出或导入时使用的目录。\n"
            "输出目录：回封结果输出位置。\n\n"
            "参数说明\n\n"
            "提取解码：读取 TEXT.DAT 时使用的编码，选错会导致导出乱码。\n"
            "回封编码：把修改后的文本写回时使用的编码，通常应与原工程一致。\n"
            "翻译文本编码：你编辑的 txt 文件本身的编码，不是游戏内部编码。\n"
            "回封输出：可选“同时输出明文和加密”“仅输出明文”“仅输出加密”。\n"
            "起始 idx：只导出/导入某段文本时的起始索引，留空表示不限制。\n"
            "结束 idx：只导出/导入某段文本时的结束索引，留空表示不限制。\n"
            "脚本地址：自动定位得到的参考位置，回封会更新整份脚本的文本引用。\n"
            "锚点 idx：自动定位得到的参考文本编号，不限制导入或回封范围。\n\n"
            "补充说明\n\n"
            "自动识别项目文件：按项目目录自动补全常用路径。\n"
            "重置配置：清空已保存配置并恢复默认值。\n"
            "如果导出乱码，优先检查“提取解码”和“翻译文本编码”。\n"
            "如果回封异常，优先检查是否已经先执行过“1. 反汇编脚本”。\n"
        )
        help_text.configure(state="disabled")


    def _add_combo(
        self,
        parent: ttk.Widget,
        row: int,
        column: int,
        label: str,
        variable: tk.StringVar,
        values: list[str],
        *,
        readonly: bool = False,
    ) -> None:
        ttk.Label(parent, text=label, anchor="w", style="FieldLabel.TLabel").grid(row=row, column=column, sticky="ew", padx=(6, 10), pady=6)
        state = "readonly" if readonly else "normal"
        combo = ttk.Combobox(parent, textvariable=variable, values=values, state=state, style="Soft.TCombobox")
        combo.configure(height=max(len(values), 3))
        combo.grid(row=row, column=column + 1, sticky="ew", padx=(0, 6), pady=6)

    def _add_labeled_entry(
        self,
        parent: ttk.Widget,
        row: int,
        column: int,
        label: str,
        variable: tk.StringVar,
    ) -> None:
        ttk.Label(parent, text=label, anchor="w", style="FieldLabel.TLabel").grid(row=row, column=column, sticky="ew", padx=(6, 10), pady=6)
        ttk.Entry(parent, textvariable=variable, style="Soft.TEntry").grid(row=row, column=column + 1, sticky="ew", padx=(0, 6), pady=6)

    def _add_path_row(self, parent: ttk.Widget, row: int, label: str, variable: tk.StringVar, *, browse, drop_handler) -> None:
        ttk.Label(parent, text=label, anchor="w", style="FieldLabel.TLabel").grid(row=row, column=0, sticky="ew", padx=(6, 10), pady=7)
        entry = ttk.Entry(parent, textvariable=variable, style="Soft.TEntry")
        entry.grid(row=row, column=1, sticky="ew", padx=(0, 8), pady=7)
        ttk.Button(parent, text="浏览", command=browse, width=8, style="Soft.TButton").grid(row=row, column=2, sticky="e", padx=(0, 4), pady=7)
        self._register_drop(entry, drop_handler)

    def _add_action_button(
        self,
        parent: ttk.Widget,
        row: int,
        text: str,
        command,
        *,
        style: str = "TButton",
        pady: int | tuple[int, int] = 4,
    ) -> None:
        is_primary = style == "Action.Primary.TButton"
        button = tk.Button(
            parent,
            text=text,
            command=command,
            font=("Microsoft YaHei UI", 10, "bold"),
            bg="#f6d7e4",
            fg=self.palette["accent_deep"],
            activebackground="#efbfd3",
            activeforeground=self.palette["accent_deep"],
            relief="flat",
            bd=0,
            padx=10,
            pady=10,
            wraplength=200,
            justify="center",
            cursor="hand2",
            disabledforeground="#b59daa",
            highlightthickness=0,
        )
        if is_primary:
            button.configure(bg="#f6d7e4", fg=self.palette["accent_deep"])
        button.grid(row=row, column=0, sticky="ew", pady=pady)
        self._action_buttons.append(button)

    def _register_drop(self, widget: ttk.Entry, handler) -> None:
        if DND_FILES is None:
            return
        widget.drop_target_register(DND_FILES)

        def on_drop(event) -> None:
            paths = [Path(item) for item in self.root.tk.splitlist(event.data)]
            if paths:
                handler(paths[0])

        widget.dnd_bind("<<Drop>>", on_drop)

    def _set_path(self, variable: tk.StringVar, path: Path) -> None:
        variable.set(str(path))

    def _choose_file(self, variable: tk.StringVar, filetypes) -> None:
        initial = self._existing_parent(variable.get(), self.project_dir.get())
        result = filedialog.askopenfilename(initialdir=initial, filetypes=filetypes)
        if result:
            variable.set(result)

    def _choose_dir(self, variable: tk.StringVar, *, auto_detect: bool = False) -> None:
        initial = self._existing_parent(variable.get(), self.project_dir.get())
        result = filedialog.askdirectory(initialdir=initial)
        if result:
            variable.set(result)
            if auto_detect:
                self._auto_detect_from_project()

    def _existing_parent(self, path_text: str, fallback: str) -> str:
        path = Path(path_text) if path_text else Path(fallback)
        if path.is_file():
            path = path.parent
        return str(path if path.exists() else Path(fallback))

    def _handle_project_drop(self, path: Path) -> None:
        self.project_dir.set(str(path if path.is_dir() else path.parent))
        self._auto_detect_from_project()

    def _find_file_case_insensitive(self, base: Path, name: str) -> Path | None:
        target = name.lower()
        for item in base.iterdir():
            if item.name.lower() == target:
                return item
        return None

    def _show_error(self, title: str, text: str) -> None:
        messagebox.showerror(title, text)

    def _set_busy(self, busy: bool, status: str) -> None:
        self._busy = busy
        self.status_text.set(status)
        for button in self._action_buttons:
            button.configure(state="disabled" if busy else "normal")
        if busy:
            self.progress.start(10)
        else:
            self.progress.stop()

    def _set_status(self, text: str) -> None:
        self.status_text.set(text)

    def _append_log(self, text: str) -> None:
        self.log_text.insert("end", text)
        lines = int(self.log_text.index("end-1c").split(".")[0]) - 1
        if lines > MAX_LOG_LINES:
            self.log_text.delete("1.0", f"{lines - MAX_LOG_LINES + 1}.0")
        self.log_text.see("end")

    def _save_config(self, *_args) -> None:
        if self._suspend_config_save:
            return
        save_config(
            {
                "project_dir": self.project_dir.get(),
                "script_path": self.script_path.get(),
                "text_path": self.text_path.get(),
                "dump_dir": self.dump_dir.get(),
                "translation_path": self.translation_path.get(),
                "scenario_dir": self.scenario_dir.get(),
                "output_dir": self.output_dir.get(),
                "text_codec": self.text_codec.get(),
                "edited_encoding": self.edited_encoding.get(),
                "translation_file_encoding": self.translation_file_encoding.get(),
                "idx_start": self.idx_start.get(),
                "idx_end": self.idx_end.get(),
                "script_offset": self.script_offset.get(),
                "anchor_idx": self.anchor_idx.get(),
                "output_mode": self.output_mode.get(),
            }
        )

    def _apply_default_config(self) -> None:
        defaults = self._default_values
        self.project_dir.set(defaults["project_dir"])
        self.script_path.set(defaults["script_path"])
        self.text_path.set(defaults["text_path"])
        self.dump_dir.set(defaults["dump_dir"])
        self.translation_path.set(defaults["translation_path"])
        self.scenario_dir.set(defaults["scenario_dir"])
        self.output_dir.set(defaults["output_dir"])
        self.text_codec.set(defaults["text_codec"])
        self.edited_encoding.set(defaults["edited_encoding"])
        self.translation_file_encoding.set(defaults["translation_file_encoding"])
        self.idx_start.set(defaults["idx_start"])
        self.idx_end.set(defaults["idx_end"])
        self.script_offset.set(defaults["script_offset"])
        self.anchor_idx.set(defaults["anchor_idx"])
        self.output_mode.set(defaults["output_mode"])
        self.status_text.set(defaults["status_text"])

    def _reset_gui_config(self) -> None:
        if self._busy:
            self._show_error("当前忙碌", "请等待当前任务完成后再重置配置。")
            return
        if not messagebox.askyesno("重置配置", "确定要清空保存的配置并恢复默认值吗？"):
            return

        self._suspend_config_save = True
        try:
            reset_config()
            self._apply_default_config()
            self._auto_detect_from_project(silent=True)
        finally:
            self._suspend_config_save = False

        self._save_config()
        self._set_status("配置已重置")
        self._append_log("[INFO] 已重置配置并恢复默认值。\n")

    def _load_config(self) -> None:
        config = load_config()
        self.project_dir.set(config.get("project_dir", self.project_dir.get()))
        self.script_path.set(config.get("script_path", self.script_path.get()))
        self.text_path.set(config.get("text_path", self.text_path.get()))
        self.dump_dir.set(config.get("dump_dir", self.dump_dir.get()))
        self.translation_path.set(config.get("translation_path", self.translation_path.get()))
        self.scenario_dir.set(config.get("scenario_dir", self.scenario_dir.get()))
        self.output_dir.set(config.get("output_dir", self.output_dir.get()))
        self.text_codec.set(config.get("text_codec", self.text_codec.get()))
        self.edited_encoding.set(config.get("edited_encoding", self.edited_encoding.get()))
        self.translation_file_encoding.set(config.get("translation_file_encoding", self.translation_file_encoding.get()))
        self.idx_start.set(config.get("idx_start", self.idx_start.get()))
        self.idx_end.set(config.get("idx_end", self.idx_end.get()))
        self.script_offset.set(config.get("script_offset", self.script_offset.get()))
        self.anchor_idx.set(config.get("anchor_idx", self.anchor_idx.get()))
        self.output_mode.set(config.get("output_mode", self.output_mode.get()))

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    SoftpalToolGUI().run()
