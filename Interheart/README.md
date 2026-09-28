# 文本提取与回封工具

从归档提取双行文本，编辑后生成新归档。源文件不会被覆盖。
当前程序只支持内置适配器声明的文件结构；它不是任意归档的自动转换器。

## 使用前

- Python 3.11+，包含 Tkinter。图形界面的文件选择无需额外依赖；如需拖放，可安装 `tkinterdnd2`。
- 将 `tools/`、`data.fpk` 和解包所得的 `data/` 放在同一目录。归档与解包文件必须属于同一版本。
- 导出目录默认是 `data_text/`，回封目录默认是 `data_rebuilt/`。已有译文就在 `data_text/` 时，直接回封，**不要重新导出覆盖译文**。
- 当前适配器使用 UTF-8。编码不匹配时停止处理，不会用替代字符凑数。

## 图形界面

在上述目录打开终端，运行：

```powershell
python .\tools\run_gui.py
```

1. 选择 `data/` 或同级 `data.fpk`；确认“回封文本 → 从”是你的译文目录。
2. 首次使用时点“输出文本”，只编辑导出文件中的 `●` 译文行。已有译文则跳过此步。
3. 点“回封文本”，核对预览和输出位置，再确认执行。取消不会生成回封产物。

默认只导出双行文本。需要字符串结构视图时可勾选 ASM；详情中的 IR 用于排查。
导出目录或回封目录已存在时，界面会询问是备份旧结果还是另选目录。

## 命令行

以下命令均在包含 `tools/`、`data/` 的目录运行：

```powershell
# 首次导出；已有 data_text/ 译文时不要执行
python .\tools\disassembler.py .\data --texts -o .\data_text

# 检查现有译文，不写归档
python .\tools\assembler.py .\data_text --data .\data --preview

# 确认预览后，写入新目录
python .\tools\assembler.py .\data_text --data .\data -o .\data_rebuilt
```

如预览列出标记调整，先逐条检查，再给最后一条命令加
`--accept-marker-repairs`；否则回封会停止。这个参数只确认预览中的调整，
不会修改 `data_text/`。调整的断句位置是估算值；不合适就在 `●` 行手动修改。

可用 `--asm` 导出 ASM，`--with-ir` 导出排查数据。输出目录已存在时，
`--overwrite` 会先把旧目录改名备份，不会直接删除。参数以对应入口的
`--help` 为准。

## 文件与编辑

| 位置 | 用途 |
|---|---|
| `data_text/texts/` | 双行文本；只改 `●` 行 |
| `data_text/asm/` | 可选结构视图；只可改 `.string value=` |
| `data_text/manifest.json` | 绑定源版本；不要改 |
| `data_text/_work/reports/` | 导出检查结果 |
| `data_rebuilt/entries/` | 回封后的明文资源，供核对 |
| `data_rebuilt/data.fpk` | 最终归档 |
| `data_rebuilt/report.json` | 回封结果和未验证事项 |

双行文本格式示意（示例文字，不对应实际文件）：

```text
# idx=10000001 tag=name
○10000001○name○原名
●10000001●name●译名

# idx=00000001 tag=msg speaker=原名
○00000001○msg○原句
●00000001●msg●译句
```

`○` 原文、编号、类别、注释和文件头是校验依据，不要改。`name` 的 `●` 行可改，
回封时会同步更新说话人。不要留空译文。字面 `\n` 是原脚本的分行；
`&heart;` 等标记也参与校验。标记数量不符时可预览调整；标记顺序颠倒、
未知字节占位符或原文锚变化仍会被拒绝。普通反斜杠不当作十六进制转义。

同一条若同时改了双行文本和 ASM，两个值必须一致。ASM 的结构行、
指令和行顺序不可改。

回封后先读 `report.json`，再核对 `entries/`。确认无误并备份原归档后，
才把 `data_rebuilt/data.fpk` 复制到目标程序读取归档的位置。
不要把 `entries/` 当成可直接替换的归档。自检通过不等于已在程序中运行。

## 报错

错误信息中的编号、路径和详情以实际输出为准。

| 错误码 | 处理办法 |
|---|---|
| `INPUT_MISSING` | 检查源归档、解包目录或带 `manifest.json` 的译文目录。 |
| `NO_PROJECTION` | 至少导出一种编辑文件；回封前先导出。 |
| `OUTPUT_EXISTS` | 换新输出目录，或明确使用 `--overwrite` 备份旧结果。 |
| `OUTPUT_UNSAFE` | 输出不能指向源文件、源目录或译文目录。 |
| `SOURCE_MISMATCH` | 源与导出清单不一致；换回匹配的源，或重新导出。 |
| `COVERAGE_GAP` | 有未识别的数据区；停止回封并检查格式适配。 |
| `IDENTITY_FAILED` | 零改动无法逐字节还原；不要使用回封结果。 |
| `ENCODING_UNSUPPORTED` | 当前适配器只支持 UTF-8；恢复相应设置。 |
| `ENCODING_UNREPRESENTABLE` | 检查提示的条目和字符；勿使用替代字符。 |
| `TEXT_ENCODING` | 把双行文本保存为 UTF-8。 |
| `TEXT_HEADER` | 恢复导出文件的前四行。 |
| `TEXT_SYNTAX` | 恢复三行条目、分隔符和条目间空行。 |
| `TEXT_ID` | 恢复三行相同且不重复的八位编号。 |
| `TEXT_TAG` | 恢复原来的 `name`、`msg` 等类别。 |
| `TEXT_MISSING` | 放回缺失的导出文件和条目。 |
| `SOURCE_ANCHOR` | 恢复 `○` 原文行及说话人注释。 |
| `EMPTY_TRANSLATION` | 填写非空译文，或保留原文。 |
| `NAME_DELIMITER` | 人名不能包含逗号或全角空格。 |
| `PLACEHOLDER_BROKEN` | 检查标记顺序和字节占位符；无法确认时手动修正。 |
| `MARKER_REPAIR_CONFIRMATION` | 核对预览；GUI 确认，或在命令行加 `--accept-marker-repairs`。 |
| `SOURCE_LAYOUT` | 恢复原脚本所需的分行数。 |
| `ASM_MISSING` | 补齐 ASM 清单，或只使用完整的双行文本。 |
| `ASM_SYNTAX` | `.string value=` 后必须是合法的 JSON 字符串。 |
| `TIER_TOO_LOW` | 只能改已支持的字符串字段；恢复结构行。 |
| `EDIT_CONFLICT` | 统一双行文本与 ASM 对同一条的译文。 |
| `POINTER_OVERFLOW` | 回封数据超出偏移表示范围；缩短译文。 |
| `VERIFY_FAILED` | 输出回读未通过；保留源文件和诊断。 |
| `EDIT_LOST` | 改动没有进入结果；停止使用并检查输入。 |
| `CANCELLED` | 任务已取消；可重新执行。 |
| `FORMAT_ERROR` | 查看错误后的路径或格式详情。 |

## 限制

当前适配器针对特定的 FPK/ZLC2、SPT、PTR/TXD 布局和 UTF-8 文本池；
不自动识别其他布局、编码或归档变体。不能新增或删除人名字段，
不能改变源脚本行数，也不能编辑未解析的 ASM 指令。
尚未完成跨作品验证或目标程序的载入、显示测试。
