COMMON_CODECS = [
    "cp932",
    "shift_jis",
    "cp936",
    "gbk",
    "utf-8",
    "utf-8-sig",
    "utf-16",
]

OUTPUT_MODE_LABELS = {
    "同时输出明文和加密": "both",
    "仅输出明文": "plain_only",
    "仅输出加密": "encrypted_only",
}

OUTPUT_MODE_VALUES = list(OUTPUT_MODE_LABELS.keys())

MAX_LOG_LINES = 500
