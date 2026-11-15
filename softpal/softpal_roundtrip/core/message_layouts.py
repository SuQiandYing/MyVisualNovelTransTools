from __future__ import annotations

import re

from .errors import MessageLayoutError


# Argument order is the PUSH order (the final argument is the stack top).
# Both message extraction and text relocation consume these verified layouts.
# See vm_analysis.md for native handler and corpus evidence.
MESSAGE_ARGUMENT_ROLES = {
    0x00020002: ("flags", "text", "name", "line"),
    0x0002000F: ("flags", "text", "name", "line"),
    0x00020012: ("flags", "text", "name", "line"),
    0x00020013: ("flags", "text", "name", "line"),
    0x00020014: ("text", "name", "line"),
}


def looks_like_inline_dialogue(text: str) -> bool:
    visible = re.sub(r"<[^>]*>", "", text).strip()
    match = re.match(r"^[^「『（\s]{1,28}(?P<quote>[「『（]).+", visible)
    return match is not None and visible.endswith({"「": "」", "『": "』", "（": "）"}[match["quote"]])


def validate_message_fields(text: str, name: str | None, *, context: str) -> None:
    # This is a contradiction check, not a general name-shape whitelist.
    # Short narration, punctuation, multiword names and dynamic labels keep
    # their declared roles. Two complete inline dialogues cannot be a pair.
    if name is not None and looks_like_inline_dialogue(text) and looks_like_inline_dialogue(name):
        raise MessageLayoutError(
            f"{context}：人名槽和正文槽都含完整对白，DAT 记录可能被合并或错位；"
            "请重新反汇编，并使用同版本原始 PAC 核对记录，不能只交换标签。"
        )
