from __future__ import annotations


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
