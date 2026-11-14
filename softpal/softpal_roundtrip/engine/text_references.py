from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from ..core.message_layouts import MESSAGE_ARGUMENT_ROLES
from ..core.models import TextEntry
from .script_parser import ParsedScript


# Sv20 instruction widths, checked against the verified VM dispatch handlers.
# Operands are never scanned as opcodes. See vm_analysis.md.
_BINARY_OPS = (*range(0x01, 0x09), *range(0x0C, 0x14), *range(0x1A, 0x1D))
_WIDTHS = {0x10000 + op: 3 for op in _BINARY_OPS}
_WIDTHS.update({
    0x10009: 2, 0x1000A: 3, 0x1000B: 2, 0x10014: 2,
    0x10015: 1, 0x10016: 1, 0x10017: 3, 0x10018: 1, 0x10019: 1,
    0x1001D: 2, 0x1001E: 2, 0x1001F: 2, 0x10020: 2, 0x10021: 2,
})
_PURE_REGISTER_OPS = {0x10000 + op for op in _BINARY_OPS} | {0x10014, 0x1001D}

# Depth is counted from the top of the argument stack (the final PUSH is 1).
# These slots consume TEXT.DAT offsets, rather than file IDs, string-variable
# indexes, coordinates, flags or line numbers. Partial PUSH runs are common:
# the compiler interleaves register assignments with argument preparation.
_NATIVE_TEXT_DEPTHS = {
    call_id: tuple(len(roles) - ordinal for ordinal, role in enumerate(roles) if role in {"text", "name"})
    for call_id, roles in MESSAGE_ARGUMENT_ROLES.items()
}
_NATIVE_TEXT_DEPTHS.update({
    0x00060002: (1,),
    0x000A0015: (1,),
    0x000F0001: (1,),
    0x000F0002: (1,),
    0x000F0004: (1,),
    0x00120008: (1,),
    0x00120009: (2,),
    0x00120024: (3, 2, 1),
    0x00120025: (2, 1),
    0x0012003B: (2,),
    0x0012005A: (1,),
    0x0012005C: (1,),
})


@dataclass(frozen=True, slots=True)
class Instruction:
    offset: int
    opcode: int
    operands: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class OperandOrigin:
    kind: str
    value: int
    site_offset: int


@dataclass(frozen=True, slots=True)
class TextReferenceSite:
    site_offset: int
    entry_offset: int
    text_idx: int
    call_offset: int
    call_id: int
    argument_depth: int
    evidence: str

    def to_row(self) -> dict[str, object]:
        return {
            "site_offset": self.site_offset,
            "entry_offset": self.entry_offset,
            "text_idx": self.text_idx,
            "call_offset": self.call_offset,
            "call_id": self.call_id,
            "argument_depth": self.argument_depth,
            "evidence": self.evidence,
        }


def decode_instructions(script: ParsedScript) -> tuple[Instruction, ...]:
    words = script.words
    start = 3 if script.raw_data.startswith(b"Sv20") else 0
    instructions = []
    i = start
    while i < len(words):
        opcode = words[i]
        width = _WIDTHS.get(opcode)
        if width is None:
            raise ValueError(f"未识别的脚本指令 0x{opcode:08X}，位置 0x{i * 4:08X}；无法安全重定位文本")
        if i + width > len(words):
            raise ValueError(f"脚本指令在 0x{i * 4:08X} 处被截断")
        instructions.append(Instruction(i * 4, opcode, words[i + 1:i + width]))
        i += width
    return tuple(instructions)


def _argument_pushes(instructions: Sequence[Instruction], call_index: int, limit: int = 10) -> list[int]:
    indexes = []
    for i in range(call_index - 1, -1, -1):
        opcode = instructions[i].opcode
        if opcode == 0x1001F:
            indexes.append(i)
            if len(indexes) == limit:
                break
        elif opcode not in _PURE_REGISTER_OPS:
            break
    return indexes


def _operand_origin(
    instructions: Sequence[Instruction],
    before_index: int,
    operand: int,
    site_offset: int,
    *,
    depth: int = 0,
) -> OperandOrigin | None:
    if depth > 64:
        return None
    operand_type = operand & 0xF0000000
    if operand_type == 0:
        return OperandOrigin("literal", operand, site_offset)
    if operand_type == 0x80000000:
        return OperandOrigin("parameter", operand & 0xFFFF, site_offset)
    if operand_type != 0x40000000:
        return None
    for i in range(before_index - 1, -1, -1):
        instruction = instructions[i]
        if instruction.opcode == 0x1001F:
            continue
        if instruction.opcode not in _PURE_REGISTER_OPS:
            break
        if instruction.operands[0] != operand:
            continue
        if instruction.opcode != 0x10001:
            return None
        return _operand_origin(
            instructions, i, instruction.operands[1], instruction.offset + 8,
            depth=depth + 1,
        )
    return None


def _push_origin(instructions: Sequence[Instruction], push_index: int) -> OperandOrigin | None:
    push = instructions[push_index]
    return _operand_origin(instructions, push_index, push.operands[0], push.offset + 4)


def _printf_text_depths(raw_text: bytes) -> tuple[int, ...]:
    # Native 0x120009 always pops eight formatting arguments. Its %t/%T
    # branches read TEXT.DAT; %f/%F use File.dat and must stay numeric here.
    depths = []
    argument = 0
    position = 0
    while position < len(raw_text):
        if raw_text[position] != ord("%"):
            position += 1
            continue
        position += 1
        if position < len(raw_text) and raw_text[position] == ord("%"):
            position += 1
            continue
        while position < len(raw_text) and raw_text[position] in b"-+ #0.123456789":
            position += 1
        if position >= len(raw_text):
            break
        code = raw_text[position]
        position += 1
        if code in b"tT":
            depths.append(argument + 3)
        argument += 1
        if argument >= 8:
            break
    return tuple(depths)


def _script_wrapper_depths(
    script: ParsedScript,
    instructions: Sequence[Instruction],
    text_map: dict[int, TextEntry],
) -> dict[int, tuple[int, ...]]:
    # Point.dat proves point 0xBF4 -> SRC code offset 0x5B734 (+12 header).
    # Keep this binding scoped to the verified Sv20 build and validate that
    # its three-argument body still sends parameter 1 to a %t formatting slot.
    # Another game's point IDs must not acquire this declaration by accident.
    if script.raw_data[:8] != b"Sv20\x26\x16\xF4\x6A":
        return {}
    start = next((i for i, ins in enumerate(instructions) if ins.offset == 0x5B740), None)
    if start is None or instructions[start].opcode != 0x10020 or instructions[start].operands != (3,):
        return {}
    end = next((i for i in range(start + 1, len(instructions)) if instructions[i].opcode == 0x10020), len(instructions))
    for i in range(start + 1, end):
        instruction = instructions[i]
        if instruction.opcode != 0x10017 or instruction.operands[0] != 0x120009:
            continue
        pushes = _argument_pushes(instructions, i)
        if len(pushes) < 2:
            continue
        template = _push_origin(instructions, pushes[1])
        entry = None if template is None or template.kind != "literal" else text_map.get(template.value)
        if entry is None:
            continue
        for depth in _printf_text_depths(entry.raw_text):
            if len(pushes) < depth:
                continue
            origin = _push_origin(instructions, pushes[depth - 1])
            if origin is not None and origin.kind == "parameter" and origin.value == 1:
                return {0xBF4: (3,)}
    return {}


def find_text_reference_sites(script: ParsedScript, entries: Iterable[TextEntry]) -> tuple[TextReferenceSite, ...]:
    text_map = {entry.entry_offset: entry for entry in entries}
    instructions = decode_instructions(script)
    wrappers = _script_wrapper_depths(script, instructions, text_map)
    by_site: dict[int, TextReferenceSite] = {}
    for i, instruction in enumerate(instructions):
        if instruction.opcode not in {0x10017, 0x1000B}:
            continue
        call_id = instruction.operands[0]
        is_native = instruction.opcode == 0x10017
        depths = (_NATIVE_TEXT_DEPTHS if is_native else wrappers).get(call_id)
        if depths is None:
            continue
        pushes = _argument_pushes(instructions, i)
        if is_native and call_id == 0x120009 and len(pushes) >= 2:
            template = _push_origin(instructions, pushes[1])
            entry = None if template is None or template.kind != "literal" else text_map.get(template.value)
            if entry is not None:
                depths += _printf_text_depths(entry.raw_text)
        text_origins = []
        for depth in depths:
            if len(pushes) < depth:
                continue
            origin = _push_origin(instructions, pushes[depth - 1])
            if origin is None or origin.kind != "literal" or origin.value not in text_map:
                continue
            text_origins.append(origin.site_offset)
            entry = text_map[origin.value]
            reference = TextReferenceSite(
                origin.site_offset, origin.value, entry.idx, instruction.offset,
                call_id, depth, "native_text_argument" if is_native else "verified_script_text_wrapper",
            )
            existing = by_site.get(origin.site_offset)
            if existing is not None and existing.entry_offset != reference.entry_offset:
                raise ValueError(f"文本引用在 0x{origin.site_offset:08X} 处产生冲突")
            by_site[origin.site_offset] = reference
        # An assignment shared by a text and numeric slot cannot be relocated
        # without changing the numeric argument as well.
        for depth, push_index in enumerate(pushes, 1):
            if depth in depths:
                continue
            origin = _push_origin(instructions, push_index)
            if origin is not None and origin.site_offset in text_origins:
                raise ValueError(f"0x{origin.site_offset:08X} 的赋值同时用于文本和数值参数，无法安全重定位")
    return tuple(by_site[offset] for offset in sorted(by_site))


def reference_map_by_entry(sites: Iterable[TextReferenceSite]) -> dict[int, list[int]]:
    result: dict[int, list[int]] = {}
    for site in sites:
        result.setdefault(site.entry_offset, []).append(site.site_offset)
    return result
