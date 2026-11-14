from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from ..core.message_layouts import MESSAGE_ARGUMENT_ROLES
from ..core.models import MessageEvent, NameTextContext, ScenarioBoundary, TextClassificationContext, TextEntry
from ..core.profiles import AbstractGameProfile

if False:
    from ..engine.script_parser import ParsedScript


SCENARIO_ID_RE = re.compile(r"^(?:after|s\d{2}_[0-9a-z_]+)(?:\s+.+)?$", re.IGNORECASE)
ASCII_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_]+$")
VERSION_VALUE_RE = re.compile(r"^(?:[A-Za-z]{1,8}\s+)?\d+(?:\.\d+)*(?:\s+[A-Za-z]{1,16})*$")
SINGLE_HIRAGANA_RE = re.compile(r"^[\u3041-\u3096]$")
SYMBOL_ONLY_RE = re.compile(r"^[|｜…・\\-_=+*]+$")
ASSET_EXT_RE = re.compile(r"(?:^|[^A-Za-z0-9])(?:[%A-Za-z0-9_\\-]*\.)[A-Za-z0-9]{2,4}(?:$|[^A-Za-z0-9])")
URL_RE = re.compile(r"^(?:https?://|www\.)", re.IGNORECASE)
DEBUG_HINT_RE = re.compile(
    r"(?:" r"\*\*\*|" r"\b(?:illegal|overflow|not found|bootup|device|layeredit|actionscroll|loadprocess)\b|"
    r"\b(?:moviegifsetex|sechplayex|bgvplay|bgvstop|csvread|systempopupdraw|favoicesave|staffrollenter)\b|"
    r"\bg_[A-Za-z0-9_]+|" r"\btest_[A-Za-z0-9_]+" r")",
    re.IGNORECASE,
)
PLACEHOLDER_NAME_RE = re.compile(r"^[?？]+$")
NAME_DISALLOWED_CHARS = frozenset("<>[]{}()（）「」『』【】《》。、：:；;…♪")


class ClassicSoftPalProfile(AbstractGameProfile):
    name = "classic-softpal"

    # A numeric flag or line value can also equal a TEXT.DAT offset.
    # The shared layouts include both four- and three-argument messages.
    _message_argument_roles = MESSAGE_ARGUMENT_ROLES

    _message_call_ids = {
        0x00020002,
        0x0002000F,
        0x00020010,
        0x00020011,
        0x00020012,
        0x00020013,
        0x00020014,
        0x00070000,
        0x00100002,
        0x00110003,
    }
    _font_call_ids = {
        0x00080003,
        0x00080010,
        0x0008000D,
        0x0008000F,
        0x0003000C,
        0x00030011,
        0x00030020,
        0x0009001B,
        0x000C0000,
        0x00160000,
        0x00160001,
    }
    _visible_ui_call_ids = {
        0x00060002,
        0x00120025,
        0x00120036,
        0x00300006,
        0x0012005A,
    }
    _system_call_ids = {0x000F0001, 0x000F0000, 0x000F0004}
    _title_display_call_ids = {0x00070005, 0x000A0015, 0x000F0005}
    _debug_call_ids = {
        0x00120009,
        0x0012005C,
        0x00030003,
        0x00110005,
        0x00110009,
        0x0011001D,
        0x00110014,
    }

    def get_message_call_ids(self) -> set[int]:
        return set(self._message_call_ids)

    def get_font_call_ids(self) -> set[int]:
        return set(self._font_call_ids)

    def get_system_call_ids(self) -> set[int]:
        return set(self._system_call_ids)

    def get_visible_ui_call_ids(self) -> set[int]:
        return set(self._visible_ui_call_ids)

    def get_title_display_call_ids(self) -> set[int]:
        return set(self._title_display_call_ids)

    def get_debug_call_ids(self) -> set[int]:
        return set(self._debug_call_ids)

    def extract_message_events(
        self,
        script: "ParsedScript",
        text_map: Mapping[int, TextEntry],
    ) -> list[MessageEvent]:
        events: list[MessageEvent] = []
        events.extend(
            self._extract_message_events_push_calls(
                script.words,
                text_map,
                call_opcode=script.instruction_set.call_opcode,
                push_immediate_opcode=script.instruction_set.push_immediate_opcode,
            )
        )
        events.extend(
            self._extract_message_events_param_blocks(
                script.words,
                text_map,
                call_opcode=script.instruction_set.call_opcode,
                param_set_opcode=script.instruction_set.param_set_opcode,
            )
        )

        deduped: list[MessageEvent] = []
        seen: set[tuple[int, int, int | None, int]] = set()
        for event in events:
            key = (event.call_offset, event.text_offset, event.name_offset, event.call_id)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(event)
        deduped.sort(key=lambda event: (event.call_offset, event.text_offset, event.name_offset or -1))
        return deduped

    def detect_choice_text_offsets(
        self,
        script: "ParsedScript",
        text_map: Mapping[int, TextEntry],
    ) -> set[int]:
        words = script.words
        choice_offsets: set[int] = set()
        call_positions: list[int] = []
        call_opcode = script.instruction_set.call_opcode
        push_immediate = script.instruction_set.push_immediate_opcode
        param_set = script.instruction_set.param_set_opcode

        for i in range(len(words) - 1):
            if words[i] == call_opcode and words[i + 1] == 0x00060001:
                call_positions.append(i)
        for start_i in call_positions:
            end_i: int | None = None
            for j in range(start_i + 2, min(len(words) - 1, start_i + 500)):
                if words[j] != call_opcode:
                    continue
                if words[j + 1] == 0x00060003:
                    end_i = j
                    break
                if words[j + 1] == 0x00060001:
                    break
            if end_i is None:
                continue
            for k in range(start_i + 2, end_i):
                if words[k] == push_immediate and k + 1 < len(words):
                    value = words[k + 1]
                    if value in text_map:
                        choice_offsets.add(value)
                elif words[k] == param_set and k + 2 < len(words):
                    if (words[k + 1] & 0xF0000000) in {0x30000000, 0x40000000}:
                        value = words[k + 2]
                        if value in text_map:
                            choice_offsets.add(value)
        return choice_offsets

    def detect_label_text_offsets(
        self,
        script: "ParsedScript",
        text_map: Mapping[int, TextEntry],
    ) -> set[int]:
        words = script.words
        label_offsets: set[int] = set()
        call_opcode = script.instruction_set.call_opcode
        for i in range(len(words) - 3):
            value = words[i]
            if value not in text_map:
                continue
            if words[i + 1] == call_opcode and words[i + 2] == 0x0012005A and words[i + 3] == 0:
                label_offsets.add(value)
        return label_offsets

    def is_name_text(self, text: str, context: NameTextContext) -> bool:
        if not text or len(text) > 24 or not context.message_text:
            return False
        if PLACEHOLDER_NAME_RE.fullmatch(text):
            return True
        trimmed = text.rstrip("!?！？")
        if not trimmed:
            return False
        if any(ch.isspace() or ch in NAME_DISALLOWED_CHARS for ch in trimmed):
            return False
        return any(ch.isalpha() for ch in trimmed)

    def is_choice_text(self, text: str, context: TextClassificationContext) -> bool:
        stripped = text.strip()
        
        if not stripped:
            return False
        choice_opcodes = {0x00060002, 0x00120036, 0x00300006}
        if not (context.call_id_set & choice_opcodes) and "choice_text" not in context.roles:
            return False
        if (
            self._looks_like_symbol_text(stripped)
            or self._looks_like_font_text(stripped, context.call_id_set)
            or self._looks_like_kana_index_text(stripped)
            or self._looks_like_asset_text(stripped)
            or self._looks_like_scenario_text(stripped)
            or self._looks_like_debug_text(stripped)
            or self._looks_like_system_text(stripped, context.call_id_set)
            or self._looks_like_config_text(stripped)
        ):
            return False
        if "<" in stripped or ">" in stripped:
            return False
        if not self._contains_cjk_or_kana(stripped):
            return False
        return len(stripped) <= 32

    def classify_display_tag(self, text: str, context: TextClassificationContext) -> str:
        stripped = text.strip()
        
        if context.call_id_set & self._title_display_call_ids:
            return self._classify_title_display_tag(stripped)
        return "display"

    def classify_script_label_tag(self, text: str, context: TextClassificationContext) -> str:
        stripped = text.strip()
        
        if stripped.startswith("#"):
            return "label"
        if (
            self._looks_like_symbol_text(stripped)
            or self._looks_like_debug_text(stripped)
            or self._looks_like_asset_text(stripped)
            or self._looks_like_scenario_text(stripped)
            or self._looks_like_config_text(stripped)
            or self._is_ascii_heavy(stripped)
        ):
            return "label_internal"
        if self._looks_like_system_text(stripped, context.call_id_set):
            return "label_internal"
        return "label_text"

    def classify_reference_tag(self, text: str, context: TextClassificationContext) -> str:
        stripped = text.strip()
        
        if self._looks_like_symbol_text(stripped):
            return "symbol"
        if self._looks_like_font_text(stripped, context.call_id_set):
            return "font"
        if self._looks_like_kana_index_text(stripped):
            return "kana"
        if self._looks_like_asset_text(stripped):
            return "asset"
        if self._looks_like_scenario_text(stripped):
            return "scenario"
        if self._looks_like_debug_text(stripped):
            return "debug"
        if self._looks_like_system_text(stripped, context.call_id_set):
            return "system"
        if self._looks_like_config_text(stripped):
            return "config"
        
        if context.call_id_set & self._title_display_call_ids:
            return self.classify_display_tag(stripped, context)
        if self._looks_like_display_text(stripped, context.call_id_set):
            return self.classify_display_tag(stripped, context)
        if self._looks_like_table_ui_text(stripped, context.call_id_set):
            return "ui"
        if self._looks_like_visible_ui_text(stripped, context.call_id_set):
            return "ui"
        return "misc"

    def detect_scenario_split_boundaries(
        self,
        rows: Sequence[dict[str, Any]],
        messages: Sequence[dict[str, Any]],
    ) -> list[ScenarioBoundary]:
        del messages
        boundaries: list[ScenarioBoundary] = []
        for row in rows:
            tag = str(row.get("export_tag", ""))
            if tag not in {"scenario", "chapter_title", "route_title", "replay_title", "title"}:
                continue
            boundaries.append(
                ScenarioBoundary(
                    anchor_idx=int(row["idx"]),
                    name=str(row["original_text"]).strip() or f"scenario_{row['idx']}",
                    kind=tag,
                    reason=f"tag:{tag}",
                )
            )
        return boundaries

    def build_manifest_extras(self) -> dict[str, Any]:
        return {
            "profile_capabilities": {
                "message_extractors": ["push-immediate", "param-block"],
                "scenario_split_strategy": "tag-driven default",
            }
        }

    def _resolve_message_entries(
        self,
        params: Mapping[int, int],
        text_map: Mapping[int, TextEntry],
        *,
        call_id: int,
        call_offset: int,
        ignored_ordinals: tuple[int, ...] = (),
    ) -> tuple[TextEntry | None, TextEntry | None]:
        """Return (body, speaker), using a declared layout before text heuristics."""
        roles = self._message_argument_roles.get(call_id)
        if roles is not None and set(params) == set(range(len(roles))):
            values = {role: params[ordinal] for ordinal, role in enumerate(roles)}
            text_entry = text_map.get(values["text"])
            if text_entry is None:
                return None, None
            name_offset = values["name"]
            name_entry = (
                None
                if name_offset == self.get_no_name_sentinel()
                else text_map.get(name_offset)
            )
            return text_entry, name_entry

        # Other layouts keep the existing text-reference path, but must have
        # one unambiguous pair. Never compare a candidate with itself or let
        # the first/last matching text decide which role it occupies.
        candidates: dict[int, TextEntry] = {}
        for ordinal, value in sorted(params.items()):
            if ordinal not in ignored_ordinals and value in text_map:
                candidates[value] = text_map[value]
        entries = list(candidates.values())
        if not entries:
            return None, None
        if len(entries) == 1:
            return entries[0], None
        if len(entries) == 2:
            left, right = entries
            left_is_name = self.is_name_text(
                left.original_text,
                NameTextContext(left, right, left.original_text, right.original_text),
            )
            right_is_name = self.is_name_text(
                right.original_text,
                NameTextContext(right, left, right.original_text, left.original_text),
            )
            if left_is_name != right_is_name:
                return (right, left) if left_is_name else (left, right)

        candidate_summary = ", ".join(f"idx={entry.idx} {entry.original_text!r}" for entry in entries)
        raise ValueError(
            f"无法确定消息调用的人名与正文：call=0x{call_offset:08X} "
            f"id=0x{call_id:08X}，候选为 {candidate_summary}；请为此调用补充参数槽位定义。"
        )

    def _extract_message_events_push_calls(
        self,
        words: Sequence[int],
        text_map: Mapping[int, TextEntry],
        *,
        call_opcode: int,
        push_immediate_opcode: int,
    ) -> list[MessageEvent]:
        events: list[MessageEvent] = []
        for i in range(len(words) - 2):
            if words[i] != call_opcode:
                continue
            call_id = words[i + 1]
            if call_id not in self._message_call_ids:
                continue
            if words[i + 2] != 0:
                continue
            
            immediates: list[int] = []
            j = i - 2
            while j >= 0 and words[j] == push_immediate_opcode:
                immediates.append(words[j + 1])
                j -= 2
            immediates.reverse()
            
            if not immediates:
                continue

            text_entry, name_entry = self._resolve_message_entries(
                dict(enumerate(immediates)),
                text_map,
                call_id=call_id,
                call_offset=i * 4,
            )
            if text_entry is None:
                continue

            kind = "spoken" if name_entry is not None else "narration"
            
            events.append(
                MessageEvent(
                    call_offset=i * 4,
                    call_id=call_id,
                    line_id=immediates[-1] if len(immediates) > 0 else 0,
                    flags=tuple(immediates),
                    text_offset=text_entry.entry_offset,
                    text_idx=text_entry.idx,
                    text=text_entry.original_text,
                    name_offset=None if name_entry is None else name_entry.entry_offset,
                    name_idx=None if name_entry is None else name_entry.idx,
                    name=None if name_entry is None else name_entry.original_text,
                    kind=kind,
                )
            )
        return events

    def _extract_message_events_param_blocks(
        self,
        words: Sequence[int],
        text_map: Mapping[int, TextEntry],
        *,
        call_opcode: int,
        param_set_opcode: int,
    ) -> list[MessageEvent]:
        events: list[MessageEvent] = []
        i = 0
        while i < len(words) - 2:
            start_i = i
            params, end_i = self._parse_param_block(words, start_i, param_set_opcode=param_set_opcode)
            if params is None:
                i += 1
                continue
            i = max(end_i, start_i + 1)
            
            if not any(value in text_map for value in params.values()):
                continue

            call_before = self._find_adjacent_message_call_before(words, start_i, call_opcode=call_opcode)
            call_after = self._find_adjacent_message_call_after(words, end_i, call_opcode=call_opcode)
            call_i = call_before if call_before is not None else call_after
            if call_i is None:
                continue

            call_id = words[call_i + 1]
            roles = self._message_argument_roles.get(call_id)
            known_layout = roles is not None and set(params) == set(range(len(roles)))
            line_ordinal = roles.index("line") if known_layout else 3
            text_entry, name_entry = self._resolve_message_entries(
                params,
                text_map,
                call_id=call_id,
                call_offset=call_i * 4,
                ignored_ordinals=(line_ordinal,),
            )
            if text_entry is None:
                continue

            kind = "spoken" if name_entry is not None else "narration"
            
            used_offsets = {text_entry.entry_offset}
            if name_entry:
                used_offsets.add(name_entry.entry_offset)
            if known_layout:
                extra_param_values = tuple(params[p] for p, role in enumerate(roles) if role not in {"text", "name", "line"})
            else:
                extra_param_values = tuple(params[p] for p in sorted(params) if params[p] not in used_offsets and p != line_ordinal)
            
            events.append(
                MessageEvent(
                    call_offset=call_i * 4,
                    call_id=call_id,
                    line_id=params.get(line_ordinal, 0),
                    flags=extra_param_values,
                    text_offset=text_entry.entry_offset,
                    text_idx=text_entry.idx,
                    text=text_entry.original_text,
                    name_offset=None if name_entry is None else name_entry.entry_offset,
                    name_idx=None if name_entry is None else name_entry.idx,
                    name=None if name_entry is None else name_entry.original_text,
                    kind=kind,
                )
            )
        return events

    def _parse_param_block(
        self,
        words: Sequence[int],
        start_i: int,
        *,
        param_set_opcode: int,
    ) -> tuple[dict[int, int] | None, int]:
        if start_i + 2 >= len(words):
            return None, start_i
        if words[start_i] != param_set_opcode:
            return None, start_i
        if (words[start_i + 1] & 0xFFFF0000) != 0x30000000:
            return None, start_i
        params: dict[int, int] = {}
        i = start_i
        while i + 2 < len(words):
            if words[i] != param_set_opcode:
                break
            if (words[i + 1] & 0xFFFF0000) != 0x30000000:
                break
            params[words[i + 1] & 0xFFFF] = words[i + 2]
            i += 3
        return params, i

    def _find_adjacent_message_call_before(
        self,
        words: Sequence[int],
        start_i: int,
        *,
        call_opcode: int,
    ) -> int | None:
        call_i = start_i - 2
        if call_i >= 0 and words[call_i] == call_opcode and words[call_i + 1] in self._message_call_ids:
            return call_i
        return None

    def _find_adjacent_message_call_after(
        self,
        words: Sequence[int],
        end_i: int,
        *,
        call_opcode: int,
        max_words: int = 32,
    ) -> int | None:
        limit = min(len(words) - 1, end_i + max_words)
        for i in range(end_i, limit):
            if words[i] == call_opcode and words[i + 1] in self._message_call_ids:
                return i
        return None

    def _contains_cjk_or_kana(self, text: str) -> bool:
        for ch in text:
            if "\u3040" <= ch <= "\u30ff" or "\u4e00" <= ch <= "\u9fff":
                return True
        return False

    def _is_ascii_heavy(self, text: str) -> bool:
        visible = [ch for ch in text if not ch.isspace()]
        if not visible:
            return False
        ascii_chars = sum(1 for ch in visible if ord(ch) < 0x80)
        return ascii_chars / len(visible) >= 0.7

    def _looks_like_symbol_text(self, text: str) -> bool:
        return bool(text) and SYMBOL_ONLY_RE.fullmatch(text) is not None

    def _looks_like_kana_index_text(self, text: str) -> bool:
        return SINGLE_HIRAGANA_RE.fullmatch(text) is not None

    def _looks_like_asset_text(self, text: str) -> bool:
        if URL_RE.match(text):
            return True
        if "\\" in text or "/" in text:
            return True
        if re.fullmatch(r"\.[A-Za-z0-9]{2,4}", text):
            return True
        return ASSET_EXT_RE.search(text) is not None

    def _looks_like_scenario_text(self, text: str) -> bool:
        return SCENARIO_ID_RE.fullmatch(text) is not None

    def _looks_like_config_text(self, text: str) -> bool:
        if VERSION_VALUE_RE.fullmatch(text):
            return True
        if ASCII_IDENTIFIER_RE.fullmatch(text):
            return len(text) >= 2
        if any(ch.isdigit() for ch in text) and re.fullmatch(r"[A-Za-z0-9. ]+", text):
            return True
        return False

    def _looks_like_debug_text(self, text: str) -> bool:
        lowered = text.lower()
        if "%" in text:
            return True
        if text.count(":D") >= 2:
            return True
        if DEBUG_HINT_RE.search(text) is not None:
            return True
        if "==" in text or "???" in text:
            return True
        if not self._is_ascii_heavy(text):
            return False
        tokens = (
            " btn",
            " mode",
            " start",
            " end",
            " rest",
            " next",
            "wait_",
            "menu_",
            "music",
            "historyjump",
            "cgallopen",
            "replayallopen",
        )
        if any(token in lowered for token in tokens):
            return True
        if lowered.startswith(("menu ", "wait_", "music", "historyjump", "cgallopen", "replayallopen")):
            return True
        if ":" in text and any(flag in lowered for flag in ("off", "on", "next", "rest", "start", "end")):
            return True
        return False

    def _looks_like_system_text(self, text: str, call_id_set: set[int]) -> bool:
        if call_id_set & self._system_call_ids:
            return True
        if not (call_id_set & self._debug_call_ids):
            return False
        if not self._contains_cjk_or_kana(text):
            return False
        return len(text) >= 4 or any(ch in text for ch in "。！？")

    def _looks_like_font_text(self, text: str, call_id_set: set[int]) -> bool:
        if not (call_id_set & self._font_call_ids):
            return False
        if text.startswith("MS "):
            return True
        if self._looks_like_kana_index_text(text):
            return False
        if self._looks_like_debug_text(text) or self._looks_like_asset_text(text) or self._looks_like_config_text(text):
            return False
        return self._contains_cjk_or_kana(text) and len(text) <= 12

    def _looks_like_display_text(self, text: str, call_id_set: set[int]) -> bool:
        if call_id_set & self._title_display_call_ids:
            if self._looks_like_debug_text(text) or self._looks_like_asset_text(text) or self._looks_like_config_text(text):
                return False
            return not self._looks_like_symbol_text(text)
        if not (call_id_set & self._message_call_ids):
            return False
        if self._looks_like_debug_text(text) or self._looks_like_asset_text(text) or self._looks_like_config_text(text):
            return False
        if self._looks_like_symbol_text(text):
            return False
        if self._contains_cjk_or_kana(text):
            return len(text) > 20 or any(ch in text for ch in "。！？")
        return len(text) >= 12

    def _looks_like_table_ui_text(self, text: str, call_id_set: set[int]) -> bool:
        if 0x00120024 not in call_id_set:
            return False
        if self._looks_like_asset_text(text) or self._looks_like_config_text(text) or self._looks_like_debug_text(text):
            return False
        if self._looks_like_symbol_text(text):
            return False
        return self._contains_cjk_or_kana(text) or " " in text or "(" in text

    def _looks_like_visible_ui_text(self, text: str, call_id_set: set[int]) -> bool:
        if not text:
            return False
        if self._looks_like_symbol_text(text):
            return True
        if call_id_set & self._visible_ui_call_ids:
            return True
        if self._contains_cjk_or_kana(text):
            return True
        if call_id_set & self._message_call_ids and len(text) <= 20:
            return True
        return False

    def _classify_title_display_tag(self, text: str) -> str:
        if self._is_ascii_replay_suffix(text):
            return "replay_title"
        if self._has_bracketed_cjk_segment(text):
            return "chapter_title"
        if self._is_short_plain_cjk_title(text):
            return "chapter_title"
        if self._count_numeric_markers(text) >= 1:
            return "route_title"
        return "title"

    def _has_bracketed_cjk_segment(self, text: str) -> bool:
        bracket_pairs = {"(": ")", "（": "）", "[": "]", "【": "】", "「": "」", "<": ">"}
        for left, right in bracket_pairs.items():
            start = text.find(left)
            if start < 0:
                continue
            end = text.find(right, start + 1)
            if end < 0:
                continue
            middle = text[start + 1 : end].strip()
            if middle and self._contains_cjk_or_kana(middle):
                return True
        return False

    def _is_ascii_replay_suffix(self, text: str) -> bool:
        colon_pos = text.rfind(":")
        if colon_pos <= 0 or colon_pos >= len(text) - 2:
            return False
        head = text[:colon_pos].strip()
        tail = text[colon_pos + 1 :].strip()
        if not head or not tail:
            return False
        if not self._contains_cjk_or_kana(head):
            return False
        if not re.fullmatch(r"[A-Za-z0-9_-]{3,16}", tail):
            return False
        return any(ch.isdigit() for ch in tail) and any(ch.isalpha() for ch in tail)

    def _count_numeric_markers(self, text: str) -> int:
        count = 0
        for ch in text:
            if ch.isdigit():
                count += 1
                continue
            code = ord(ch)
            if 0x2460 <= code <= 0x2473:
                count += 1
        return count

    def _is_short_plain_cjk_title(self, text: str) -> bool:
        stripped = text.strip()
        
        if not stripped or len(stripped) > 12:
            return False
        if any(ch.isascii() and ch.isalnum() for ch in stripped):
            return False
        if any(ch.isdigit() for ch in stripped):
            return False
        if any(ch.isspace() for ch in stripped):
            return False
        return all(self._contains_cjk_or_kana(ch) for ch in stripped)
