"""Evidence-bound Interheart profile for the supplied data.fpk corpus.

This is data, not a claim that non-text SPT opcodes have been decoded.
See vm_analysis.md for each evidence reference.
"""

DIALECT = {
    "schema_version": "1",
    "engine_id": "interheart-act-a-ja",
    "endianness": "little",
    "source_encoding": "utf-8",
    "target_encoding": "utf-8",
    "text_file_encoding": "utf-8-sig",
    "spt": {
        "count_offset": 0,
        "header_size": 4,
        "record_size": 32,
        "field_format": "<8i",
        "text_opcode": 1,
        "text_kind": 7,
        "text_id_slot": 7,
        "source_line_slot": 4,
        "line_count_slot": 5,
        "evidence_refs": ["EV_SPT_32", "EV_TEXT_JOIN"],
        "confidence": "derived",
    },
    "ptr": {
        "signature": "PTR ",
        "header_size": 16,
        "record_size": 12,
        "record_format": "<III",
        "text_separator": ",",
        "evidence_refs": ["EV_PTR_TXD"],
        "confidence": "observed",
    },
    "text_rules": {
        "choice_anchor": "***SS_",
        "anchor_regex": r"\[([0-9]+)\]",
        "selection_regex": r"^\*\*\*SS_([AW][0-9]{4}_[0-9]+)_([0-9]+)(?:_|$)",
        "name_id_base": 10_000_000,
        "source_identity_domain": "INTERHEART-TEXT-SOURCE/1",
        "control_tokens": [r"\n", "&heart;"],
        "name_storage": "inline-prefix-before-first-comma",
        "evidence_refs": ["EV_CHOICE", "EV_NAME"],
        "confidence": "derived",
    },
    "fpk": {
        "record_size": 36,
        "name_size": 24,
        "encrypted_count_flag": 0x80000000,
        "count_mask": 0x7FFFFFFF,
        "zlc2_magic": "ZLC2",
        "backref_high_mask": 0xF0,
        "evidence_refs": ["EV_FPK_GARBRO", "EV_ZLC2_GARBRO"],
        "confidence": "observed",
    },
    "supported_archive": "FPK encrypted 36-byte index; ZLC2",
    "unsupported": ["other FPK dialects", "non-text SPT instruction edits"],
}
