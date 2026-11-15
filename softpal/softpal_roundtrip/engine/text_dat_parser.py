from __future__ import annotations

from pathlib import Path

from ..binary.primitives import decode_with_codec, read_u32
from ..core.models import TextDatArchive, TextEntry
from ..core.profiles import AbstractGameProfile
from ..crypto.softpal import softpal_decrypt_bytes


def parse_text_dat_bytes(
    data: bytes,
    source_name: str,
    *,
    text_codec: str = "cp932",
    header_size: int = 0x10,
) -> tuple[bytes, tuple[TextEntry, ...], bytes]:
    if len(data) < header_size:
        raise ValueError(f"{source_name} is too small to be a valid TEXT.DAT")
    count = read_u32(data, 0x0C)
    entries: list[TextEntry] = []
    pos = header_size
    for order in range(count):
        if pos + 4 > len(data):
            raise ValueError(f"{source_name} ended early while reading entry {order}")
        entry_offset = pos
        idx = read_u32(data, pos)
        pos += 4
        end = data.find(b"\x00", pos)
        if end < 0:
            raise ValueError(f"{source_name} entry {order} does not have a trailing NUL")
        raw_text = data[pos:end]
        entries.append(
            TextEntry(
                order=order,
                idx=idx,
                entry_offset=entry_offset,
                raw_text=raw_text,
                original_text=decode_with_codec(raw_text, text_codec),
            )
        )
        pos = end + 1
    header = data[:header_size]
    trailer = data[pos:]
    return header, tuple(entries), trailer


def load_text_dat_auto(
    path: Path,
    profile: AbstractGameProfile,
    *,
    text_codec: str | None = None,
) -> TextDatArchive:
    return load_text_dat_bytes_auto(path.read_bytes(), profile, source_name=str(path), text_codec=text_codec)


def load_text_dat_bytes_auto(
    raw_data: bytes,
    profile: AbstractGameProfile,
    *,
    source_name: str,
    text_codec: str | None = None,
) -> TextDatArchive:
    codec = text_codec or profile.get_text_codec()
    parse_errors: list[str] = []
    header_size = profile.get_text_header_size()

    try:
        header, entries, trailer = parse_text_dat_bytes(
            raw_data,
            source_name,
            text_codec=codec,
            header_size=header_size,
        )
        return TextDatArchive(
            header=header,
            entries=entries,
            trailer=trailer,
            normalized_data=raw_data,
            was_encrypted=False,
            input_mode="plain",
        )
    except Exception as exc:
        parse_errors.append(f"plain: {exc}")

    cipher = profile.get_text_cipher_config()
    if cipher is not None:
        try:
            decrypted = softpal_decrypt_bytes(raw_data, cipher)
            header, entries, trailer = parse_text_dat_bytes(
                decrypted,
                f"{source_name} (decrypted)",
                text_codec=codec,
                header_size=header_size,
            )
            return TextDatArchive(
                header=header,
                entries=entries,
                trailer=trailer,
                normalized_data=decrypted,
                was_encrypted=True,
                input_mode="encrypted",
            )
        except Exception as exc:
            parse_errors.append(f"encrypted: {exc}")

    details = " | ".join(parse_errors) or "no parser variants were attempted"
    raise ValueError(f"failed to parse TEXT.DAT from {source_name}: {details}")
