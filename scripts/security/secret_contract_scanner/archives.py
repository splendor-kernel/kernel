"""Bounded structural archive detection and safe member extraction."""

from __future__ import annotations

import io
import lzma
import bz2
import stat
import struct
import tarfile
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Iterator

from .content import is_secret_field_name, scan_content
from .model import ScanDataError, WorkBudget, bounded_plain_string


@dataclass(frozen=True)
class ArchiveMember:
    name: str
    data: bytes


@dataclass(frozen=True)
class ZipLayout:
    entries: int
    central_offset: int
    central_size: int
    central_actual: int
    eocd_offset: int
    comment_length: int
    prefix_length: int
    trailing_length: int


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _zip_layout(data: bytes) -> ZipLayout | None:
    minimum = max(0, len(data) - (65_535 + 22 + 4096))
    position = len(data)
    while True:
        position = data.rfind(b"PK\x05\x06", minimum, position)
        if position < 0:
            return None
        if position + 22 <= len(data):
            disk = _u16(data, position + 4)
            central_disk = _u16(data, position + 6)
            disk_entries = _u16(data, position + 8)
            entries = _u16(data, position + 10)
            central_size = _u32(data, position + 12)
            central_offset = _u32(data, position + 16)
            comment_length = _u16(data, position + 20)
            expected_end = position + 22 + comment_length
            central_actual = position - central_size
            prefix = central_actual - central_offset
            if (
                disk == 0
                and central_disk == 0
                and disk_entries == entries
                and expected_end <= len(data)
                and central_actual >= 0
                and prefix >= 0
                and (
                    entries == 0
                    or data[central_actual : central_actual + 4] == b"PK\x01\x02"
                )
            ):
                return ZipLayout(
                    entries=entries,
                    central_offset=central_offset,
                    central_size=central_size,
                    central_actual=central_actual,
                    eocd_offset=position,
                    comment_length=comment_length,
                    prefix_length=prefix,
                    trailing_length=len(data) - expected_end,
                )
        position = max(minimum, position)


def _tar_header_checksum(data: bytes) -> bool:
    if len(data) < 512:
        return False
    header = data[:512]
    raw_checksum = header[148:156].strip(b"\x00 ")
    if not raw_checksum:
        return False
    try:
        expected = int(raw_checksum, 8)
    except ValueError:
        return False
    unsigned = sum(header[:148]) + (8 * 0x20) + sum(header[156:])
    # POSIX readers historically accept both unsigned-byte and signed-byte
    # checksum producers.  Recognize both before deciding that an opaque file
    # is not a TAR; strict metadata/member validation still runs afterwards.
    signed = sum(byte if byte < 128 else byte - 256 for byte in header[:148])
    signed += 8 * 0x20
    signed += sum(byte if byte < 128 else byte - 256 for byte in header[156:])
    return expected in {unsigned, signed}


def _plausible_tar_checksum_field(data: bytes, offset: int) -> bool:
    if offset < 0 or offset + 512 > len(data):
        return False
    raw = data[offset + 148 : offset + 156]
    stripped = raw.strip(b"\x00 ")
    return bool(stripped) and all(byte in b"01234567" for byte in stripped)


def detect_archive_kind(data: bytes, *, budget: WorkBudget | None = None) -> str | None:
    """Recognize supported containers structurally, independent of suffix/prefix."""

    # Reserve one bounded linear recognition pass before any suffix-independent
    # probing.  This makes exact-limit and limit+1 behavior deterministic and
    # accounts for every candidate byte even when optimized C searches return
    # early.  Header/decompression work is separately charged by extractors.
    if budget is not None:
        budget.charge_parser_operations(len(data))

    if _zip_layout(data) is not None:
        return "zip"
    if any(
        signature in data for signature in (b"PK\x03\x04", b"PK\x01\x02", b"PK\x05\x06")
    ):
        # Malformed, truncated, and prefixed ZIP candidates must reach the ZIP
        # validator rather than becoming opaque binary content.
        return "zip"
    if data.startswith(b"\x1f\x8b") or b"\x1f\x8b\x08" in data:
        return "gzip"
    if _tar_header_checksum(data):
        return "tar"
    # Reject prefixed/self-extracting TAR polyglots. V7 has no USTAR marker, so
    # inspect every possible header start with a constant-memory rolling sum.
    # Repository file-size limits bound this O(n) pass.
    last_header = len(data) - 512
    window_sum = sum(data[:512])
    signed_window_sum = sum(byte if byte < 128 else byte - 256 for byte in data[:512])
    for offset in range(1, last_header + 1):
        window_sum += data[offset + 511] - data[offset - 1]
        incoming = data[offset + 511]
        outgoing = data[offset - 1]
        signed_window_sum += (incoming if incoming < 128 else incoming - 256) - (
            outgoing if outgoing < 128 else outgoing - 256
        )
        if not _plausible_tar_checksum_field(data, offset):
            continue
        checksum = data[offset + 148 : offset + 156]
        expected = int(checksum.strip(b"\x00 "), 8)
        unsigned = window_sum - sum(checksum) + (8 * 0x20)
        signed_checksum = sum(byte if byte < 128 else byte - 256 for byte in checksum)
        signed = signed_window_sum - signed_checksum + (8 * 0x20)
        if expected in {unsigned, signed}:
            return "tar"
    plausible_markers = 0
    marker_start = 0
    while True:
        marker = data.find(b"ustar", marker_start)
        if marker < 0:
            break
        header = marker - 257
        if header > 0 and _plausible_tar_checksum_field(data, header):
            plausible_markers += 1
            if plausible_markers > 64 or _tar_header_checksum(
                data[header : header + 512]
            ):
                return "tar"
        marker_start = marker + 1
    return None


def _credential_capable_archive_text(value: str) -> bool:
    if scan_content(value, 1, assignment_context=True):
        return True
    for component in value.replace("\\", "/").split("/"):
        stem = component.rsplit(".", 1)[0]
        if is_secret_field_name(stem):
            return True
    return False


def _safe_member_name(
    name: object,
    *,
    directory: bool,
    seen_names: set[str],
    maximum: int,
) -> str:
    if not isinstance(name, str) or not name or "\x00" in name:
        raise ScanDataError("SCA001_ARCHIVE_INVALID")
    normalized = name.replace("\\", "/")
    stripped = normalized[:-1] if directory and normalized.endswith("/") else normalized
    parts = stripped.split("/")
    pure = PurePosixPath(stripped)
    canonical = pure.as_posix()
    if (
        not bounded_plain_string(stripped, min(maximum, 4096))
        or pure.is_absolute()
        or any(part in {"", ".", ".."} for part in parts)
        or canonical in seen_names
        or _credential_capable_archive_text(canonical)
    ):
        raise ScanDataError("SCA001_ARCHIVE_INVALID")
    seen_names.add(canonical)
    return canonical


def _zip_central_preflight(
    data: bytes, layout: ZipLayout, limits: dict[str, int], budget: WorkBudget
) -> None:
    if (
        layout.prefix_length != 0
        or layout.trailing_length != 0
        or layout.comment_length != 0
        or layout.central_actual + layout.central_size != layout.eocd_offset
    ):
        raise ScanDataError("SCA001_ARCHIVE_INVALID")
    budget.ensure_archive_capacity(layout.entries)
    position = layout.central_actual
    total_unpacked = 0
    local_records: list[tuple[int, int, int, int, int, int, bytes]] = []
    for _ in range(layout.entries):
        if (
            position + 46 > layout.eocd_offset
            or data[position : position + 4] != b"PK\x01\x02"
        ):
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        flags = _u16(data, position + 8)
        compression = _u16(data, position + 10)
        crc32 = _u32(data, position + 16)
        compressed = _u32(data, position + 20)
        unpacked = _u32(data, position + 24)
        name_length = _u16(data, position + 28)
        extra_length = _u16(data, position + 30)
        comment_length = _u16(data, position + 32)
        disk_start = _u16(data, position + 34)
        local_offset = _u32(data, position + 42)
        if (
            flags & ~0x0800
            or compression not in {0, 8, 12}
            or disk_start != 0
            or name_length == 0
            or unpacked > limits["max_file_bytes"]
            or unpacked > max(1, compressed) * 100
            or extra_length != 0
            or comment_length != 0
        ):
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        next_position = position + 46 + name_length + extra_length + comment_length
        if next_position > layout.eocd_offset:
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        central_name = data[position + 46 : position + 46 + name_length]
        local_records.append(
            (
                local_offset,
                flags,
                compression,
                crc32,
                compressed,
                unpacked,
                central_name,
            )
        )
        total_unpacked += unpacked
        if total_unpacked > budget.remaining_archive_bytes():
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        position = next_position
    if position != layout.eocd_offset:
        raise ScanDataError("SCA001_ARCHIVE_INVALID")
    # Strict stream validation and ZipFile extraction each process the expanded
    # bytes. Reserve both passes before either decompressor runs.
    budget.ensure_work_capacity(total_unpacked * 2)

    expected_local_offset = 0
    for (
        local_offset,
        flags,
        compression,
        crc32,
        compressed,
        unpacked,
        central_name,
    ) in sorted(local_records):
        if (
            local_offset != expected_local_offset
            or local_offset + 30 > layout.central_actual
            or data[local_offset : local_offset + 4] != b"PK\x03\x04"
        ):
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        local_name_length = _u16(data, local_offset + 26)
        local_extra_length = _u16(data, local_offset + 28)
        local_name_start = local_offset + 30
        local_data_start = local_name_start + local_name_length + local_extra_length
        local_end = local_data_start + compressed
        if (
            _u16(data, local_offset + 6) != flags
            or _u16(data, local_offset + 8) != compression
            or _u32(data, local_offset + 14) != crc32
            or _u32(data, local_offset + 18) != compressed
            or _u32(data, local_offset + 22) != unpacked
            or local_name_length != len(central_name)
            or local_extra_length != 0
            or local_end > layout.central_actual
            or data[local_name_start : local_name_start + local_name_length]
            != central_name
        ):
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        compressed_payload = data[local_data_start:local_end]
        if compression == 0:
            payload = compressed_payload
        elif compression == 8:
            decoder = zlib.decompressobj(wbits=-15)
            payload = decoder.decompress(compressed_payload, unpacked + 1)
            if (
                len(payload) > unpacked
                or decoder.unconsumed_tail
                or decoder.unused_data
                or not decoder.eof
            ):
                raise ScanDataError("SCA001_ARCHIVE_INVALID")
            payload += decoder.flush(unpacked + 1 - len(payload))
        else:
            decoder_bzip = bz2.BZ2Decompressor()
            payload = decoder_bzip.decompress(
                compressed_payload, max_length=unpacked + 1
            )
            if not decoder_bzip.eof or decoder_bzip.unused_data:
                raise ScanDataError("SCA001_ARCHIVE_INVALID")
        if (
            len(payload) != unpacked
            or zlib.crc32(payload) & 0xFFFFFFFF != crc32
            or (compression == 0 and compressed != unpacked)
        ):
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        budget.charge_work(unpacked)
        expected_local_offset = local_end
    if expected_local_offset != layout.central_actual:
        raise ScanDataError("SCA001_ARCHIVE_INVALID")


def _zip_members(
    data: bytes, limits: dict[str, int], budget: WorkBudget
) -> Iterator[ArchiveMember]:
    layout = _zip_layout(data)
    if layout is None:
        raise ScanDataError("SCA001_ARCHIVE_INVALID")
    _zip_central_preflight(data, layout, limits, budget)
    seen_names: set[str] = set()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if len(infos) != layout.entries:
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        for info in sorted(infos, key=lambda item: item.filename):
            mode = (info.external_attr >> 16) & 0xFFFF
            file_type = stat.S_IFMT(mode)
            is_directory = info.is_dir()
            if (
                info.comment
                or info.extra
                or info.flag_bits & 0x1
                or stat.S_ISLNK(mode)
                or file_type not in {0, stat.S_IFREG, stat.S_IFDIR}
                or info.file_size < 0
                or (is_directory and info.file_size != 0)
                or info.file_size > limits["max_file_bytes"]
            ):
                raise ScanDataError("SCA001_ARCHIVE_INVALID")
            name = _safe_member_name(
                info.filename,
                directory=is_directory,
                seen_names=seen_names,
                maximum=limits["max_string_bytes"],
            )
            if is_directory:
                budget.charge_archive_member(0)
                continue
            budget.charge_archive_member(info.file_size)
            with archive.open(info, "r") as member:
                member_data = member.read(info.file_size + 1)
            if len(member_data) != info.file_size:
                raise ScanDataError("SCA001_ARCHIVE_INVALID")
            yield ArchiveMember(name, member_data)


def _tar_text_field(
    header: bytes, start: int, end: int, *, required: bool = False
) -> str:
    raw = header[start:end]
    marker = raw.find(b"\x00")
    if marker >= 0:
        if any(raw[marker + 1 :]):
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        raw = raw[:marker]
    if not raw:
        if required:
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        return ""
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScanDataError("SCA001_ARCHIVE_INVALID") from exc
    if not bounded_plain_string(value, min(4096, end - start)):
        raise ScanDataError("SCA001_ARCHIVE_INVALID")
    return value


def _validate_tar_header_metadata(header: bytes) -> None:
    magic = header[257:263]
    version = header[263:265]
    if not (
        (magic == b"\x00" * 6 and version == b"\x00" * 2)
        or (magic in {b"ustar\x00", b"ustar "} and version in {b"00", b" \x00"})
    ):
        raise ScanDataError("SCA001_ARCHIVE_INVALID")
    if any(header[500:512]):
        raise ScanDataError("SCA001_ARCHIVE_INVALID")
    for start, end in (
        (100, 108),
        (108, 116),
        (116, 124),
        (124, 136),
        (136, 148),
        (148, 156),
        (329, 337),
        (337, 345),
    ):
        if any(byte not in b"01234567\x00 " for byte in header[start:end]):
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
    name = _tar_text_field(header, 0, 100, required=True)
    link_name = _tar_text_field(header, 157, 257)
    user_name = _tar_text_field(header, 265, 297)
    group_name = _tar_text_field(header, 297, 329)
    prefix = _tar_text_field(header, 345, 500)
    canonical_name = f"{prefix}/{name}" if prefix else name
    if link_name or any(
        _credential_capable_archive_text(value)
        for value in (canonical_name, user_name, group_name)
        if value
    ):
        raise ScanDataError("SCA001_ARCHIVE_INVALID")


def _tar_preflight(
    data: bytes,
    limits: dict[str, int],
    budget: WorkBudget,
    *,
    count_unpacked: bool,
) -> int:
    budget.ensure_archive_capacity(1)
    position = 0
    entries = 0
    total_unpacked = 0
    saw_end = False
    while position + 512 <= len(data):
        header = data[position : position + 512]
        if header == b"\x00" * 512:
            if (
                position + 1024 > len(data)
                or data[position + 512 : position + 1024] != b"\x00" * 512
            ):
                raise ScanDataError("SCA001_ARCHIVE_INVALID")
            if any(data[position + 1024 :]):
                raise ScanDataError("SCA001_ARCHIVE_INVALID")
            saw_end = True
            break
        if not _tar_header_checksum(header):
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        _validate_tar_header_metadata(header)
        budget.ensure_archive_capacity(entries + 1)
        type_flag = header[156:157] or b"\x00"
        if type_flag not in {b"\x00", b"0", b"5"}:
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        raw_size = header[124:136].strip(b"\x00 ") or b"0"
        try:
            size = int(raw_size, 8)
        except ValueError as exc:
            raise ScanDataError("SCA001_ARCHIVE_INVALID") from exc
        if (
            size < 0
            or size > limits["max_file_bytes"]
            or (type_flag == b"5" and size != 0)
        ):
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        entries += 1
        total_unpacked += size
        if total_unpacked > budget.remaining_archive_bytes():
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        payload_end = position + 512 + size
        next_position = position + 512 + ((size + 511) // 512) * 512
        if next_position > len(data) or any(data[payload_end:next_position]):
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        position = next_position
    if not saw_end:
        raise ScanDataError("SCA001_ARCHIVE_INVALID")
    if count_unpacked:
        budget.ensure_work_capacity(total_unpacked)
    return entries


def _tar_members(
    data: bytes,
    limits: dict[str, int],
    budget: WorkBudget,
    *,
    count_unpacked: bool = True,
) -> Iterator[ArchiveMember]:
    expected_entries = _tar_preflight(
        data, limits, budget, count_unpacked=count_unpacked
    )
    seen_names: set[str] = set()
    actual_entries = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for info in archive:
            actual_entries += 1
            is_directory = info.isdir()
            if info.size < 0 or info.size > limits["max_file_bytes"]:
                raise ScanDataError("SCA001_ARCHIVE_INVALID")
            name = _safe_member_name(
                info.name,
                directory=is_directory,
                seen_names=seen_names,
                maximum=limits["max_string_bytes"],
            )
            if is_directory:
                budget.charge_archive_member(0)
                continue
            if not info.isfile() or info.issym() or info.islnk():
                raise ScanDataError("SCA001_ARCHIVE_INVALID")
            if any(
                metadata and _credential_capable_archive_text(metadata)
                for metadata in (info.uname, info.gname)
            ):
                raise ScanDataError("SCA001_ARCHIVE_INVALID")
            budget.charge_archive_member(info.size, count_unpacked=count_unpacked)
            handle = archive.extractfile(info)
            if handle is None:
                raise ScanDataError("SCA001_ARCHIVE_INVALID")
            member_data = handle.read(info.size + 1)
            if len(member_data) != info.size:
                raise ScanDataError("SCA001_ARCHIVE_INVALID")
            yield ArchiveMember(name, member_data)
    if actual_entries != expected_entries:
        raise ScanDataError("SCA001_ARCHIVE_INVALID")


def _gzip_metadata_end(data: bytes, limits: dict[str, int]) -> int:
    if len(data) < 10 or data[:2] != b"\x1f\x8b" or data[2] != 8:
        raise ScanDataError("SCA001_ARCHIVE_INVALID")
    flags = data[3]
    if flags & 0xE0:
        raise ScanDataError("SCA001_ARCHIVE_INVALID")
    position = 10
    if flags & 0x04:
        if position + 2 > len(data):
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        extra_length = _u16(data, position)
        position += 2 + extra_length
        if position > len(data):
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        raise ScanDataError("SCA001_ARCHIVE_INVALID")
    for mask in (0x08, 0x10):
        if flags & mask:
            end = data.find(b"\x00", position, min(len(data), position + 4097))
            if end < 0:
                raise ScanDataError("SCA001_ARCHIVE_INVALID")
            try:
                metadata = data[position:end].decode("latin-1")
            except UnicodeError as exc:
                raise ScanDataError("SCA001_ARCHIVE_INVALID") from exc
            if not bounded_plain_string(
                metadata, min(limits["max_string_bytes"], 4096)
            ) or _credential_capable_archive_text(metadata):
                raise ScanDataError("SCA001_ARCHIVE_INVALID")
            position = end + 1
    if flags & 0x02:
        position += 2
    if position > len(data) - 8:
        raise ScanDataError("SCA001_ARCHIVE_INVALID")
    return position


def _gzip_payload(data: bytes, limits: dict[str, int], budget: WorkBudget) -> bytes:
    _gzip_metadata_end(data, limits)
    maximum = min(
        limits["max_archive_unpacked_bytes"],
        budget.remaining_archive_bytes(),
        budget.remaining_work_bytes(),
    )
    decoder = zlib.decompressobj(wbits=31)
    payload = decoder.decompress(data, maximum + 1)
    if len(payload) > maximum or decoder.unconsumed_tail or not decoder.eof:
        raise ScanDataError("SCA001_ARCHIVE_INVALID")
    payload += decoder.flush(maximum + 1 - len(payload))
    if len(payload) > maximum or decoder.unused_data:
        raise ScanDataError("SCA001_ARCHIVE_INVALID")
    budget.charge_archive_expansion(len(payload))
    return payload


def archive_members(
    data: bytes, limits: dict[str, int], budget: WorkBudget
) -> Iterator[ArchiveMember]:
    """Yield one archive's members and reject every nested supported container."""

    kind = detect_archive_kind(data, budget=budget)
    if kind is None:
        raise ScanDataError("SCA001_ARCHIVE_INVALID")
    try:
        if kind == "zip":
            yield from _zip_members(data, limits, budget)
            return
        if kind == "tar":
            yield from _tar_members(data, limits, budget)
            return
        payload = _gzip_payload(data, limits, budget)
        payload_kind = detect_archive_kind(payload, budget=budget)
        if payload_kind == "tar":
            yield from _tar_members(payload, limits, budget, count_unpacked=False)
            return
        if payload_kind is not None:
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        if len(payload) > limits["max_file_bytes"]:
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        budget.ensure_archive_capacity(1)
        budget.charge_archive_member(0, count_unpacked=False)
        yield ArchiveMember("<gzip-payload>", payload)
    except ScanDataError:
        raise
    except (
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        tarfile.TarError,
        lzma.LZMAError,
        OSError,
        EOFError,
        RuntimeError,
        UnicodeError,
        OverflowError,
        ValueError,
        zlib.error,
    ) as exc:
        raise ScanDataError("SCA001_ARCHIVE_INVALID") from exc
