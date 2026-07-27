"""Archive magic detection and globally budgeted safe member extraction."""

from __future__ import annotations

import gzip
import io
import lzma
import stat
import tarfile
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Iterator

from .model import ScanDataError, WorkBudget, bounded_plain_string


@dataclass(frozen=True)
class ArchiveMember:
    name: str
    data: bytes


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
    actual = sum(header[:148]) + (8 * 0x20) + sum(header[156:])
    return expected == actual


def detect_archive_kind(data: bytes) -> str | None:
    """Recognize supported containers by bytes, never by filename."""

    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if _tar_header_checksum(data):
        return "tar"
    return None


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
    ):
        raise ScanDataError("SCA001_ARCHIVE_INVALID")
    seen_names.add(canonical)
    return canonical


def _zip_members(
    data: bytes, limits: dict[str, int], budget: WorkBudget
) -> Iterator[ArchiveMember]:
    seen_names: set[str] = set()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        for info in sorted(infos, key=lambda item: item.filename):
            mode = (info.external_attr >> 16) & 0xFFFF
            file_type = stat.S_IFMT(mode)
            is_directory = info.is_dir()
            if (
                info.flag_bits & 0x1
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
            if info.file_size > max(1, info.compress_size) * 100:
                raise ScanDataError("SCA001_ARCHIVE_INVALID")
            budget.charge_archive_member(info.file_size)
            with archive.open(info, "r") as member:
                member_data = member.read(info.file_size + 1)
            if len(member_data) != info.file_size:
                raise ScanDataError("SCA001_ARCHIVE_INVALID")
            yield ArchiveMember(name, member_data)


def _tar_members(
    data: bytes,
    limits: dict[str, int],
    budget: WorkBudget,
    *,
    count_unpacked: bool = True,
) -> Iterator[ArchiveMember]:
    seen_names: set[str] = set()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for info in archive:
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
            budget.charge_archive_member(info.size, count_unpacked=count_unpacked)
            handle = archive.extractfile(info)
            if handle is None:
                raise ScanDataError("SCA001_ARCHIVE_INVALID")
            member_data = handle.read(info.size + 1)
            if len(member_data) != info.size:
                raise ScanDataError("SCA001_ARCHIVE_INVALID")
            yield ArchiveMember(name, member_data)


def _gzip_payload(data: bytes, limits: dict[str, int], budget: WorkBudget) -> bytes:
    maximum = min(
        limits["max_archive_unpacked_bytes"], budget.remaining_archive_bytes()
    )
    with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as compressed:
        payload = compressed.read(maximum + 1)
    if len(payload) > maximum:
        raise ScanDataError("SCA001_ARCHIVE_INVALID")
    budget.charge_archive_expansion(len(payload))
    return payload


def archive_members(
    data: bytes, limits: dict[str, int], budget: WorkBudget
) -> Iterator[ArchiveMember]:
    """Yield one top-level archive's members and reject every nested container."""

    kind = detect_archive_kind(data)
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
        payload_kind = detect_archive_kind(payload)
        if payload_kind == "tar":
            yield from _tar_members(payload, limits, budget, count_unpacked=False)
            return
        if payload_kind is not None:
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        if len(payload) > limits["max_file_bytes"]:
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        budget.charge_archive_member(0, count_unpacked=False)
        yield ArchiveMember("<gzip-payload>", payload)
    except ScanDataError:
        raise
    except (
        gzip.BadGzipFile,
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
