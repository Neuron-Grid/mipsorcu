"""Receive a bounded, fixed-set USTAR artifact stream from an isolated builder."""

from __future__ import annotations

import argparse
import os
import stat
import sys

BLOCK_SIZE = 512
FILE_LIMIT = 128 * 1024 * 1024
TOTAL_LIMIT = 384 * 1024 * 1024
TRAILER_LIMIT = 1024 * 1024
READ_SIZE = 64 * 1024
ARTIFACTS = {
    "demo": ("mipsorcu-orchestrator",),
    "postgres-tests": ("mipsorcu_orchestrator", "postgres_integration", "engine_postgres"),
}
NUMERIC_FIELDS = ((100, 108), (108, 116), (116, 124), (124, 136), (136, 148), (329, 337), (337, 345))


class InvalidArchive(ValueError):
    """The builder output did not match the fixed artifact contract."""


def read_exact(stream, length: int, *, allow_eof: bool = False) -> bytes | None:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = stream.read(length - len(chunks))
        if not chunk:
            if allow_eof and not chunks:
                return None
            raise InvalidArchive("truncated archive")
        chunks.extend(chunk)
    return bytes(chunks)


def parse_octal(field: bytes) -> int:
    value = field.strip(b"\0 ")
    if not value:
        return 0
    if any(byte < ord("0") or byte > ord("7") for byte in value):
        raise InvalidArchive("invalid USTAR numeric field")
    return int(value, 8)


def parse_header(block: bytes, allowed: set[str]) -> tuple[str, int]:
    if len(block) != BLOCK_SIZE or block[257:263] != b"ustar\0" or block[263:265] != b"00":
        raise InvalidArchive("expected a USTAR header")

    checksum = parse_octal(block[148:156])
    calculated = sum(block[:148]) + (ord(" ") * 8) + sum(block[156:])
    if checksum != calculated:
        raise InvalidArchive("invalid USTAR header checksum")

    for start, end in NUMERIC_FIELDS:
        parse_octal(block[start:end])

    raw_name = block[:100]
    name_bytes, separator, remainder = raw_name.partition(b"\0")
    if separator and any(remainder):
        raise InvalidArchive("invalid USTAR name padding")
    try:
        name = name_bytes.decode("ascii")
    except UnicodeDecodeError as error:
        raise InvalidArchive("non-ASCII artifact name") from error

    if block[156:157] not in (b"0", b"\0") or any(block[157:257]) or any(block[345:500]):
        raise InvalidArchive("only plain USTAR regular files are accepted")
    if name not in allowed:
        raise InvalidArchive("unexpected artifact name")
    if parse_octal(block[100:108]) != 0o500:
        raise InvalidArchive("unexpected artifact permissions")

    return name, parse_octal(block[124:136])


def write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short artifact write")
        view = view[written:]


def receive(mode: str, output_dir: str) -> None:
    expected = set(ARTIFACTS[mode])
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
    directory_fd = os.open(output_dir, directory_flags)
    try:
        directory = os.fstat(directory_fd)
        if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid() or stat.S_IMODE(directory.st_mode) != 0o700:
            raise InvalidArchive("output directory must be owner-controlled mode 0700")
        if os.listdir(directory_fd):
            raise InvalidArchive("output directory must be empty")

        received: set[str] = set()
        total_size = 0
        stream = sys.stdin.buffer
        while True:
            header = read_exact(stream, BLOCK_SIZE, allow_eof=True)
            if header is None:
                raise InvalidArchive("archive is missing its end markers")
            if not any(header):
                if any(read_exact(stream, BLOCK_SIZE)):
                    raise InvalidArchive("archive must end with two zero blocks")
                trailer_size = 0
                while True:
                    chunk = stream.read(min(READ_SIZE, TRAILER_LIMIT + 1 - trailer_size))
                    if not chunk:
                        break
                    trailer_size += len(chunk)
                    if trailer_size > TRAILER_LIMIT or any(chunk):
                        raise InvalidArchive("invalid or oversized archive trailer")
                if received != expected:
                    raise InvalidArchive("archive is missing required artifacts")
                return

            name, size = parse_header(header, expected)
            if name in received:
                raise InvalidArchive("duplicate artifact")
            if size == 0 or size > FILE_LIMIT or total_size + size > TOTAL_LIMIT:
                raise InvalidArchive("artifact is empty or exceeds size limits")

            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            descriptor = os.open(name, flags, 0o500, dir_fd=directory_fd)
            received.add(name)
            total_size += size
            try:
                remaining = size
                while remaining:
                    chunk = read_exact(stream, min(READ_SIZE, remaining))
                    write_all(descriptor, chunk)
                    remaining -= len(chunk)
                padding_size = (-size) % BLOCK_SIZE
                if padding_size and any(read_exact(stream, padding_size)):
                    raise InvalidArchive("invalid USTAR file padding")
            finally:
                os.close(descriptor)
    finally:
        os.close(directory_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=sorted(ARTIFACTS))
    parser.add_argument("output_dir")
    arguments = parser.parse_args()
    if not hasattr(os, "O_NOFOLLOW"):
        print("platform does not support O_NOFOLLOW", file=sys.stderr)
        return 1
    try:
        receive(arguments.mode, arguments.output_dir)
    except (InvalidArchive, OSError, OverflowError) as error:
        print(f"artifact receive failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
