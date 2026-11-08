"""
Binary Magic Signature Inspection & Header Analysis Engine.

Educational Overview:
---------------------
In POSIX and Unix-like operating systems, a file's extension (e.g., .txt, .pdf, .exe)
is merely a human-readable convention and advisory metadata stored in directory entries.
The kernel's execve() system call does not care about file extensions; instead, it looks
at the initial bytes of the file—known as the "magic bytes" or "file signature"—to determine
how to load and execute the file.

Attackers routinely exploit this architecture via "Extension Spoofing" and "Binary Masquerading":
- Naming a compiled ELF Linux binary or Windows PE32 executable as `financial_report.pdf`
- Naming a malicious bash shell script as `invoice.png`
- Relying on desktop file managers (like Windows Explorer, macOS Finder, or GNOME Nautilus)
  which may hide extensions or associate icons based solely on name, while backend processes
  or unaware users execute the payload.

This module provides a pure-Python, zero-dependency binary signature scanner that reads only
the initial header chunk (up to 4096 bytes) using defensive I/O patterns to categorize the file's
true biological format regardless of what its filename claims.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union


class FileTypeCategory(str, Enum):
    """
    High-level functional category of a file.

    Categorization enables defensive policy engines to distinguish harmless passive media
    (images, text) from active execution vectors (compiled binaries, scripts, installers).
    """
    EXECUTABLE = "executable"      # Machine code binaries (ELF, PE, Mach-O)
    SCRIPT = "script"              # Interpreted scripts (bash, python, perl, powershell)
    DOCUMENT = "document"          # Formatted office documents (PDF, DOCX, OLE, RTF)
    IMAGE = "image"                # Raster/vector graphics (PNG, JPEG, GIF, BMP, SVG)
    ARCHIVE = "archive"            # Compressed containers (ZIP, TAR, GZ, 7Z, BZ2, XZ)
    AUDIO_VIDEO = "media"          # Media streams (MP3, MP4, WAV, AVI)
    TEXT = "text"                  # Generic plaintext, source code, JSON, XML
    DATA = "data"                  # Raw structured or arbitrary data
    UNKNOWN = "unknown"            # Unrecognized binary or format


@dataclass(frozen=True)
class MagicInspectionResult:
    """
    Immutable structured report representing the low-level binary analysis of a file header.

    Attributes:
        mime_type: Standardized MIME representation (e.g., 'application/x-executable').
        category: High-level risk category (EXECUTABLE, SCRIPT, DOCUMENT, etc.).
        description: Human-readable technical description of the detected container/format.
        is_executable: True if format represents runnable machine code or interpreted instructions.
        magic_bytes_hex: Hexadecimal representation of the initial identifying bytes.
        details: Deep architectural metadata extracted from the file headers (architecture,
                 endianness, bitness, shebang interpreter path, etc.).
    """
    mime_type: str
    category: FileTypeCategory
    description: str
    is_executable: bool
    magic_bytes_hex: str
    details: Dict[str, Union[str, int, bool]] = field(default_factory=dict)


class MagicInspector:
    """
    Defensive binary file inspector.

    Reads header bytes directly from disk using bounded stream reads (never loading
    entire files into memory to avoid Denial-of-Service via ZIP bombs or multi-gigabyte memory exhaustion).
    """

    # Maximum bytes needed to inspect headers (4096 bytes covers ELF, PE, Mach-O, and Zip manifests)
    HEADER_READ_SIZE: int = 4096

    # =========================================================================
    # WELL-KNOWN BINARY SIGNATURE CONSTANTS (Offsets and Magic Byte Sequences)
    # =========================================================================

    # ELF (Executable and Linkable Format) - Standard on Linux, BSD, and Solaris
    # Byte 0-3: 0x7F 'E' 'L' 'F' (\x7fELF)
    ELF_MAGIC: bytes = b"\x7fELF"

    # Microsoft PE (Portable Executable) - Used by DOS, Windows .exe, .dll, .sys
    # Byte 0-1: 'M' 'Z' (Mark Zbikowski signature from DOS 2.0)
    DOS_MZ_MAGIC: bytes = b"MZ"

    # Apple Mach-O (Mach Object) - Used by macOS, iOS, Darwin
    # 32-bit and 64-bit, Little Endian and Big Endian variants
    MACHO_32_BE: bytes = b"\xfe\xed\xfa\xce"  # 0xFEEDFACE
    MACHO_32_LE: bytes = b"\xce\xfa\xed\xfe"  # 0xCEFAEDFE
    MACHO_64_BE: bytes = b"\xfe\xed\xfa\xcf"  # 0xFEEDFACF
    MACHO_64_LE: bytes = b"\xcf\xfa\xed\xfe"  # 0xCFFAEDFE
    MACHO_FAT_BE: bytes = b"\xca\xfe\xba\xbe" # 0xCAFEBABE (Universal fat binary)
    MACHO_FAT_LE: bytes = b"\xbe\xba\xfe\xca" # 0xBEBAFECA

    # WebAssembly (Wasm) Binary Format
    # Byte 0-3: \x00 'a' 's' 'm'
    WASM_MAGIC: bytes = b"\x00asm"

    # Script Interpreters: Shebang line
    # Byte 0-1: '#' '!' (\x23\x21)
    SHEBANG_MAGIC: bytes = b"#!"

    # Adobe Portable Document Format
    PDF_MAGIC: bytes = b"%PDF-"

    # Standard Compressed Archives
    ZIP_LOCAL_HEADER: bytes = b"PK\x03\x04"  # Standard zip entry header
    ZIP_EMPTY_ARCHIVE: bytes = b"PK\x05\x06" # Empty zip directory record
    ZIP_SPANNED: bytes = b"PK\x07\x08"       # Spanned archive marker
    GZIP_MAGIC: bytes = b"\x1f\x8b"          # RFC 1952 gzip ID1 + ID2
    BZIP2_MAGIC: bytes = b"BZh"              # 'B' 'Z' 'h' block-sorting compressor
    XZ_MAGIC: bytes = b"\xfd7zXZ\x00"        # XZ stream format
    SEVEN_ZIP_MAGIC: bytes = b"7z\xbc\xaf\x27\x1c" # 7-Zip header
    TAR_USTAR_MAGIC: bytes = b"ustar"        # POSIX ustar at offset 257

    # Standard Raster Image Formats
    PNG_MAGIC: bytes = b"\x89PNG\r\n\x1a\n"  # 8-byte PNG header with DOS/Unix line break test
    JPEG_SOI: bytes = b"\xff\xd8\xff"        # JPEG Start of Image (SOI) marker
    GIF_87A: bytes = b"GIF87a"               # CompuServe GIF 1987
    GIF_89A: bytes = b"GIF89a"               # CompuServe GIF 1989 (supports animation/transparency)
    BMP_MAGIC: bytes = b"BM"                 # Windows Bitmap header
    TIFF_LE: bytes = b"II*\x00"              # Intel Little-Endian TIFF
    TIFF_BE: bytes = b"MM\x00*"              # Motorola Big-Endian TIFF

    # Microsoft OLE Compound Document (Legacy DOC, XLS, PPT)
    OLE_COMPOUND_MAGIC: bytes = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

    @classmethod
    def inspect_bytes(cls, header: bytes) -> MagicInspectionResult:
        """
        Analyze an in-memory byte slice (typically initial 4KB of a file).

        This is a pure deterministic classification function with zero side effects.
        """
        # If payload is completely empty, it's a 0-byte file
        if not header:
            return MagicInspectionResult(
                mime_type="application/x-empty",
                category=FileTypeCategory.TEXT,
                description="Empty file (zero bytes)",
                is_executable=False,
                magic_bytes_hex="",
                details={"file_size": 0},
            )

        # Capture first 16 bytes as hex representation for audit logging
        hex_preview = header[:16].hex(" ")

        # ---------------------------------------------------------------------
        # 1. LINUX / UNIX ELF BINARY PARSING
        # ---------------------------------------------------------------------
        if header.startswith(cls.ELF_MAGIC):
            return cls._parse_elf_header(header, hex_preview)

        # ---------------------------------------------------------------------
        # 2. MICROSOFT WINDOWS PE / DOS MZ BINARY PARSING
        # ---------------------------------------------------------------------
        if header.startswith(cls.DOS_MZ_MAGIC):
            pe_result = cls._parse_pe_header(header, hex_preview)
            if pe_result is not None:
                return pe_result

        # ---------------------------------------------------------------------
        # 3. APPLE MACOS / IOS MACH-O BINARY PARSING
        # ---------------------------------------------------------------------
        macho_result = cls._parse_macho_header(header, hex_preview)
        if macho_result is not None:
            return macho_result

        # ---------------------------------------------------------------------
        # 4. WEBASSEMBLY (WASM) BINARY PARSING
        # ---------------------------------------------------------------------
        if header.startswith(cls.WASM_MAGIC):
            wasm_version = struct.unpack("<I", header[4:8])[0] if len(header) >= 8 else 1
            return MagicInspectionResult(
                mime_type="application/wasm",
                category=FileTypeCategory.EXECUTABLE,
                description="WebAssembly binary module",
                is_executable=True,
                magic_bytes_hex=hex_preview,
                details={"format": "WebAssembly", "version": wasm_version},
            )

        # ---------------------------------------------------------------------
        # 5. POSIX INTERPRETED SCRIPTS (SHEBANG #!)
        # ---------------------------------------------------------------------
        if header.startswith(cls.SHEBANG_MAGIC):
            return cls._parse_shebang(header, hex_preview)

        # ---------------------------------------------------------------------
        # 6. ADOBE PDF DOCUMENTS
        # ---------------------------------------------------------------------
        if header.startswith(cls.PDF_MAGIC):
            # Extract PDF version e.g. %PDF-1.7
            first_line = header.split(b"\n", 1)[0].decode("ascii", errors="replace").strip()
            return MagicInspectionResult(
                mime_type="application/pdf",
                category=FileTypeCategory.DOCUMENT,
                description=f"Adobe Portable Document Format ({first_line})",
                is_executable=False,
                magic_bytes_hex=hex_preview,
                details={"version_header": first_line},
            )

        # ---------------------------------------------------------------------
        # 7. ARCHIVES & COMPRESSED CONTAINERS
        # ---------------------------------------------------------------------
        if header.startswith((cls.ZIP_LOCAL_HEADER, cls.ZIP_EMPTY_ARCHIVE, cls.ZIP_SPANNED)):
            return cls._parse_zip_container(header, hex_preview)

        if header.startswith(cls.GZIP_MAGIC):
            return MagicInspectionResult(
                mime_type="application/gzip",
                category=FileTypeCategory.ARCHIVE,
                description="GZIP compressed archive",
                is_executable=False,
                magic_bytes_hex=hex_preview,
                details={"compression": "DEFLATE"},
            )

        if header.startswith(cls.BZIP2_MAGIC):
            return MagicInspectionResult(
                mime_type="application/x-bzip2",
                category=FileTypeCategory.ARCHIVE,
                description="BZIP2 compressed archive",
                is_executable=False,
                magic_bytes_hex=hex_preview,
                details={"compression": "Burrows-Wheeler"},
            )

        if header.startswith(cls.XZ_MAGIC):
            return MagicInspectionResult(
                mime_type="application/x-xz",
                category=FileTypeCategory.ARCHIVE,
                description="XZ compressed archive (LZMA2)",
                is_executable=False,
                magic_bytes_hex=hex_preview,
                details={"compression": "LZMA2"},
            )

        if header.startswith(cls.SEVEN_ZIP_MAGIC):
            return MagicInspectionResult(
                mime_type="application/x-7z-compressed",
                category=FileTypeCategory.ARCHIVE,
                description="7-Zip compressed archive",
                is_executable=False,
                magic_bytes_hex=hex_preview,
                details={"format": "7z"},
            )

        # POSIX Tar check (ustar magic string at offset 257)
        if len(header) >= 262 and header[257:262] == cls.TAR_USTAR_MAGIC:
            return MagicInspectionResult(
                mime_type="application/x-tar",
                category=FileTypeCategory.ARCHIVE,
                description="POSIX TAR archive (ustar format)",
                is_executable=False,
                magic_bytes_hex=hex_preview,
                details={"format": "ustar"},
            )

        # ---------------------------------------------------------------------
        # 8. RASTER & VECTOR IMAGES
        # ---------------------------------------------------------------------
        if header.startswith(cls.PNG_MAGIC):
            return MagicInspectionResult(
                mime_type="image/png",
                category=FileTypeCategory.IMAGE,
                description="Portable Network Graphics (PNG) image",
                is_executable=False,
                magic_bytes_hex=hex_preview,
                details={"format": "PNG"},
            )

        if header.startswith(cls.JPEG_SOI):
            return MagicInspectionResult(
                mime_type="image/jpeg",
                category=FileTypeCategory.IMAGE,
                description="JPEG raster image",
                is_executable=False,
                magic_bytes_hex=hex_preview,
                details={"format": "JPEG"},
            )

        if header.startswith((cls.GIF_87A, cls.GIF_89A)):
            version = header[:6].decode("ascii", errors="replace")
            return MagicInspectionResult(
                mime_type="image/gif",
                category=FileTypeCategory.IMAGE,
                description=f"Graphics Interchange Format ({version})",
                is_executable=False,
                magic_bytes_hex=hex_preview,
                details={"format": version},
            )

        if header.startswith(cls.BMP_MAGIC):
            return MagicInspectionResult(
                mime_type="image/bmp",
                category=FileTypeCategory.IMAGE,
                description="Windows Bitmap (BMP) image",
                is_executable=False,
                magic_bytes_hex=hex_preview,
                details={"format": "BMP"},
            )

        if header.startswith((cls.TIFF_LE, cls.TIFF_BE)):
            endianness = "little-endian" if header.startswith(cls.TIFF_LE) else "big-endian"
            return MagicInspectionResult(
                mime_type="image/tiff",
                category=FileTypeCategory.IMAGE,
                description=f"Tagged Image File Format (TIFF, {endianness})",
                is_executable=False,
                magic_bytes_hex=hex_preview,
                details={"format": "TIFF", "endianness": endianness},
            )

        # ---------------------------------------------------------------------
        # 9. MICROSOFT LEGACY OLE COMPOUND DOCUMENTS
        # ---------------------------------------------------------------------
        if header.startswith(cls.OLE_COMPOUND_MAGIC):
            return MagicInspectionResult(
                mime_type="application/x-ole-storage",
                category=FileTypeCategory.DOCUMENT,
                description="Microsoft OLE Compound Document (legacy DOC/XLS/PPT or MSI)",
                is_executable=False,
                magic_bytes_hex=hex_preview,
                details={"format": "OLECF"},
            )

        # ---------------------------------------------------------------------
        # 10. TEXT / PLAINTEXT HEURISTICS
        # ---------------------------------------------------------------------
        text_result = cls._inspect_plaintext_heuristics(header, hex_preview)
        if text_result is not None:
            return text_result

        # ---------------------------------------------------------------------
        # 11. UNKNOWN BINARY DATA
        # ---------------------------------------------------------------------
        return MagicInspectionResult(
            mime_type="application/octet-stream",
            category=FileTypeCategory.UNKNOWN,
            description="Unidentified raw binary payload",
            is_executable=False,
            magic_bytes_hex=hex_preview,
            details={"sample_length": len(header)},
        )

    @classmethod
    def inspect_file(cls, path: Union[str, Path]) -> MagicInspectionResult:
        """
        Safely open and inspect a file from the filesystem.

        Defensive Guarantees:
        1. Never loads the whole file into RAM: reads strictly up to HEADER_READ_SIZE (4KB).
        2. Handles permission errors and broken symlinks gracefully.
        3. Uses context manager for immediate descriptor closure.
        """
        file_path = Path(path)

        # Defense: Verify file exists and is accessible
        if not file_path.is_file():
            raise FileNotFoundError(f"Target path does not exist or is not a regular file: {file_path}")

        try:
            # Read first 4KB using binary mode
            with open(file_path, "rb") as f:
                header = f.read(cls.HEADER_READ_SIZE)
            return cls.inspect_bytes(header)
        except PermissionError as pe:
            # Security boundary: If read permissions are denied, flag as inaccessible
            return MagicInspectionResult(
                mime_type="application/x-inaccessible",
                category=FileTypeCategory.UNKNOWN,
                description=f"Permission denied reading file header: {pe}",
                is_executable=False,
                magic_bytes_hex="",
                details={"error": "PermissionError"},
            )

    # =========================================================================
    # LOW-LEVEL FORMAT PARSERS (Educational System Deep Dives)
    # =========================================================================

    @classmethod
    def _parse_elf_header(cls, header: bytes, hex_preview: str) -> MagicInspectionResult:
        """
        Parse POSIX Executable and Linkable Format (ELF) header fields.

        ELF Header Structure (from /usr/include/elf.h):
        - e_ident[4] (EI_CLASS): 1 = 32-bit architecture, 2 = 64-bit architecture
        - e_ident[5] (EI_DATA): 1 = 2's complement little-endian, 2 = 2's complement big-endian
        - e_ident[6] (EI_VERSION): 1 = Current ELF standard version
        - e_ident[7] (EI_OSABI): Target Operating System ABI (0=SysV, 3=Linux, 9=FreeBSD)
        - e_type (offset 16, 2 bytes): 1=ET_REL (.o), 2=ET_EXEC (executable), 3=ET_DYN (.so or PIE binary)
        """
        details: Dict[str, Union[str, int, bool]] = {"format": "ELF"}

        # Extract bitness (Byte 4)
        if len(header) > 4:
            ei_class = header[4]
            if ei_class == 1:
                details["bitness"] = 32
                details["arch_class"] = "ELF32"
            elif ei_class == 2:
                details["bitness"] = 64
                details["arch_class"] = "ELF64"

        # Extract endianness (Byte 5)
        endian = "<"  # default little endian
        if len(header) > 5:
            ei_data = header[5]
            if ei_data == 1:
                details["endianness"] = "little-endian"
                endian = "<"
            elif ei_data == 2:
                details["endianness"] = "big-endian"
                endian = ">"

        # Extract OS/ABI (Byte 7)
        if len(header) > 7:
            abi_map = {0: "System V", 3: "Linux", 6: "Solaris", 9: "FreeBSD", 97: "ARM"}
            details["os_abi"] = abi_map.get(header[7], f"Unknown (0x{header[7]:02x})")

        # Extract e_type (offset 16, uint16)
        if len(header) >= 18:
            e_type = struct.unpack(f"{endian}H", header[16:18])[0]
            type_map = {
                1: "Relocatable Object (.o)",
                2: "Executable Binary",
                3: "Shared Object (.so or PIE executable)",
                4: "Core Dump",
            }
            details["elf_type"] = type_map.get(e_type, f"Unknown ({e_type})")

        arch_desc = f"{details.get('arch_class', 'ELF')} ({details.get('elf_type', 'executable')})"
        return MagicInspectionResult(
            mime_type="application/x-executable-elf",
            category=FileTypeCategory.EXECUTABLE,
            description=f"Linux/Unix ELF binary: {arch_desc}",
            is_executable=True,
            magic_bytes_hex=hex_preview,
            details=details,
        )

    @classmethod
    def _parse_pe_header(cls, header: bytes, hex_preview: str) -> Optional[MagicInspectionResult]:
        """
        Parse Microsoft Portable Executable (PE) headers.

        Windows binaries start with a legacy MS-DOS 2.0 stub beginning with 'MZ' (0x4D 0x5A).
        At offset 0x3C (60 bytes) is a 4-byte little-endian integer (`e_lfanew`) pointing
        to the location of the true NT PE header. The PE header must start with the
        magic signature 'PE\\0\\0' (0x50 0x45 0x00 0x00).
        """
        details: Dict[str, Union[str, int, bool]] = {"format": "PE"}

        # Check if file has enough bytes to contain the e_lfanew pointer (offset 0x3C to 0x40)
        if len(header) < 0x40:
            # Short MZ file - DOS executable or stub
            return MagicInspectionResult(
                mime_type="application/x-dosexec",
                category=FileTypeCategory.EXECUTABLE,
                description="DOS MZ executable or stub",
                is_executable=True,
                magic_bytes_hex=hex_preview,
                details=details,
            )

        # Unpack e_lfanew (pointer to PE header)
        pe_offset = struct.unpack("<I", header[0x3C:0x40])[0]
        details["pe_offset"] = pe_offset

        # Verify PE signature at indicated offset
        if len(header) >= pe_offset + 4 and header[pe_offset:pe_offset + 4] == b"PE\x00\x00":
            # Target is a confirmed Win32/Win64 PE executable
            details["has_pe_signature"] = True

            # Machine type is at pe_offset + 4 (uint16)
            if len(header) >= pe_offset + 6:
                machine_type = struct.unpack("<H", header[pe_offset + 4:pe_offset + 6])[0]
                machine_map = {
                    0x014C: "Intel x86 (32-bit)",
                    0x8664: "AMD64 / x86-64 (64-bit)",
                    0x0200: "Intel Itanium (IA-64)",
                    0xAA64: "ARM64 Little-Endian",
                }
                details["machine"] = machine_map.get(machine_type, f"Unknown (0x{machine_type:04X})")

            # Characteristics flag is at pe_offset + 22 (uint16)
            # 0x2000 = DLL (IMAGE_FILE_DLL), 0x0002 = EXECUTABLE_IMAGE
            if len(header) >= pe_offset + 24:
                characteristics = struct.unpack("<H", header[pe_offset + 22:pe_offset + 24])[0]
                is_dll = bool(characteristics & 0x2000)
                details["is_dll"] = is_dll
                pe_kind = "DLL" if is_dll else "EXE"
            else:
                pe_kind = "EXE"

            return MagicInspectionResult(
                mime_type="application/x-dosexec",
                category=FileTypeCategory.EXECUTABLE,
                description=f"Windows PE32/PE32+ {pe_kind} ({details.get('machine', 'x86/x64')})",
                is_executable=True,
                magic_bytes_hex=hex_preview,
                details=details,
            )

        # Fallback: file begins with 'MZ' but lacks PE signature (legacy 16-bit DOS or truncated)
        return MagicInspectionResult(
            mime_type="application/x-dosexec",
            category=FileTypeCategory.EXECUTABLE,
            description="MS-DOS executable or MZ stub",
            is_executable=True,
            magic_bytes_hex=hex_preview,
            details=details,
        )

    @classmethod
    def _parse_macho_header(cls, header: bytes, hex_preview: str) -> Optional[MagicInspectionResult]:
        """
        Parse Apple Mach-O binaries (macOS / iOS executables, dylibs, bundles).

        Mach-O uses 4-byte magic headers distinguishing 32-bit vs 64-bit architectures
        and endianness. It also supports Fat Universal binaries packing multiple architectures
        (e.g., x86_64 + ARM64 Apple Silicon) under the signature 0xCAFEBABE or 0xBEBAFECA.
        """
        # 64-bit Mach-O Little-Endian (Standard on Modern macOS x86_64 and arm64)
        if header.startswith(cls.MACHO_64_LE):
            return MagicInspectionResult(
                mime_type="application/x-mach-binary",
                category=FileTypeCategory.EXECUTABLE,
                description="Apple Mach-O 64-bit binary (little-endian)",
                is_executable=True,
                magic_bytes_hex=hex_preview,
                details={"format": "Mach-O", "bitness": 64, "endianness": "little-endian"},
            )

        # 64-bit Mach-O Big-Endian
        if header.startswith(cls.MACHO_64_BE):
            return MagicInspectionResult(
                mime_type="application/x-mach-binary",
                category=FileTypeCategory.EXECUTABLE,
                description="Apple Mach-O 64-bit binary (big-endian)",
                is_executable=True,
                magic_bytes_hex=hex_preview,
                details={"format": "Mach-O", "bitness": 64, "endianness": "big-endian"},
            )

        # 32-bit Mach-O Little-Endian
        if header.startswith(cls.MACHO_32_LE):
            return MagicInspectionResult(
                mime_type="application/x-mach-binary",
                category=FileTypeCategory.EXECUTABLE,
                description="Apple Mach-O 32-bit binary (little-endian)",
                is_executable=True,
                magic_bytes_hex=hex_preview,
                details={"format": "Mach-O", "bitness": 32, "endianness": "little-endian"},
            )

        # 32-bit Mach-O Big-Endian
        if header.startswith(cls.MACHO_32_BE):
            return MagicInspectionResult(
                mime_type="application/x-mach-binary",
                category=FileTypeCategory.EXECUTABLE,
                description="Apple Mach-O 32-bit binary (big-endian)",
                is_executable=True,
                magic_bytes_hex=hex_preview,
                details={"format": "Mach-O", "bitness": 32, "endianness": "big-endian"},
            )

        # Fat Universal Binary (0xCAFEBABE or 0xBEBAFECA)
        # Note: 0xCAFEBABE is shared with Java .class files.
        # We differentiate by checking bytes 4-8: In Java class files, bytes 4-5 are minor_version
        # and 6-7 are major_version (>= 45 for Java 1.1+). In Mach-O, bytes 4-7 are nfat_arch (uint32).
        if header.startswith(cls.MACHO_FAT_BE):
            if len(header) >= 8:
                major_version = struct.unpack(">H", header[6:8])[0]
                if 45 <= major_version <= 70:
                    return MagicInspectionResult(
                        mime_type="application/java-vm",
                        category=FileTypeCategory.EXECUTABLE,
                        description=f"Compiled Java Class bytecode (major version {major_version})",
                        is_executable=True,
                        magic_bytes_hex=hex_preview,
                        details={"format": "Java .class", "major_version": major_version},
                    )

            # Otherwise, it's an Apple Mach-O Universal Fat Binary
            return MagicInspectionResult(
                mime_type="application/x-mach-binary",
                category=FileTypeCategory.EXECUTABLE,
                description="Apple Mach-O Universal Fat Binary (multi-architecture)",
                is_executable=True,
                magic_bytes_hex=hex_preview,
                details={"format": "Mach-O Fat", "endianness": "big-endian"},
            )

        if header.startswith(cls.MACHO_FAT_LE):
            return MagicInspectionResult(
                mime_type="application/x-mach-binary",
                category=FileTypeCategory.EXECUTABLE,
                description="Apple Mach-O Universal Fat Binary (little-endian)",
                is_executable=True,
                magic_bytes_hex=hex_preview,
                details={"format": "Mach-O Fat", "endianness": "little-endian"},
            )

        return None

    @classmethod
    def _parse_shebang(cls, header: bytes, hex_preview: str) -> MagicInspectionResult:
        """
        Parse POSIX Shebang (`#!`) interpreter directive.

        When an executable script is invoked on Linux/macOS, the kernel's binfmt_script handler
        reads the first line to identify the interpreter path (e.g., #!/bin/bash, #!/usr/bin/env python3).
        This makes scripts weaponizable execution vectors even without an extension.
        """
        first_line = header.split(b"\n", 1)[0].decode("utf-8", errors="replace").strip()
        interpreter = first_line[2:].strip()

        # Classify script type based on interpreter binary name
        lower_interp = interpreter.lower()
        script_type = "Generic shell script"
        mime = "text/x-shellscript"

        if "bash" in lower_interp:
            script_type = "GNU Bash script"
        elif "sh" in lower_interp:
            script_type = "POSIX Shell script"
        elif "python" in lower_interp:
            script_type = "Python script"
            mime = "text/x-python"
        elif "perl" in lower_interp:
            script_type = "Perl script"
            mime = "text/x-perl"
        elif "ruby" in lower_interp:
            script_type = "Ruby script"
            mime = "text/x-ruby"
        elif "node" in lower_interp:
            script_type = "Node.js JavaScript script"
            mime = "application/javascript"

        return MagicInspectionResult(
            mime_type=mime,
            category=FileTypeCategory.SCRIPT,
            description=f"{script_type} (interpreter: {interpreter})",
            is_executable=True,
            magic_bytes_hex=hex_preview,
            details={"interpreter": interpreter, "shebang_line": first_line},
        )

    @classmethod
    def _parse_zip_container(cls, header: bytes, hex_preview: str) -> MagicInspectionResult:
        """
        Inspect PKZip containers to distinguish generic ZIPs from Office documents (DOCX/XLSX/PPTX) or JARs.

        Modern Microsoft Office documents (.docx, .xlsx, .pptx) are Open Packaging Conventions (OPC)
        ZIP archives containing XML parts. Attackers frequently disguise malicious scripts or executables
        as .docx or .xlsx. Conversely, checking internal paths like '[Content_Types].xml' verifies genuine Office documents.
        """
        details: Dict[str, Union[str, int, bool]] = {"format": "ZIP"}

        # Search within the header chunk for Office or Java manifest signatures
        if b"[Content_Types].xml" in header:
            if b"word/" in header:
                return MagicInspectionResult(
                    mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    category=FileTypeCategory.DOCUMENT,
                    description="Microsoft Word Document (DOCX)",
                    is_executable=False,
                    magic_bytes_hex=hex_preview,
                    details={"format": "DOCX", "container": "ZIP"},
                )
            if b"xl/" in header:
                return MagicInspectionResult(
                    mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    category=FileTypeCategory.DOCUMENT,
                    description="Microsoft Excel Spreadsheet (XLSX)",
                    is_executable=False,
                    magic_bytes_hex=hex_preview,
                    details={"format": "XLSX", "container": "ZIP"},
                )
            if b"ppt/" in header:
                return MagicInspectionResult(
                    mime_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
                    category=FileTypeCategory.DOCUMENT,
                    description="Microsoft PowerPoint Presentation (PPTX)",
                    is_executable=False,
                    magic_bytes_hex=hex_preview,
                    details={"format": "PPTX", "container": "ZIP"},
                )

        if b"META-INF/MANIFEST.MF" in header:
            return MagicInspectionResult(
                mime_type="application/java-archive",
                category=FileTypeCategory.ARCHIVE,
                description="Java Archive (JAR / APK package)",
                is_executable=True,
                magic_bytes_hex=hex_preview,
                details={"format": "JAR", "container": "ZIP"},
            )

        return MagicInspectionResult(
            mime_type="application/zip",
            category=FileTypeCategory.ARCHIVE,
            description="Standard PKZip compressed archive",
            is_executable=False,
            magic_bytes_hex=hex_preview,
            details=details,
        )

    @classmethod
    def _inspect_plaintext_heuristics(cls, header: bytes, hex_preview: str) -> Optional[MagicInspectionResult]:
        """
        Analyze whether buffer is plaintext, source code, or text script.

        Heuristic:
        Binary files typically contain null bytes (`\\x00`) or a high ratio of non-printable
        control characters (outside ASCII 9-13, 32-126). Plaintext files lack null bytes
        and decode cleanly as UTF-8 or ASCII.
        """
        # If null byte exists in initial chunk, it is almost certainly a binary format
        if b"\x00" in header:
            return None

        try:
            decoded = header.decode("utf-8")
        except UnicodeDecodeError:
            try:
                decoded = header.decode("latin-1")
            except UnicodeDecodeError:
                return None

        stripped = decoded.strip()
        lower_stripped = stripped.lower()

        # Batch script detection
        if lower_stripped.startswith("@echo") or lower_stripped.startswith("rem "):
            return MagicInspectionResult(
                mime_type="text/x-msdos-batch",
                category=FileTypeCategory.SCRIPT,
                description="Windows Batch / CMD script",
                is_executable=True,
                magic_bytes_hex=hex_preview,
                details={"format": "Batch"},
            )

        # HTML / XML / SVG detection
        if stripped.startswith("<!DOCTYPE html") or stripped.startswith("<html"):
            return MagicInspectionResult(
                mime_type="text/html",
                category=FileTypeCategory.DOCUMENT,
                description="HTML hypertext document",
                is_executable=False,
                magic_bytes_hex=hex_preview,
                details={"format": "HTML"},
            )

        if stripped.startswith("<?xml") or stripped.startswith("<svg"):
            mime = "image/svg+xml" if "<svg" in stripped else "text/xml"
            cat = FileTypeCategory.IMAGE if "<svg" in stripped else FileTypeCategory.DOCUMENT
            return MagicInspectionResult(
                mime_type=mime,
                category=cat,
                description="XML / SVG document",
                is_executable=False,
                magic_bytes_hex=hex_preview,
                details={"format": "XML/SVG"},
            )

        # JSON detection
        if (stripped.startswith("{") and "}" in stripped) or (stripped.startswith("[") and "]" in stripped):
            return MagicInspectionResult(
                mime_type="application/json",
                category=FileTypeCategory.TEXT,
                description="JSON structured data",
                is_executable=False,
                magic_bytes_hex=hex_preview,
                details={"format": "JSON"},
            )

        # Generic plaintext
        return MagicInspectionResult(
            mime_type="text/plain",
            category=FileTypeCategory.TEXT,
            description="Plain text document",
            is_executable=False,
            magic_bytes_hex=hex_preview,
            details={"sample_chars": len(stripped)},
        )
