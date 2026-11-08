"""
Program: Quarantine Sentinel - Binary Magic Signature & Header Analyzer
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Inspect initial binary header bytes to determine true biological file formats (ELF, PE, Mach-O, WASM, Shebang, PDF, ZIP, Images) independently of untrusted file extensions.
"""

from __future__ import annotations

## Standard binary parsing and data container libraries
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union


## ----------------------------------------------------------------------------
## File Type Classification Enum
## ----------------------------------------------------------------------------

class FileTypeCategory(str, Enum):
    """
    High-level functional category of a file.

    Categorization enables defensive policy engines to distinguish harmless passive media
    (images, text) from active execution vectors (compiled binaries, scripts, installers).
    """
    ## Compiled native machine code (ELF, PE, Mach-O, WebAssembly)
    EXECUTABLE = "executable"

    ## Interpreted scripting code (Bash, Python, Perl, Ruby, Node, Batch)
    SCRIPT = "script"

    ## Structured office documents and page description formats (PDF, DOCX, XLSX, OLE)
    DOCUMENT = "document"

    ## Raster and vector graphics formats (PNG, JPEG, GIF, BMP, TIFF, SVG)
    IMAGE = "image"

    ## Compressed archive containers (ZIP, GZIP, BZIP2, XZ, 7Z, TAR)
    ARCHIVE = "archive"

    ## Audio and video media containers (MP3, MP4, WAV, AVI)
    AUDIO_VIDEO = "media"

    ## Plain text documents, configuration files, and human-readable formats
    TEXT = "text"

    ## Structured or unstructured data blobs
    DATA = "data"

    ## Unrecognized or unclassified binary payloads
    UNKNOWN = "unknown"


## ----------------------------------------------------------------------------
## Inspection Result Data Structure
## ----------------------------------------------------------------------------

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
        details: Deep architectural metadata extracted from the file headers.
    """
    ## Standardized MIME type string
    mime_type: str

    ## High-level threat assessment category
    category: FileTypeCategory

    ## Descriptive summary of format architecture and sub-type
    description: str

    ## Boolean indicating if payload can be executed by kernel or interpreter
    is_executable: bool

    ## Hexadecimal string showing first 16 bytes for forensic audit logs
    magic_bytes_hex: str

    ## Key-value architectural metadata dictionary
    details: Dict[str, Union[str, int, bool]] = field(default_factory=dict)


## ----------------------------------------------------------------------------
## Magic Inspection Engine
## ----------------------------------------------------------------------------

class MagicInspector:
    """
    Defensive binary file inspector.

    Reads header bytes directly from disk using bounded stream reads (never loading
    entire files into memory to avoid Denial-of-Service via ZIP bombs or multi-gigabyte memory exhaustion).
    """

    ## Bounded buffer limit: 4096 bytes covers headers for ELF, PE, Mach-O, and Zip manifests
    HEADER_READ_SIZE: int = 4096

    ## =========================================================================
    ## WELL-KNOWN BINARY SIGNATURE CONSTANTS
    ## =========================================================================

    ## Linux/Unix Executable and Linkable Format (ELF) signature: 0x7F 'E' 'L' 'F'
    ELF_MAGIC: bytes = b"\x7fELF"

    ## Microsoft DOS/PE executable stub signature: 'M' 'Z' (Mark Zbikowski)
    DOS_MZ_MAGIC: bytes = b"MZ"

    ## Apple Mach-O 32-bit Big Endian: 0xFEEDFACE
    MACHO_32_BE: bytes = b"\xfe\xed\xfa\xce"

    ## Apple Mach-O 32-bit Little Endian: 0xCEFAEDFE
    MACHO_32_LE: bytes = b"\xce\xfa\xed\xfe"

    ## Apple Mach-O 64-bit Big Endian: 0xFEEDFACF
    MACHO_64_BE: bytes = b"\xfe\xed\xfa\xcf"

    ## Apple Mach-O 64-bit Little Endian: 0xCFFAEDFE
    MACHO_64_LE: bytes = b"\xcf\xfa\xed\xfe"

    ## Apple Universal Fat Binary Big Endian: 0xCAFEBABE (shared with Java class)
    MACHO_FAT_BE: bytes = b"\xca\xfe\xba\xbe"

    ## Apple Universal Fat Binary Little Endian: 0xBEBAFECA
    MACHO_FAT_LE: bytes = b"\xbe\xba\xfe\xca"

    ## WebAssembly (Wasm) Binary Format: 0x00 'a' 's' 'm'
    WASM_MAGIC: bytes = b"\x00asm"

    ## POSIX Shebang directive for interpreted executable scripts: '#' '!'
    SHEBANG_MAGIC: bytes = b"#!"

    ## Adobe Portable Document Format signature: '%PDF-'
    PDF_MAGIC: bytes = b"%PDF-"

    ## Standard PKZip entry local file header: 'P' 'K' 0x03 0x04
    ZIP_LOCAL_HEADER: bytes = b"PK\x03\x04"

    ## Empty ZIP archive end-of-central-directory: 'P' 'K' 0x05 0x06
    ZIP_EMPTY_ARCHIVE: bytes = b"PK\x05\x06"

    ## Spanned ZIP archive marker: 'P' 'K' 0x07 0x08
    ZIP_SPANNED: bytes = b"PK\x07\x08"

    ## GNU Zip (GZIP) RFC 1952 signature: 0x1F 0x8B
    GZIP_MAGIC: bytes = b"\x1f\x8b"

    ## BZip2 block compressor signature: 'B' 'Z' 'h'
    BZIP2_MAGIC: bytes = b"BZh"

    ## XZ stream format signature: 0xFD '7' 'z' 'X' 'Z' 0x00
    XZ_MAGIC: bytes = b"\xfd7zXZ\x00"

    ## 7-Zip compressed archive signature: '7' 'z' 0xBC 0xAF 0x27 0x1C
    SEVEN_ZIP_MAGIC: bytes = b"7z\xbc\xaf\x27\x1c"

    ## POSIX TAR ustar archive magic at offset 257: 'ustar'
    TAR_USTAR_MAGIC: bytes = b"ustar"

    ## PNG image signature with DOS/Unix line-break validation sequence
    PNG_MAGIC: bytes = b"\x89PNG\r\n\x1a\n"

    ## JPEG Start-Of-Image (SOI) marker: 0xFF 0xD8 0xFF
    JPEG_SOI: bytes = b"\xff\xd8\xff"

    ## CompuServe GIF 1987 format
    GIF_87A: bytes = b"GIF87a"

    ## CompuServe GIF 1989 format (transparency and animation support)
    GIF_89A: bytes = b"GIF89a"

    ## Windows Bitmap (BMP) signature: 'B' 'M'
    BMP_MAGIC: bytes = b"BM"

    ## Tagged Image File Format (TIFF) Little Endian: 'I' 'I' 0x2A 0x00
    TIFF_LE: bytes = b"II*\x00"

    ## Tagged Image File Format (TIFF) Big Endian: 'M' 'M' 0x00 0x2A
    TIFF_BE: bytes = b"MM\x00*"

    ## Microsoft OLE Compound Document (legacy DOC, XLS, PPT, MSI)
    OLE_COMPOUND_MAGIC: bytes = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

    @classmethod
    def inspect_bytes(cls, header: bytes) -> MagicInspectionResult:
        """
        Analyze an in-memory byte slice (typically initial 4KB of a file).

        This is a pure deterministic classification function with zero side effects.
        """
        ## Check if payload contains zero bytes (empty file)
        if not header:
            return MagicInspectionResult(
                mime_type="application/x-empty",
                category=FileTypeCategory.TEXT,
                description="Empty file (zero bytes)",
                is_executable=False,
                magic_bytes_hex="",
                details={"file_size": 0},
            )

        ## Capture up to first 16 bytes as spaced hex string for forensic receipts
        hex_preview = header[:16].hex(" ")

        ## ---------------------------------------------------------------------
        ## 1. Linux/Unix ELF Binaries
        ## ---------------------------------------------------------------------
        if header.startswith(cls.ELF_MAGIC):
            return cls._parse_elf_header(header, hex_preview)

        ## ---------------------------------------------------------------------
        ## 2. Microsoft Windows PE / DOS Binaries
        ## ---------------------------------------------------------------------
        if header.startswith(cls.DOS_MZ_MAGIC):
            pe_result = cls._parse_pe_header(header, hex_preview)
            if pe_result is not None:
                return pe_result

        ## ---------------------------------------------------------------------
        ## 3. Apple macOS / iOS Mach-O Binaries
        ## ---------------------------------------------------------------------
        macho_result = cls._parse_macho_header(header, hex_preview)
        if macho_result is not None:
            return macho_result

        ## ---------------------------------------------------------------------
        ## 4. WebAssembly (WASM) Modules
        ## ---------------------------------------------------------------------
        if header.startswith(cls.WASM_MAGIC):
            ## Unpack little-endian 32-bit module version from offset 4
            wasm_version = struct.unpack("<I", header[4:8])[0] if len(header) >= 8 else 1
            return MagicInspectionResult(
                mime_type="application/wasm",
                category=FileTypeCategory.EXECUTABLE,
                description="WebAssembly binary module",
                is_executable=True,
                magic_bytes_hex=hex_preview,
                details={"format": "WebAssembly", "version": wasm_version},
            )

        ## ---------------------------------------------------------------------
        ## 5. POSIX Interpreted Scripts (Shebang #!)
        ## ---------------------------------------------------------------------
        if header.startswith(cls.SHEBANG_MAGIC):
            return cls._parse_shebang(header, hex_preview)

        ## ---------------------------------------------------------------------
        ## 6. Adobe PDF Documents
        ## ---------------------------------------------------------------------
        if header.startswith(cls.PDF_MAGIC):
            ## Extract PDF version header string from first line
            first_line = header.split(b"\n", 1)[0].decode("ascii", errors="replace").strip()
            return MagicInspectionResult(
                mime_type="application/pdf",
                category=FileTypeCategory.DOCUMENT,
                description=f"Adobe Portable Document Format ({first_line})",
                is_executable=False,
                magic_bytes_hex=hex_preview,
                details={"version_header": first_line},
            )

        ## ---------------------------------------------------------------------
        ## 7. Compressed Archives and Containers
        ## ---------------------------------------------------------------------
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

        ## Check POSIX ustar tar header signature located at offset 257
        if len(header) >= 262 and header[257:262] == cls.TAR_USTAR_MAGIC:
            return MagicInspectionResult(
                mime_type="application/x-tar",
                category=FileTypeCategory.ARCHIVE,
                description="POSIX TAR archive (ustar format)",
                is_executable=False,
                magic_bytes_hex=hex_preview,
                details={"format": "ustar"},
            )

        ## ---------------------------------------------------------------------
        ## 8. Raster and Vector Images
        ## ---------------------------------------------------------------------
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

        ## ---------------------------------------------------------------------
        ## 9. Microsoft Legacy OLE Compound Documents
        ## ---------------------------------------------------------------------
        if header.startswith(cls.OLE_COMPOUND_MAGIC):
            return MagicInspectionResult(
                mime_type="application/x-ole-storage",
                category=FileTypeCategory.DOCUMENT,
                description="Microsoft OLE Compound Document (legacy DOC/XLS/PPT or MSI)",
                is_executable=False,
                magic_bytes_hex=hex_preview,
                details={"format": "OLECF"},
            )

        ## ---------------------------------------------------------------------
        ## 10. Plaintext and Source Code Heuristics
        ## ---------------------------------------------------------------------
        text_result = cls._inspect_plaintext_heuristics(header, hex_preview)
        if text_result is not None:
            return text_result

        ## ---------------------------------------------------------------------
        ## 11. Unidentified Binary Payload Fallback
        ## ---------------------------------------------------------------------
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
        ## Resolve path to concrete local path
        file_path = Path(path)

        ## Defensive check: Verify file exists and is a regular file
        if not file_path.is_file():
            raise FileNotFoundError(f"Target path does not exist or is not a regular file: {file_path}")

        try:
            ## Read first 4096 bytes using binary mode
            with open(file_path, "rb") as f:
                header = f.read(cls.HEADER_READ_SIZE)
            ## Classify header bytes
            return cls.inspect_bytes(header)
        except PermissionError as pe:
            ## Security boundary: If read permissions are denied, flag as inaccessible
            return MagicInspectionResult(
                mime_type="application/x-inaccessible",
                category=FileTypeCategory.UNKNOWN,
                description=f"Permission denied reading file header: {pe}",
                is_executable=False,
                magic_bytes_hex="",
                details={"error": "PermissionError"},
            )

    ## =========================================================================
    ## LOW-LEVEL FORMAT PARSERS
    ## =========================================================================

    @classmethod
    def _parse_elf_header(cls, header: bytes, hex_preview: str) -> MagicInspectionResult:
        """
        Parse POSIX Executable and Linkable Format (ELF) header fields.
        """
        ## Initialize metadata dictionary
        details: Dict[str, Union[str, int, bool]] = {"format": "ELF"}

        ## Extract bitness from e_ident[4] (EI_CLASS: 1=32-bit, 2=64-bit)
        if len(header) > 4:
            ei_class = header[4]
            if ei_class == 1:
                details["bitness"] = 32
                details["arch_class"] = "ELF32"
            elif ei_class == 2:
                details["bitness"] = 64
                details["arch_class"] = "ELF64"

        ## Extract endianness from e_ident[5] (EI_DATA: 1=little-endian, 2=big-endian)
        endian = "<"  ## Default little-endian
        if len(header) > 5:
            ei_data = header[5]
            if ei_data == 1:
                details["endianness"] = "little-endian"
                endian = "<"
            elif ei_data == 2:
                details["endianness"] = "big-endian"
                endian = ">"

        ## Extract OS/ABI from e_ident[7] (EI_OSABI)
        if len(header) > 7:
            abi_map = {0: "System V", 3: "Linux", 6: "Solaris", 9: "FreeBSD", 97: "ARM"}
            details["os_abi"] = abi_map.get(header[7], f"Unknown (0x{header[7]:02x})")

        ## Extract e_type from offset 16 (uint16)
        if len(header) >= 18:
            e_type = struct.unpack(f"{endian}H", header[16:18])[0]
            type_map = {
                1: "Relocatable Object (.o)",
                2: "Executable Binary",
                3: "Shared Object (.so or PIE executable)",
                4: "Core Dump",
            }
            details["elf_type"] = type_map.get(e_type, f"Unknown ({e_type})")

        ## Compose descriptive architecture string
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
        """
        ## Initialize metadata dictionary
        details: Dict[str, Union[str, int, bool]] = {"format": "PE"}

        ## Check if file is too small to contain e_lfanew pointer (offset 0x3C to 0x40)
        if len(header) < 0x40:
            return MagicInspectionResult(
                mime_type="application/x-dosexec",
                category=FileTypeCategory.EXECUTABLE,
                description="DOS MZ executable or stub",
                is_executable=True,
                magic_bytes_hex=hex_preview,
                details=details,
            )

        ## Unpack 32-bit little-endian e_lfanew offset pointing to NT PE header
        pe_offset = struct.unpack("<I", header[0x3C:0x40])[0]
        details["pe_offset"] = pe_offset

        ## Verify PE signature 'PE\0\0' at the unpacked offset
        if len(header) >= pe_offset + 4 and header[pe_offset:pe_offset + 4] == b"PE\x00\x00":
            details["has_pe_signature"] = True

            ## Unpack machine architecture type at pe_offset + 4 (uint16)
            if len(header) >= pe_offset + 6:
                machine_type = struct.unpack("<H", header[pe_offset + 4:pe_offset + 6])[0]
                machine_map = {
                    0x014C: "Intel x86 (32-bit)",
                    0x8664: "AMD64 / x86-64 (64-bit)",
                    0x0200: "Intel Itanium (IA-64)",
                    0xAA64: "ARM64 Little-Endian",
                }
                details["machine"] = machine_map.get(machine_type, f"Unknown (0x{machine_type:04X})")

            ## Unpack characteristics flags at pe_offset + 22 (uint16)
            ## 0x2000 = IMAGE_FILE_DLL, 0x0002 = IMAGE_FILE_EXECUTABLE_IMAGE
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

        ## Fallback: Beginning with MZ but lacking PE header is legacy DOS executable
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
        """
        ## 64-bit Mach-O Little-Endian (Standard Apple Silicon & Intel macOS)
        if header.startswith(cls.MACHO_64_LE):
            return MagicInspectionResult(
                mime_type="application/x-mach-binary",
                category=FileTypeCategory.EXECUTABLE,
                description="Apple Mach-O 64-bit binary (little-endian)",
                is_executable=True,
                magic_bytes_hex=hex_preview,
                details={"format": "Mach-O", "bitness": 64, "endianness": "little-endian"},
            )

        ## 64-bit Mach-O Big-Endian
        if header.startswith(cls.MACHO_64_BE):
            return MagicInspectionResult(
                mime_type="application/x-mach-binary",
                category=FileTypeCategory.EXECUTABLE,
                description="Apple Mach-O 64-bit binary (big-endian)",
                is_executable=True,
                magic_bytes_hex=hex_preview,
                details={"format": "Mach-O", "bitness": 64, "endianness": "big-endian"},
            )

        ## 32-bit Mach-O Little-Endian
        if header.startswith(cls.MACHO_32_LE):
            return MagicInspectionResult(
                mime_type="application/x-mach-binary",
                category=FileTypeCategory.EXECUTABLE,
                description="Apple Mach-O 32-bit binary (little-endian)",
                is_executable=True,
                magic_bytes_hex=hex_preview,
                details={"format": "Mach-O", "bitness": 32, "endianness": "little-endian"},
            )

        ## 32-bit Mach-O Big-Endian
        if header.startswith(cls.MACHO_32_BE):
            return MagicInspectionResult(
                mime_type="application/x-mach-binary",
                category=FileTypeCategory.EXECUTABLE,
                description="Apple Mach-O 32-bit binary (big-endian)",
                is_executable=True,
                magic_bytes_hex=hex_preview,
                details={"format": "Mach-O", "bitness": 32, "endianness": "big-endian"},
            )

        ## Fat Universal Binary (0xCAFEBABE) - differentiate from Java class files
        if header.startswith(cls.MACHO_FAT_BE):
            if len(header) >= 8:
                ## Java class files store major_version (uint16) at bytes 6-8
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

            ## Otherwise confirmed Apple Mach-O Universal Fat Binary
            return MagicInspectionResult(
                mime_type="application/x-mach-binary",
                category=FileTypeCategory.EXECUTABLE,
                description="Apple Mach-O Universal Fat Binary (multi-architecture)",
                is_executable=True,
                magic_bytes_hex=hex_preview,
                details={"format": "Mach-O Fat", "endianness": "big-endian"},
            )

        ## Little-endian Fat Universal Binary
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
        """
        ## Extract the entire first line up to newline
        first_line = header.split(b"\n", 1)[0].decode("utf-8", errors="replace").strip()

        ## Strip the leading '#!' characters
        interpreter = first_line[2:].strip()

        ## Classify script category based on interpreter path keywords
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
        """
        details: Dict[str, Union[str, int, bool]] = {"format": "ZIP"}

        ## Inspect header chunk for Open Packaging Conventions XML signatures
        if b"[Content_Types].xml" in header:
            ## Word Document marker
            if b"word/" in header:
                return MagicInspectionResult(
                    mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    category=FileTypeCategory.DOCUMENT,
                    description="Microsoft Word Document (DOCX)",
                    is_executable=False,
                    magic_bytes_hex=hex_preview,
                    details={"format": "DOCX", "container": "ZIP"},
                )
            ## Excel Spreadsheet marker
            if b"xl/" in header:
                return MagicInspectionResult(
                    mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    category=FileTypeCategory.DOCUMENT,
                    description="Microsoft Excel Spreadsheet (XLSX)",
                    is_executable=False,
                    magic_bytes_hex=hex_preview,
                    details={"format": "XLSX", "container": "ZIP"},
                )
            ## PowerPoint Presentation marker
            if b"ppt/" in header:
                return MagicInspectionResult(
                    mime_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
                    category=FileTypeCategory.DOCUMENT,
                    description="Microsoft PowerPoint Presentation (PPTX)",
                    is_executable=False,
                    magic_bytes_hex=hex_preview,
                    details={"format": "PPTX", "container": "ZIP"},
                )

        ## Java Archive manifest signature
        if b"META-INF/MANIFEST.MF" in header:
            return MagicInspectionResult(
                mime_type="application/java-archive",
                category=FileTypeCategory.ARCHIVE,
                description="Java Archive (JAR / APK package)",
                is_executable=True,
                magic_bytes_hex=hex_preview,
                details={"format": "JAR", "container": "ZIP"},
            )

        ## Standard generic ZIP archive
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
        """
        ## If null byte exists in initial chunk, it is almost certainly a binary format
        if b"\x00" in header:
            return None

        ## Attempt UTF-8 decode
        try:
            decoded = header.decode("utf-8")
        except UnicodeDecodeError:
            ## Fallback to Latin-1
            try:
                decoded = header.decode("latin-1")
            except UnicodeDecodeError:
                return None

        stripped = decoded.strip()
        lower_stripped = stripped.lower()

        ## Windows Batch script detection
        if lower_stripped.startswith("@echo") or lower_stripped.startswith("rem "):
            return MagicInspectionResult(
                mime_type="text/x-msdos-batch",
                category=FileTypeCategory.SCRIPT,
                description="Windows Batch / CMD script",
                is_executable=True,
                magic_bytes_hex=hex_preview,
                details={"format": "Batch"},
            )

        ## HTML hypertext detection
        if stripped.startswith("<!DOCTYPE html") or stripped.startswith("<html"):
            return MagicInspectionResult(
                mime_type="text/html",
                category=FileTypeCategory.DOCUMENT,
                description="HTML hypertext document",
                is_executable=False,
                magic_bytes_hex=hex_preview,
                details={"format": "HTML"},
            )

        ## XML and SVG vector graphics detection
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

        ## JSON structured data detection
        if (stripped.startswith("{") and "}" in stripped) or (stripped.startswith("[") and "]" in stripped):
            return MagicInspectionResult(
                mime_type="application/json",
                category=FileTypeCategory.TEXT,
                description="JSON structured data",
                is_executable=False,
                magic_bytes_hex=hex_preview,
                details={"format": "JSON"},
            )

        ## Generic UTF-8 / ASCII plaintext document
        return MagicInspectionResult(
            mime_type="text/plain",
            category=FileTypeCategory.TEXT,
            description="Plain text document",
            is_executable=False,
            magic_bytes_hex=hex_preview,
            details={"sample_chars": len(stripped)},
        )
