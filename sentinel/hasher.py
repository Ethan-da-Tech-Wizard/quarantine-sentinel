"""
Streaming Multi-Algorithm Cryptographic Hasher.

Educational Overview:
---------------------
In defensive security operations, calculating cryptographic digests (hashes) serves two primary roles:
1. Integrity Verification: Demonstrating beyond mathematical doubt that an quarantined file has not
   been altered, corrupted, or tampered with while in storage.
2. Threat Intelligence Correlation: Cross-referencing samples against local and global indicators of
   compromise (IoCs).

Why Multi-Hash Streaming?
- SHA-256: The contemporary industry-standard cryptographic hash function (FIPS PUB 180-4). Provides
  256-bit collision resistance and is immune to practical collision attacks.
- SHA-512: 512-bit digest offering higher margin of security against quantum and hyper-scale pre-image
  attacks, while running exceptionally fast on 64-bit CPU architectures (due to native 64-bit words).
- MD5: Computationally broken for collision resistance (RFC 1321), yet universally retained in digital
  forensics and incident response (DFIR) because historical malware threat feeds (e.g. VirusTotal,
  MISP, legacy databases) index hundreds of millions of samples by MD5.

Defensive Architecture: Single-Pass O(1) Memory Streaming:
Loading entire files into RAM via `f.read()` is a severe vulnerability:
- A malicious actor can drop a 10 GB sparse file or archive payload designed to trigger Linux OOM Killer
  (Out-Of-Memory) or freeze server environments.
- By streaming files in fixed-size 64 KiB chunks (`65,536` bytes), our memory footprint remains strictly
  bounded at ~64 KiB regardless of whether the target file is 10 bytes or 100 gigabytes.
- All hash algorithms are updated simultaneously in the same single disk read pass, minimizing I/O bus contention.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Union


@dataclass(frozen=True)
class HashManifest:
    """
    Cryptographic fingerprint manifest capturing simultaneous digests of a file.

    Attributes:
        sha256: Hex-encoded SHA-256 digest (64 lowercase hex characters).
        sha512: Hex-encoded SHA-512 digest (128 lowercase hex characters).
        md5: Hex-encoded MD5 digest (32 lowercase hex characters).
        file_size_bytes: Exact byte count of the file at time of hashing.
    """
    sha256: str
    sha512: str
    md5: str
    file_size_bytes: int

    @property
    def formatted_size(self) -> str:
        """
        Return human-readable file size with binary prefixes (KiB, MiB, GiB).
        """
        size = float(self.file_size_bytes)
        for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
            if size < 1024.0:
                return f"{size:.2f} {unit}" if unit != "B" else f"{int(size)} B"
            size /= 1024.0
        return f"{size:.2f} PiB"

    def to_dict(self) -> Dict[str, Union[str, int]]:
        """Serialize manifest to dictionary for JSON audit receipts."""
        return {
            "sha256": self.sha256,
            "sha512": self.sha512,
            "md5": self.md5,
            "size_bytes": self.file_size_bytes,
            "formatted_size": self.formatted_size,
        }


class CryptoHasher:
    """
    Memory-efficient streaming cryptographic hash generator.

    Maintains zero pip dependencies, relying strictly on standard library `hashlib`
    which binds directly to OpenSSL C implementations for maximum throughput.
    """

    # 64 KiB (65536 bytes) chunk buffer size.
    # Aligns cleanly with standard OS virtual memory page sizes (4 KiB or 64 KiB)
    # and optimizes L1/L2 CPU cache utilization without exhausting physical RAM.
    CHUNK_SIZE: int = 65536

    @classmethod
    def hash_file(cls, path: Union[str, Path]) -> HashManifest:
        """
        Stream a file from disk and compute SHA-256, SHA-512, and MD5 simultaneously.

        Args:
            path: Target file path on local filesystem.

        Returns:
            HashManifest containing all calculated digests and file size.

        Raises:
            FileNotFoundError: If the target path does not exist.
            PermissionError: If read permissions are withheld by the OS.
            IsADirectoryError: If target path points to a directory rather than a file.
        """
        file_path = Path(path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found for cryptographic hashing: {file_path}")
        if file_path.is_dir():
            raise IsADirectoryError(f"Cannot hash a directory: {file_path}")

        # Initialize hash accumulators simultaneously
        hasher_sha256 = hashlib.sha256()
        hasher_sha512 = hashlib.sha512()
        hasher_md5 = hashlib.md5()

        total_bytes = 0

        # Open in binary mode ('rb') to guarantee byte-exact raw reading without OS newline translation
        with open(file_path, "rb") as f:
            while True:
                # Read next slice into buffer
                chunk = f.read(cls.CHUNK_SIZE)
                if not chunk:
                    # End of file reached (EOF)
                    break

                # Increment byte counter
                total_bytes += len(chunk)

                # Feed current chunk to all three hashing engines in-place
                hasher_sha256.update(chunk)
                hasher_sha512.update(chunk)
                hasher_md5.update(chunk)

        # Finalize digests into hex strings
        return HashManifest(
            sha256=hasher_sha256.hexdigest(),
            sha512=hasher_sha512.hexdigest(),
            md5=hasher_md5.hexdigest(),
            file_size_bytes=total_bytes,
        )

    @classmethod
    def hash_bytes(cls, data: bytes) -> HashManifest:
        """
        Compute cryptographic digests for an in-memory byte sequence.

        Convenient helper for unit testing and header verification.
        """
        return HashManifest(
            sha256=hashlib.sha256(data).hexdigest(),
            sha512=hashlib.sha512(data).hexdigest(),
            md5=hashlib.md5(data).hexdigest(),
            file_size_bytes=len(data),
        )

    @classmethod
    def verify_integrity(cls, path: Union[str, Path], expected_sha256: str) -> bool:
        """
        Verify that a file on disk matches an expected SHA-256 digest.

        Uses constant-time comparison (`secrets.compare_digest`) via `hmac.compare_digest`
        to prevent side-channel timing attacks when validating cryptographic proofs.
        """
        import hmac

        manifest = cls.hash_file(path)
        # Constant time hex string comparison prevents timing leak attacks
        return hmac.compare_digest(manifest.sha256.lower(), expected_sha256.lower())
