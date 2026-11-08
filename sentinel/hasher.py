"""
Program: Quarantine Sentinel - Streaming Cryptographic Multi-Hasher
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Compute simultaneous SHA-256, SHA-512, and MD5 cryptographic digests using bounded 64KB streaming buffers to prevent memory exhaustion and establish immutable file integrity.
"""

from __future__ import annotations

## Standard library cryptographic and filesystem utilities
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Union


## ----------------------------------------------------------------------------
## Data Model: HashManifest
## ----------------------------------------------------------------------------

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
    ## Cryptographic digest strings
    sha256: str
    sha512: str
    md5: str
    file_size_bytes: int

    @property
    def formatted_size(self) -> str:
        """
        Return human-readable file size with binary prefixes (KiB, MiB, GiB).
        """
        ## Convert integer bytes to floating point for gradual division
        size = float(self.file_size_bytes)

        ## Iterate through binary scale units
        for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
            ## Check if size fits within current 1024 scale boundary
            if size < 1024.0:
                ## Format with 2 decimal places unless working with raw bytes
                return f"{size:.2f} {unit}" if unit != "B" else f"{int(size)} B"
            ## Scale down to next magnitude
            size /= 1024.0

        ## Fallback for extremely large enterprise archives
        return f"{size:.2f} PiB"

    def to_dict(self) -> Dict[str, Union[str, int]]:
        """Serialize manifest to dictionary for JSON audit receipts."""
        ## Return plain dictionary suitable for json.dump()
        return {
            "sha256": self.sha256,
            "sha512": self.sha512,
            "md5": self.md5,
            "size_bytes": self.file_size_bytes,
            "formatted_size": self.formatted_size,
        }


## ----------------------------------------------------------------------------
## Core Engine: CryptoHasher
## ----------------------------------------------------------------------------

class CryptoHasher:
    """
    Memory-efficient streaming cryptographic hash generator.

    Maintains zero pip dependencies, relying strictly on standard library `hashlib`
    which binds directly to OpenSSL C implementations for maximum throughput.
    """

    ## 64 KiB (65,536 bytes) chunk buffer size.
    ## Aligns cleanly with standard OS virtual memory page sizes (4 KiB or 64 KiB)
    ## and optimizes L1/L2 CPU cache utilization without exhausting physical RAM.
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
        ## Normalize input path to a standard Path object
        file_path = Path(path)

        ## Defensive check: Verify file existence before attempting to open
        if not file_path.exists():
            raise FileNotFoundError(f"File not found for cryptographic hashing: {file_path}")

        ## Defensive check: Prevent hashing directory nodes
        if file_path.is_dir():
            raise IsADirectoryError(f"Cannot hash a directory: {file_path}")

        ## Initialize all three hash accumulators simultaneously
        ## SHA-256: FIPS standard for tamper-proof cryptographic verification
        hasher_sha256 = hashlib.sha256()

        ## SHA-512: 512-bit digest with high performance on 64-bit architectures
        hasher_sha512 = hashlib.sha512()

        ## MD5: Retained for threat intelligence correlation against legacy IoC feeds
        hasher_md5 = hashlib.md5()

        ## Byte accumulator tracking the exact stream length
        total_bytes = 0

        ## Open target file in raw binary mode ('rb') to avoid OS newline transformations
        with open(file_path, "rb") as f:
            ## Stream file sequentially in fixed-size memory chunks
            while True:
                ## Read next slice into bounded memory buffer (max 64 KiB)
                chunk = f.read(cls.CHUNK_SIZE)

                ## Check for End-Of-File (EOF) marker
                if not chunk:
                    break

                ## Increment total byte count by slice length
                total_bytes += len(chunk)

                ## Feed chunk simultaneously to all three hashing engines in-place
                hasher_sha256.update(chunk)
                hasher_sha512.update(chunk)
                hasher_md5.update(chunk)

        ## Finalize digests into standardized lowercase hexadecimal strings
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
        ## Feed raw byte slice directly into hashlib algorithms
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

        Uses constant-time comparison (`secrets.compare_digest` / `hmac.compare_digest`)
        to prevent side-channel timing attacks when validating cryptographic proofs.
        """
        ## Import hmac for timing-attack-resistant constant-time string comparison
        import hmac

        ## Compute current disk hash via bounded streaming
        manifest = cls.hash_file(path)

        ## Perform constant-time hex comparison to eliminate timing side-channel leakage
        return hmac.compare_digest(manifest.sha256.lower(), expected_sha256.lower())
