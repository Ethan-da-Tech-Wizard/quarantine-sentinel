"""
Quarantine Sentinel: Zero-Dependency Offline File Security & Automated Quarantine System.

This package provides a standalone, POSIX-compliant, pure-Python security tool designed to
inspect untrusted files, detect extension spoofing and binary masquerading, compute multi-hash
cryptographic fingerprints, and isolate suspicious payloads into an immutable quarantine vault
with permission stripping and tamper-evident audit receipts.

Core Tenets:
1. Zero External Dependencies: Built strictly upon the Python Standard Library (os, sys, hashlib,
   pathlib, stat, json) to eliminate supply chain vulnerabilities and ensure high-assurance deployment
   in air-gapped or restricted infrastructure.
2. Defensive Programming: All file I/O operations employ streaming chunk buffers, atomic transitions,
   and strict permission lockdowns (POSIX chmod 000) to neutralize weaponized binaries.
3. Complete Auditability: Every quarantine action emits a cryptographically hashed, immutable JSON
   audit receipt documenting detection heuristics, original inode metadata, and hash digests.
"""

from sentinel.magic import (
    MagicInspector,
    MagicInspectionResult,
    FileTypeCategory,
)
from sentinel.hasher import (
    CryptoHasher,
    HashManifest,
)
from sentinel.rules import (
    ThreatEngine,
    ThreatReport,
    Finding,
    RiskLevel,
)
from sentinel.vault import (
    QuarantineVault,
    QuarantineReceipt,
)

__version__ = "1.0.0"
__author__ = "Ethan Kilmer"
__license__ = "MIT"

__all__ = [
    "MagicInspector",
    "MagicInspectionResult",
    "FileTypeCategory",
    "CryptoHasher",
    "HashManifest",
    "ThreatEngine",
    "ThreatReport",
    "Finding",
    "RiskLevel",
    "QuarantineVault",
    "QuarantineReceipt",
]
