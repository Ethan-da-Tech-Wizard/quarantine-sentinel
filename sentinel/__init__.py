# Program: quarantine-sentinel - __init__.py
# Programmer: Ethan-da-Tech-Wizard (written with Claude, an AI assistant)
# Last Modified: 2026-11-18
# Purpose: Package entry point: re-exports the public classes (inspector, hasher, threat engine, vault) and defines version, author and license metadata.

"""
Provide the top-level package interface, version metadata, and clean public symbol exports for Quarantine Sentinel.
"""

## ----------------------------------------------------------------------------
## Core Component Imports
## ----------------------------------------------------------------------------

## Import the binary magic inspection engine and supporting category enums
from sentinel.magic import (
    MagicInspector,
    MagicInspectionResult,
    FileTypeCategory,
)

## Import the streaming multi-algorithm cryptographic hasher and manifest dataclass
from sentinel.hasher import (
    CryptoHasher,
    HashManifest,
)

## Import threat detection heuristics, severity enums, and reporting structures
from sentinel.rules import (
    ThreatEngine,
    ThreatReport,
    Finding,
    RiskLevel,
)

## Import the atomic quarantine vault manager and cryptographic audit receipt
from sentinel.vault import (
    QuarantineVault,
    QuarantineReceipt,
)

## ----------------------------------------------------------------------------
## Package Metadata
## ----------------------------------------------------------------------------

## Semantic version string for Quarantine Sentinel
__version__ = "1.0.0"

## Author and copyright ownership
__author__ = "Ethan Kilmer"

## Software licensing under MIT open-source terms
__license__ = "MIT"

## ----------------------------------------------------------------------------
## Public API Surface (__all__)
## ----------------------------------------------------------------------------

## Define explicitly exported symbols when importing via `from sentinel import *`
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
