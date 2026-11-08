"""
Program: Quarantine Sentinel - Atomic Quarantine Vault & Receipt Issuer
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Safely isolate suspicious payloads into an access-restricted vault, neutralize execution vectors via POSIX chmod 000, issue cryptographically verifiable JSON audit receipts, and support tamper-evident restoration.
"""

from __future__ import annotations

## Standard date, hash, filesystem, and serialization utilities
import datetime
import hashlib
import json
import os
import shutil
import stat
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

## Import cryptographic hashing and threat analysis components
from sentinel.hasher import CryptoHasher, HashManifest
from sentinel.magic import MagicInspectionResult
from sentinel.rules import Finding, RiskLevel, ThreatEngine, ThreatReport


## ----------------------------------------------------------------------------
## Forensic Audit Receipt Data Model
## ----------------------------------------------------------------------------

@dataclass(frozen=True)
class QuarantineReceipt:
    """
    Immutable forensic receipt certifying the isolation of a suspicious file.

    Attributes:
        quarantine_id: Globally unique record identifier (e.g., 'Q-20261108-120000-a1b2c3d4').
        quarantined_at_utc: ISO-8601 formatted UTC timestamp of the isolation event.
        original_path: Full absolute path where the file was discovered.
        original_filename: Original filename on disk.
        original_mode_octal: Filesystem permission bits prior to quarantine (e.g., '0o755').
        original_uid: User ID of file owner.
        original_gid: Group ID of file owner.
        file_size_bytes: Total byte size of the payload.
        hashes: Cryptographic hash manifest (SHA-256, SHA-512, MD5).
        magic: Binary format inspection result.
        threat_report: Detailed findings and risk evaluation.
        status: Current vault status ('QUARANTINED', 'RESTORED', 'PURGED').
        receipt_digest: SHA-256 digest of the receipt payload itself for tamper-evidence.
        restored_at_utc: ISO-8601 UTC timestamp if file has been restored.
        restored_path: Path where file was restored.
    """
    ## Unique quarantine record identifier
    quarantine_id: str

    ## Timestamp recording exact isolation moment in UTC
    quarantined_at_utc: str

    ## Pre-quarantine location
    original_path: str

    ## Original filename
    original_filename: str

    ## Pre-quarantine octal permission bits
    original_mode_octal: str

    ## POSIX user and group owner IDs
    original_uid: int
    original_gid: int

    ## Total payload size in bytes
    file_size_bytes: int

    ## Multi-algorithm cryptographic hash digests
    hashes: Dict[str, Union[str, int]]

    ## Binary magic analysis details
    magic: Dict[str, Union[str, bool, dict]]

    ## Threat engine evaluation and findings
    threat_report: Dict[str, Union[str, int, list]]

    ## Vault status lifecycle indicator
    status: str

    ## Self-referential cryptographic digest verifying receipt authenticity
    receipt_digest: str = ""

    ## Restoration metadata
    restored_at_utc: Optional[str] = None
    restored_path: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert receipt into dictionary representation for JSON persistence."""
        result = {
            "quarantine_id": self.quarantine_id,
            "quarantined_at_utc": self.quarantined_at_utc,
            "original_path": self.original_path,
            "original_filename": self.original_filename,
            "original_mode_octal": self.original_mode_octal,
            "original_uid": self.original_uid,
            "original_gid": self.original_gid,
            "file_size_bytes": self.file_size_bytes,
            "hashes": self.hashes,
            "magic": self.magic,
            "threat_report": self.threat_report,
            "status": self.status,
            "receipt_digest": self.receipt_digest,
        }
        ## Conditionally append restoration fields if present
        if self.restored_at_utc:
            result["restored_at_utc"] = self.restored_at_utc
        if self.restored_path:
            result["restored_path"] = self.restored_path
        return result


## ----------------------------------------------------------------------------
## Quarantine Vault Storage Manager
## ----------------------------------------------------------------------------

class QuarantineVault:
    """
    Isolated storage vault managing file quarantine, permission lockdown, and verification.
    """

    ## Default storage directory located in user's home directory
    DEFAULT_VAULT_DIR: Path = Path.home() / ".quarantine_vault"

    def __init__(self, vault_dir: Optional[Union[str, Path]] = None) -> None:
        """
        Initialize the quarantine vault.

        Args:
            vault_dir: Path to directory housing quarantined payloads and audit receipts.
                       Defaults to `~/.quarantine_vault`.
        """
        ## Resolve vault root directory
        self.vault_dir = Path(vault_dir).resolve() if vault_dir else self.DEFAULT_VAULT_DIR

        ## Directory housing isolated payload items
        self.payloads_dir = self.vault_dir / "quarantined"

        ## Master index file recording all items
        self.index_file = self.vault_dir / "index.json"

        ## Establish vault directories with owner-only (0o700) access
        self._ensure_secure_vault_hierarchy()

    def _ensure_secure_vault_hierarchy(self) -> None:
        """
        Create vault directories with POSIX 0o700 (rwx------) permissions.
        """
        ## Create root vault directory if non-existent
        self.vault_dir.mkdir(parents=True, exist_ok=True)

        ## Enforce owner-only permissions on vault root (0o700)
        try:
            os.chmod(self.vault_dir, 0o700)
        except OSError:
            pass

        ## Create payloads subdirectory
        self.payloads_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.payloads_dir, 0o700)
        except OSError:
            pass

        ## Initialize empty index file if not present
        if not self.index_file.exists():
            self._write_index({})

    def _read_index(self) -> Dict[str, dict]:
        """Read and parse the vault index JSON."""
        ## Return empty dictionary if index file does not exist
        if not self.index_file.exists():
            return {}
        try:
            with open(self.index_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    def _write_index(self, index_data: Dict[str, dict]) -> None:
        """Write the vault index JSON atomically using a temporary swap file."""
        ## Write to temporary swap file first
        tmp_file = self.vault_dir / "index.json.tmp"
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(index_data, f, indent=2, sort_keys=True)
        ## Atomically replace index file to prevent partial write corruption
        os.replace(tmp_file, self.index_file)

    def quarantine(
        self,
        source_path: Union[str, Path],
        report: Optional[ThreatReport] = None,
        force: bool = False,
    ) -> QuarantineReceipt:
        """
        Safely isolate a suspicious file into the quarantine vault.

        Step-by-step Defensive Protocol:
        1. Verify source file exists and is a regular file.
        2. Run threat analysis if not already supplied; abort if file is SAFE (unless force=True).
        3. Capture source filesystem stat metadata (mode, inode, uid, gid, mtime).
        4. Generate unique Quarantine ID (`Q-YYYYMMDD-HHMMSS-<token>`).
        5. Create dedicated isolation directory under `<vault_dir>/quarantined/<quarantine_id>/`.
        6. Atomically relocate the file (`os.replace` or copy-then-unlink).
        7. Strip ALL permissions on the quarantined payload: `chmod 0000` (neutralization).
        8. Write immutable audit `receipt.json` inside the quarantine folder.
        9. Update vault index.
        """
        ## Resolve absolute path of source file
        src = Path(source_path).resolve()

        ## Defensive verification: Ensure file exists
        if not src.exists():
            raise FileNotFoundError(f"Source file to quarantine does not exist: {src}")

        ## Defensive verification: Prevent attempting to quarantine directory nodes
        if not src.is_file():
            raise ValueError(f"Source path is not a regular file: {src}")

        ## Step 2: Compute ThreatReport if not supplied by caller
        if report is None:
            report = ThreatEngine.analyze_file(src)

        ## Skip quarantine if file is completely benign unless force flag is supplied
        if not report.is_suspicious and not force:
            raise ValueError(
                f"File '{src.name}' is assessed as SAFE (risk score: {report.risk_score}). "
                "Quarantine skipped. Use force=True to override."
            )

        ## Step 3: Capture filesystem metadata
        src_stat = src.stat()
        original_mode_octal = oct(stat.S_IMODE(src_stat.st_mode))
        original_uid = src_stat.st_uid
        original_gid = src_stat.st_gid
        file_size = src_stat.st_size
        utc_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        ## Step 4: Generate unique Quarantine ID: Q-YYYYMMDD-HHMMSS-<first 8 hex chars of SHA-256>
        date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
        short_hash = report.hash_manifest.sha256[:8]
        quarantine_id = f"Q-{date_str}-{short_hash}"

        ## Step 5: Create isolated directory for quarantined item
        item_dir = self.payloads_dir / quarantine_id
        item_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(item_dir, 0o700)

        ## Destination payload path inside vault
        payload_path = item_dir / "payload.bin"

        ## Step 6: Atomic relocation
        try:
            ## Fast atomic move on same filesystem
            os.replace(src, payload_path)
        except OSError:
            ## Cross-filesystem fallback: copy, verify cryptographic integrity, then remove source
            shutil.copy2(src, payload_path)
            CryptoHasher.verify_integrity(payload_path, report.hash_manifest.sha256)
            src.unlink()

        ## Step 7: Neutralization - Strip all POSIX permissions (chmod 0000)
        ## Neutralizes execution: no user, group, or process can run or read it without explicit chmod
        os.chmod(payload_path, 0o000)

        ## Step 8: Build and issue cryptographic receipt
        receipt_data_without_digest = {
            "quarantine_id": quarantine_id,
            "quarantined_at_utc": utc_timestamp,
            "original_path": str(src),
            "original_filename": src.name,
            "original_mode_octal": original_mode_octal,
            "original_uid": original_uid,
            "original_gid": original_gid,
            "file_size_bytes": file_size,
            "hashes": report.hash_manifest.to_dict(),
            "magic": {
                "mime_type": report.magic_result.mime_type,
                "category": report.magic_result.category.value,
                "description": report.magic_result.description,
                "is_executable": report.magic_result.is_executable,
                "magic_bytes_hex": report.magic_result.magic_bytes_hex,
                "details": report.magic_result.details,
            },
            "threat_report": {
                "risk_score": report.risk_score,
                "risk_level": report.risk_level.value,
                "findings": [f.to_dict() for f in report.findings],
            },
            "status": "QUARANTINED",
        }

        ## Calculate cryptographic digest of receipt for self-verifying tamper resistance
        receipt_json_canonical = json.dumps(receipt_data_without_digest, sort_keys=True)
        receipt_digest = hashlib.sha256(receipt_json_canonical.encode("utf-8")).hexdigest()

        receipt = QuarantineReceipt(
            quarantine_id=quarantine_id,
            quarantined_at_utc=utc_timestamp,
            original_path=str(src),
            original_filename=src.name,
            original_mode_octal=original_mode_octal,
            original_uid=original_uid,
            original_gid=original_gid,
            file_size_bytes=file_size,
            hashes=report.hash_manifest.to_dict(),
            magic=receipt_data_without_digest["magic"],
            threat_report=receipt_data_without_digest["threat_report"],
            status="QUARANTINED",
            receipt_digest=receipt_digest,
        )

        ## Write receipt file to disk
        receipt_file = item_dir / "receipt.json"
        with open(receipt_file, "w", encoding="utf-8") as f:
            json.dump(receipt.to_dict(), f, indent=2, sort_keys=True)

        ## Enforce read-only permissions on receipt file (0o400)
        os.chmod(receipt_file, 0o400)

        ## Step 9: Update vault index
        index = self._read_index()
        index[quarantine_id] = {
            "quarantine_id": quarantine_id,
            "original_path": str(src),
            "original_filename": src.name,
            "quarantined_at_utc": utc_timestamp,
            "sha256": report.hash_manifest.sha256,
            "risk_score": report.risk_score,
            "risk_level": report.risk_level.value,
            "status": "QUARANTINED",
        }
        self._write_index(index)

        return receipt

    def get_receipt(self, quarantine_id: str) -> QuarantineReceipt:
        """
        Retrieve and validate a quarantine receipt by its ID.
        """
        receipt_file = self.payloads_dir / quarantine_id / "receipt.json"
        if not receipt_file.exists():
            raise KeyError(f"Quarantine receipt not found for ID: {quarantine_id}")

        with open(receipt_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        return QuarantineReceipt(**data)

    def list_receipts(self) -> List[Dict[str, Union[str, int]]]:
        """
        List all indexed quarantine records sorted by timestamp descending.
        """
        index = self._read_index()
        records = list(index.values())
        records.sort(key=lambda r: r.get("quarantined_at_utc", ""), reverse=True)
        return records

    def verify_vault_integrity(self) -> List[Dict[str, Union[str, bool]]]:
        """
        Audit the entire vault for tampering, corruption, or missing payloads.

        Forensic Verification Process:
        1. Enumerate all indexed quarantine records.
        2. Verify receipt JSON matches its internal receipt_digest.
        3. Temporarily read-enable `payload.bin` (0o400) to compute current SHA-256.
        4. Re-lock `payload.bin` back to neutralized mode (0o000).
        5. Verify computed SHA-256 matches the recorded receipt digest.
        """
        results: List[Dict[str, Union[str, bool]]] = []
        index = self._read_index()

        ## Audit each registered record
        for qid, entry in index.items():
            item_dir = self.payloads_dir / qid
            receipt_file = item_dir / "receipt.json"
            payload_file = item_dir / "payload.bin"

            status = {
                "quarantine_id": qid,
                "status": entry.get("status", "UNKNOWN"),
                "receipt_valid": False,
                "payload_exists": payload_file.exists(),
                "payload_hash_valid": False,
                "error": None,
            }

            ## Check if receipt file is missing
            if not receipt_file.exists():
                status["error"] = "Missing receipt.json"
                results.append(status)
                continue

            try:
                receipt = self.get_receipt(qid)

                ## Verify receipt self-digest
                receipt_dict = receipt.to_dict()
                recorded_digest = receipt_dict.pop("receipt_digest", "")
                calc_digest = hashlib.sha256(json.dumps(receipt_dict, sort_keys=True).encode("utf-8")).hexdigest()
                status["receipt_valid"] = (recorded_digest == calc_digest)

                ## If already restored, payload is not expected to remain in vault
                if receipt.status == "RESTORED":
                    status["payload_hash_valid"] = True
                    results.append(status)
                    continue

                ## Verify payload exists in vault
                if not payload_file.exists():
                    status["error"] = "Payload file missing from vault"
                    results.append(status)
                    continue

                ## Temporarily enable read mode (0o400) to compute current SHA-256
                os.chmod(payload_file, 0o400)
                try:
                    current_manifest = CryptoHasher.hash_file(payload_file)
                    expected_sha256 = receipt.hashes["sha256"]
                    status["payload_hash_valid"] = (current_manifest.sha256 == expected_sha256)
                finally:
                    ## Defensive guarantee: Always return payload to neutralized mode (0o000)
                    os.chmod(payload_file, 0o000)

            except Exception as ex:
                status["error"] = str(ex)

            results.append(status)

        return results

    def restore(
        self,
        quarantine_id: str,
        destination_path: Optional[Union[str, Path]] = None,
    ) -> Path:
        """
        Safely restore a quarantined file back to the filesystem.

        Defensive Verification Steps:
        1. Fetch receipt and verify status is 'QUARANTINED'.
        2. Temporarily set read permissions on `payload.bin` (0o400).
        3. Compute SHA-256 and confirm zero tampering occurred in vault storage.
        4. Determine restoration destination (default: original_path recorded in receipt).
        5. Atomically move/copy payload to destination.
        6. Restore original POSIX permission bits (st_mode) recorded in receipt.
        7. Update receipt status and vault index to 'RESTORED'.
        """
        item_dir = self.payloads_dir / quarantine_id
        payload_file = item_dir / "payload.bin"
        receipt = self.get_receipt(quarantine_id)

        ## Verify item has not already been restored
        if receipt.status == "RESTORED":
            raise ValueError(f"Payload '{quarantine_id}' has already been restored.")

        ## Verify payload exists on disk
        if not payload_file.exists():
            raise FileNotFoundError(f"Quarantined payload file missing: {payload_file}")

        ## Step 2 & 3: Integrity verification
        os.chmod(payload_file, 0o400)
        try:
            current_manifest = CryptoHasher.hash_file(payload_file)
            expected_sha256 = receipt.hashes["sha256"]
            if current_manifest.sha256 != expected_sha256:
                raise ValueError(
                    f"CRITICAL: Integrity failure! Quarantined payload hash {current_manifest.sha256} "
                    f"does not match recorded receipt hash {expected_sha256}. Restoration aborted."
                )
        except Exception:
            ## Restore permissions to 0o000 in case of failure
            os.chmod(payload_file, 0o000)
            raise

        ## Step 4: Resolve destination path
        if destination_path:
            dest = Path(destination_path).resolve()
            if dest.is_dir():
                dest = dest / receipt.original_filename
        else:
            dest = Path(receipt.original_path).resolve()

        ## Ensure parent directory exists
        dest.parent.mkdir(parents=True, exist_ok=True)

        ## Step 5: Move payload to target destination
        try:
            os.replace(payload_file, dest)
        except OSError:
            shutil.copy2(payload_file, dest)
            payload_file.unlink()

        ## Step 6: Restore original POSIX permission bits
        try:
            restored_mode = int(receipt.original_mode_octal, 8)
            os.chmod(dest, restored_mode)
        except (ValueError, OSError):
            os.chmod(dest, 0o644)

        ## Step 7: Update receipt status
        receipt_file = item_dir / "receipt.json"
        ## Temporarily enable write permissions on receipt file
        os.chmod(receipt_file, 0o600)
        updated_dict = receipt.to_dict()
        updated_dict["status"] = "RESTORED"
        updated_dict["restored_at_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        updated_dict["restored_path"] = str(dest)
        with open(receipt_file, "w", encoding="utf-8") as f:
            json.dump(updated_dict, f, indent=2, sort_keys=True)
        ## Lock receipt file back to read-only
        os.chmod(receipt_file, 0o400)

        ## Update index record
        index = self._read_index()
        if quarantine_id in index:
            index[quarantine_id]["status"] = "RESTORED"
            self._write_index(index)

        return dest
