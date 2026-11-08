"""
Program: Quarantine Sentinel - Command-Line Interface (CLI)
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Provide a POSIX-standard CLI with TTY-aware colorized output and structured JSON export for scanning files, isolating threats into the vault, viewing receipts, verifying integrity, and restoring files.
"""

from __future__ import annotations

## Standard CLI, JSON, system, and filesystem modules
import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

## Import package version and core sentinel engines
from sentinel import __version__
from sentinel.magic import MagicInspector
from sentinel.rules import RiskLevel, ThreatEngine, ThreatReport
from sentinel.vault import QuarantineReceipt, QuarantineVault


## ----------------------------------------------------------------------------
## Terminal Color & Formatting Helper
## ----------------------------------------------------------------------------

class TermColor:
    """ANSI Escape sequence color formatter with automatic TTY detection."""
    ## ANSI escape code constants
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    @classmethod
    def enabled(cls) -> bool:
        """
        Check if ANSI colors should be emitted.
        Colors are disabled if stdout is redirected or NO_COLOR is defined.
        """
        ## Honor NO_COLOR standard (https://no-color.org) and dumb terminals
        if "NO_COLOR" in os.environ or os.environ.get("TERM") == "dumb":
            return False
        ## Only emit ANSI codes if stdout is connected to a live interactive terminal
        return sys.stdout.isatty()

    @classmethod
    def colorize(cls, text: str, color_code: str) -> str:
        """Wrap text in ANSI color sequence if supported."""
        if cls.enabled():
            return f"{color_code}{text}{cls.RESET}"
        return text

    @classmethod
    def red(cls, text: str) -> str:
        """Render text in red."""
        return cls.colorize(text, cls.RED)

    @classmethod
    def green(cls, text: str) -> str:
        """Render text in green."""
        return cls.colorize(text, cls.GREEN)

    @classmethod
    def yellow(cls, text: str) -> str:
        """Render text in yellow."""
        return cls.colorize(text, cls.YELLOW)

    @classmethod
    def cyan(cls, text: str) -> str:
        """Render text in cyan."""
        return cls.colorize(text, cls.CYAN)

    @classmethod
    def bold(cls, text: str) -> str:
        """Render text in bold."""
        return cls.colorize(text, cls.BOLD)

    @classmethod
    def dim(cls, text: str) -> str:
        """Render text in dim style."""
        return cls.colorize(text, cls.DIM)


## ----------------------------------------------------------------------------
## CLI Command Handlers
## ----------------------------------------------------------------------------

def handle_scan(args: argparse.Namespace) -> int:
    """
    Recursively inspect files and print forensic threat reports.
    """
    ## Resolve target path
    target_path = Path(args.path).resolve()
    if not target_path.exists():
        print(TermColor.red(f"Error: Target path does not exist: {target_path}"), file=sys.stderr)
        return 1

    ## Collect list of candidate regular files
    files_to_scan: List[Path] = []
    if target_path.is_file():
        files_to_scan.append(target_path)
    else:
        ## Collect regular files recursively, ignoring broken symlinks
        for item in sorted(target_path.rglob("*")):
            if item.is_file() and not item.is_symlink():
                files_to_scan.append(item)

    ## Early exit if directory is empty
    if not files_to_scan:
        print(TermColor.yellow(f"No regular files discovered under {target_path}"))
        return 0

    reports: List[ThreatReport] = []
    threat_count = 0

    ## Execute forensic threat analysis on each file
    for file_path in files_to_scan:
        try:
            report = ThreatEngine.analyze_file(file_path)
            reports.append(report)
            if report.is_suspicious:
                threat_count += 1
        except Exception as ex:
            if not args.json:
                print(TermColor.red(f"Failed to analyze {file_path}: {ex}"), file=sys.stderr)

    ## Output structured JSON if requested
    if args.json:
        output_data = {
            "target": str(target_path),
            "files_scanned": len(files_to_scan),
            "threats_detected": threat_count,
            "reports": [r.to_dict() for r in reports if args.show_all or r.is_suspicious],
        }
        print(json.dumps(output_data, indent=2))
        return 2 if threat_count > 0 else 0

    ## Human-readable interactive terminal formatting
    print(TermColor.bold(f"\n🔍 Quarantine Sentinel Scan Summary: {target_path}"))
    print(TermColor.dim("=" * 78))
    print(f"Total Files Scanned: {TermColor.cyan(str(len(files_to_scan)))} | "
          f"Threats Detected: {TermColor.red(str(threat_count)) if threat_count > 0 else TermColor.green('0')}")
    print(TermColor.dim("-" * 78))

    ## Filter display reports
    display_reports = [r for r in reports if args.show_all or r.is_suspicious]

    if not display_reports:
        print(TermColor.green("✓ All scanned files appear clean and conform to expected signatures."))
        print(TermColor.dim("=" * 78 + "\n"))
        return 0

    ## Render individual threat reports
    for r in display_reports:
        if r.risk_level == RiskLevel.CRITICAL:
            badge = TermColor.red(f"[{r.risk_level.value} - SCORE {r.risk_score}]")
        elif r.risk_level == RiskLevel.HIGH:
            badge = TermColor.red(f"[{r.risk_level.value} - SCORE {r.risk_score}]")
        elif r.risk_level == RiskLevel.MEDIUM:
            badge = TermColor.yellow(f"[{r.risk_level.value} - SCORE {r.risk_score}]")
        elif r.risk_level == RiskLevel.LOW:
            badge = TermColor.cyan(f"[{r.risk_level.value} - SCORE {r.risk_score}]")
        else:
            badge = TermColor.green(f"[{r.risk_level.value} - SCORE {r.risk_score}]")

        print(f"\n{badge} {TermColor.bold(str(r.file_path))}")
        print(f"  • True Format : {TermColor.cyan(r.magic_result.description)} ({r.magic_result.mime_type})")
        print(f"  • File Size   : {r.hash_manifest.formatted_size} ({r.hash_manifest.file_size_bytes} bytes)")
        print(f"  • SHA-256     : {TermColor.dim(r.hash_manifest.sha256)}")

        if r.findings:
            print("  • Findings:")
            for f in r.findings:
                severity_tag = TermColor.red(f"[{f.severity.value}]") if f.severity in (RiskLevel.CRITICAL, RiskLevel.HIGH) else TermColor.yellow(f"[{f.severity.value}]")
                print(f"    - {severity_tag} {TermColor.bold(f.title)}")
                print(f"      {TermColor.dim(f.explanation)}")

    print(TermColor.dim("\n" + "=" * 78))
    if threat_count > 0:
        print(TermColor.yellow(f"⚠️  {threat_count} suspicious file(s) identified. Run 'quarantine' to isolate them into the vault.\n"))
        ## POSIX Exit Code 2 signals detected threats to CI/CD and pre-commit runners
        return 2

    print(TermColor.green("✓ Clean scan complete.\n"))
    return 0


def handle_quarantine(args: argparse.Namespace) -> int:
    """
    Scan files and isolate any suspicious payloads into the quarantine vault.
    """
    target_path = Path(args.path).resolve()
    if not target_path.exists():
        print(TermColor.red(f"Error: Target path does not exist: {target_path}"), file=sys.stderr)
        return 1

    ## Initialize vault instance
    vault = QuarantineVault(vault_dir=args.vault_dir)

    ## Collect target files
    files_to_check: List[Path] = []
    if target_path.is_file():
        files_to_check.append(target_path)
    else:
        for item in sorted(target_path.rglob("*")):
            if item.is_file() and not item.is_symlink():
                files_to_check.append(item)

    quarantined_count = 0
    receipts: List[QuarantineReceipt] = []

    print(TermColor.bold(f"\n🛡️  Quarantine Sentinel: Isolating Untrusted Payloads"))
    print(TermColor.dim(f"Vault Directory: {vault.vault_dir}"))
    print(TermColor.dim("=" * 78))

    ## Process each candidate file
    for file_path in files_to_check:
        try:
            report = ThreatEngine.analyze_file(file_path)
            if report.is_suspicious or args.force:
                if args.dry_run:
                    print(TermColor.yellow(f"[DRY-RUN] Would quarantine: {file_path} (Risk: {report.risk_level.value} - Score {report.risk_score})"))
                    quarantined_count += 1
                else:
                    receipt = vault.quarantine(file_path, report=report, force=args.force)
                    receipts.append(receipt)
                    quarantined_count += 1
                    print(TermColor.red(f"[QUARANTINED] {file_path}"))
                    print(f"  → ID: {TermColor.cyan(receipt.quarantine_id)}")
                    print(f"  → Permissions Neutralized: {receipt.original_mode_octal} -> 0o000")
                    print(f"  → Audit Receipt Issued: {vault.payloads_dir / receipt.quarantine_id / 'receipt.json'}")
        except Exception as ex:
            print(TermColor.red(f"Failed to process {file_path}: {ex}"), file=sys.stderr)

    print(TermColor.dim("-" * 78))
    if args.dry_run:
        print(TermColor.yellow(f"Dry-run finished. {quarantined_count} file(s) would be isolated into quarantine."))
    else:
        print(TermColor.green(f"Quarantine completed. {quarantined_count} file(s) safely isolated into vault."))
    print(TermColor.dim("=" * 78 + "\n"))

    return 0


def handle_receipts(args: argparse.Namespace) -> int:
    """
    List all stored quarantine audit receipts.
    """
    vault = QuarantineVault(vault_dir=args.vault_dir)
    records = vault.list_receipts()

    if args.json:
        print(json.dumps(records, indent=2))
        return 0

    print(TermColor.bold(f"\n📜 Quarantine Vault Receipts ({vault.vault_dir})"))
    print(TermColor.dim("=" * 78))

    if not records:
        print(TermColor.dim("Vault is currently empty. No quarantine records found."))
        print(TermColor.dim("=" * 78 + "\n"))
        return 0

    for r in records:
        status = r.get("status", "QUARANTINED")
        status_colored = TermColor.green(f"[{status}]") if status == "RESTORED" else TermColor.red(f"[{status}]")
        print(f"{status_colored} {TermColor.cyan(r['quarantine_id'])}")
        print(f"  • Date & Time   : {r.get('quarantined_at_utc')}")
        print(f"  • Original File : {TermColor.bold(r.get('original_filename', ''))}")
        print(f"  • Original Path : {r.get('original_path')}")
        print(f"  • Risk Level    : {r.get('risk_level')} (Score {r.get('risk_score')})")
        print(f"  • SHA-256       : {TermColor.dim(r.get('sha256', ''))}")
        print(TermColor.dim("-" * 78))

    print()
    return 0


def handle_receipt(args: argparse.Namespace) -> int:
    """
    Inspect the complete cryptographic receipt for a specific quarantine record.
    """
    vault = QuarantineVault(vault_dir=args.vault_dir)
    try:
        receipt = vault.get_receipt(args.quarantine_id)
    except KeyError:
        print(TermColor.red(f"Error: Receipt ID '{args.quarantine_id}' not found in vault."), file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(receipt.to_dict(), indent=2))
        return 0

    print(TermColor.bold(f"\n📋 Detailed Quarantine Audit Receipt: {receipt.quarantine_id}"))
    print(TermColor.dim("=" * 78))
    print(f"Status              : {receipt.status}")
    print(f"Quarantined At (UTC): {receipt.quarantined_at_utc}")
    print(f"Original Path       : {receipt.original_path}")
    print(f"Original File Mode  : {receipt.original_mode_octal}")
    print(f"Original Owner UID  : {receipt.original_uid} (GID: {receipt.original_gid})")
    print(f"Payload File Size   : {receipt.file_size_bytes} bytes")
    print(f"Receipt Self-Digest : {receipt.receipt_digest}")
    print(TermColor.dim("-" * 78))
    print(TermColor.bold("Cryptographic Digests:"))
    print(f"  • SHA-256 : {receipt.hashes.get('sha256')}")
    print(f"  • SHA-512 : {receipt.hashes.get('sha512')}")
    print(f"  • MD5     : {receipt.hashes.get('md5')}")
    print(TermColor.dim("-" * 78))
    print(TermColor.bold("Binary Format Inspection:"))
    print(f"  • MIME Type   : {receipt.magic.get('mime_type')}")
    print(f"  • Description : {receipt.magic.get('description')}")
    print(f"  • Executable  : {receipt.magic.get('is_executable')}")
    print(TermColor.dim("-" * 78))
    print(TermColor.bold(f"Threat Evaluation (Risk Score: {receipt.threat_report.get('risk_score')}/100):"))
    for f in receipt.threat_report.get("findings", []):
        print(f"  - [{f.get('severity')}] {f.get('title')}")
        print(f"    {TermColor.dim(f.get('explanation', ''))}")
    print(TermColor.dim("=" * 78 + "\n"))

    return 0


def handle_restore(args: argparse.Namespace) -> int:
    """
    Restore an isolated file after mandatory SHA-256 integrity verification.
    """
    vault = QuarantineVault(vault_dir=args.vault_dir)

    print(TermColor.bold(f"\n🔄 Restoring Quarantined Payload: {args.quarantine_id}"))
    try:
        dest = vault.restore(args.quarantine_id, destination_path=args.target)
        print(TermColor.green(f"✓ File successfully verified and restored!"))
        print(f"Restored Location: {TermColor.bold(str(dest))}")
        return 0
    except Exception as ex:
        print(TermColor.red(f"Restoration failed: {ex}"), file=sys.stderr)
        return 1


def handle_verify_vault(args: argparse.Namespace) -> int:
    """
    Audit vault integrity, verifying file digests against receipts.
    """
    vault = QuarantineVault(vault_dir=args.vault_dir)
    results = vault.verify_vault_integrity()

    print(TermColor.bold(f"\n🔒 Quarantine Vault Integrity Audit"))
    print(TermColor.dim(f"Vault: {vault.vault_dir}"))
    print(TermColor.dim("=" * 78))

    if not results:
        print(TermColor.dim("No items in vault to verify."))
        print(TermColor.dim("=" * 78 + "\n"))
        return 0

    all_passed = True
    for item in results:
        qid = item["quarantine_id"]
        receipt_ok = item["receipt_valid"]
        payload_ok = item["payload_hash_valid"]
        err = item.get("error")

        if receipt_ok and payload_ok:
            status_text = TermColor.green("[PASS: VALID]")
        else:
            status_text = TermColor.red("[FAIL: TAMPERED/CORRUPT]")
            all_passed = False

        print(f"{status_text} {TermColor.cyan(qid)}")
        print(f"  • Receipt Signature Integrity : {'PASS' if receipt_ok else 'FAIL'}")
        print(f"  • Payload SHA-256 Match       : {'PASS' if payload_ok else 'FAIL'}")
        if err:
            print(f"  • Error Details               : {TermColor.red(err)}")
        print(TermColor.dim("-" * 78))

    if all_passed:
        print(TermColor.green("✓ All vault records and payloads passed cryptographic integrity checks.\n"))
        return 0
    else:
        print(TermColor.red("❌ Integrity verification failed on one or more records!\n"))
        return 1


## ----------------------------------------------------------------------------
## CLI Parser Definition & Main Execution
## ----------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Quarantine Sentinel: Zero-dependency offline file security and automated quarantine.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"quarantine-sentinel {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available sub-commands")

    ## Command: scan
    scan_parser = subparsers.add_parser("scan", help="Scan files or directories for disguised executables and threats")
    scan_parser.add_argument("path", help="Path to file or directory to scan")
    scan_parser.add_argument("--all", dest="show_all", action="store_true", help="Display all files including clean ones")
    scan_parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    ## Command: quarantine
    quar_parser = subparsers.add_parser("quarantine", help="Scan and automatically isolate suspicious files into the vault")
    quar_parser.add_argument("path", help="Path to file or directory to inspect and quarantine")
    quar_parser.add_argument("--vault-dir", default=None, help="Custom quarantine vault path")
    quar_parser.add_argument("--dry-run", action="store_true", help="Preview files to be quarantined without moving them")
    quar_parser.add_argument("--force", action="store_true", help="Force quarantine even if risk score is low")

    ## Command: receipts
    receipts_parser = subparsers.add_parser("receipts", help="List all quarantine audit receipts")
    receipts_parser.add_argument("--vault-dir", default=None, help="Custom quarantine vault path")
    receipts_parser.add_argument("--json", action="store_true", help="Output receipts in JSON format")

    ## Command: receipt
    receipt_parser = subparsers.add_parser("receipt", help="Show full forensic details for a specific quarantine record")
    receipt_parser.add_argument("quarantine_id", help="Quarantine ID to inspect")
    receipt_parser.add_argument("--vault-dir", default=None, help="Custom quarantine vault path")
    receipt_parser.add_argument("--json", action="store_true", help="Output receipt in JSON format")

    ## Command: restore
    restore_parser = subparsers.add_parser("restore", help="Safely restore a quarantined file with hash verification")
    restore_parser.add_argument("quarantine_id", help="Quarantine ID of payload to restore")
    restore_parser.add_argument("--target", default=None, help="Optional destination path or directory")
    restore_parser.add_argument("--vault-dir", default=None, help="Custom quarantine vault path")

    ## Command: verify
    verify_parser = subparsers.add_parser("verify", help="Audit vault integrity and cryptographic hash proofs")
    verify_parser.add_argument("--vault-dir", default=None, help="Custom quarantine vault path")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    ## If no subcommand provided, show help message
    if not args.command:
        parser.print_help()
        return 1

    ## Route to appropriate command handler
    if args.command == "scan":
        return handle_scan(args)
    elif args.command == "quarantine":
        return handle_quarantine(args)
    elif args.command == "receipts":
        return handle_receipts(args)
    elif args.command == "receipt":
        return handle_receipt(args)
    elif args.command == "restore":
        return handle_restore(args)
    elif args.command == "verify":
        return handle_verify_vault(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
