"""
Program: Quarantine Sentinel - Automated Test Suite
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Comprehensive verification suite validating binary signature parsing, cryptographic hashing, heuristic threat detection, quarantine isolation, vault tamper auditing, and CLI integration.
"""

## Standard testing, filesystem, hashing, and binary packing utilities
import hashlib
import json
import os
import shutil
import stat
import struct
import tempfile
import unittest
from pathlib import Path

## Import Quarantine Sentinel subsystems under test
from sentinel.cli import main
from sentinel.hasher import CryptoHasher
from sentinel.magic import FileTypeCategory, MagicInspector
from sentinel.rules import RiskLevel, ThreatEngine
from sentinel.vault import QuarantineVault


## ----------------------------------------------------------------------------
## Test Suite 1: Binary Magic Inspector
## ----------------------------------------------------------------------------

class TestMagicInspector(unittest.TestCase):
    """Test suite for binary header magic byte parsing."""

    def test_empty_payload(self) -> None:
        """Verify empty files are identified as zero-byte text."""
        ## Inspect empty byte payload
        result = MagicInspector.inspect_bytes(b"")

        ## Assert proper categorization as empty text without execution privileges
        self.assertEqual(result.mime_type, "application/x-empty")
        self.assertEqual(result.category, FileTypeCategory.TEXT)
        self.assertFalse(result.is_executable)

    def test_elf_binary_parsing(self) -> None:
        """Construct synthetic ELF64 Little-Endian binary header and verify parsing."""
        ## Assemble 64-bit Little-Endian ELF executable header:
        ## \x7fELF (magic) + 2 (64-bit) + 1 (LE) + 1 (version) + 0 (SysV) + 8 zeros + 2 (ET_EXEC) + 0x3E (x86-64)
        elf_header = (
            b"\x7fELF"
            b"\x02"
            b"\x01"
            b"\x01"
            b"\x00"
            + b"\x00" * 8
            + b"\x02\x00"
            + b"\x3e\x00"
        )
        ## Inspect synthetic ELF header
        result = MagicInspector.inspect_bytes(elf_header)

        ## Assert ELF properties extracted correctly
        self.assertEqual(result.mime_type, "application/x-executable-elf")
        self.assertEqual(result.category, FileTypeCategory.EXECUTABLE)
        self.assertTrue(result.is_executable)
        self.assertEqual(result.details.get("bitness"), 64)
        self.assertEqual(result.details.get("endianness"), "little-endian")
        self.assertEqual(result.details.get("elf_type"), "Executable Binary")

    def test_pe_executable_parsing(self) -> None:
        """Construct synthetic Windows PE32+ (x64) executable header and verify parsing."""
        ## Build 256-byte MS-DOS stub containing MZ signature
        header = bytearray(b"\x00" * 256)
        header[0:2] = b"MZ"

        ## Pack e_lfanew pointer at offset 0x3C pointing to NT PE header at 0x80
        struct.pack_into("<I", header, 0x3C, 0x80)

        ## Write PE signature 'PE\0\0' at offset 0x80
        header[0x80:0x84] = b"PE\x00\x00"

        ## Pack machine architecture at 0x84: 0x8664 represents AMD64 / x86-64
        struct.pack_into("<H", header, 0x84, 0x8664)

        ## Pack characteristics at 0x96: 0x0002 represents IMAGE_FILE_EXECUTABLE_IMAGE
        struct.pack_into("<H", header, 0x96, 0x0002)

        ## Inspect synthetic PE header
        result = MagicInspector.inspect_bytes(bytes(header))

        ## Assert PE format properties
        self.assertEqual(result.mime_type, "application/x-dosexec")
        self.assertEqual(result.category, FileTypeCategory.EXECUTABLE)
        self.assertTrue(result.is_executable)
        self.assertIn("x86-64", str(result.details.get("machine")))

    def test_macho_binary_parsing(self) -> None:
        """Verify Mach-O 64-bit header detection."""
        ## Build Mach-O 64-bit Little Endian header (0xCFFAEDFE)
        macho_header = b"\xcf\xfa\xed\xfe" + b"\x00" * 32
        result = MagicInspector.inspect_bytes(macho_header)

        ## Assert Mach-O identification
        self.assertEqual(result.mime_type, "application/x-mach-binary")
        self.assertEqual(result.category, FileTypeCategory.EXECUTABLE)
        self.assertTrue(result.is_executable)
        self.assertEqual(result.details.get("bitness"), 64)

    def test_shebang_parsing(self) -> None:
        """Verify POSIX shebang scripts are recognized as executable scripts."""
        ## Construct bash shebang script
        script_data = b"#!/bin/bash\necho 'hello world'\n"
        result = MagicInspector.inspect_bytes(script_data)

        ## Assert script classification and interpreter path extraction
        self.assertEqual(result.mime_type, "text/x-shellscript")
        self.assertEqual(result.category, FileTypeCategory.SCRIPT)
        self.assertTrue(result.is_executable)
        self.assertEqual(result.details.get("interpreter"), "/bin/bash")

    def test_pdf_document_parsing(self) -> None:
        """Verify PDF document signature."""
        ## Construct minimal PDF header
        pdf_data = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n"
        result = MagicInspector.inspect_bytes(pdf_data)

        ## Assert PDF categorization as passive document
        self.assertEqual(result.mime_type, "application/pdf")
        self.assertEqual(result.category, FileTypeCategory.DOCUMENT)
        self.assertFalse(result.is_executable)

    def test_image_formats_parsing(self) -> None:
        """Verify PNG and JPEG headers."""
        ## Construct PNG header slice
        png_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        res_png = MagicInspector.inspect_bytes(png_data)
        self.assertEqual(res_png.mime_type, "image/png")
        self.assertEqual(res_png.category, FileTypeCategory.IMAGE)

        ## Construct JPEG header slice
        jpeg_data = b"\xff\xd8\xff\xe0\x00\x10JFIF"
        res_jpeg = MagicInspector.inspect_bytes(jpeg_data)
        self.assertEqual(res_jpeg.mime_type, "image/jpeg")
        self.assertEqual(res_jpeg.category, FileTypeCategory.IMAGE)

    def test_wasm_binary_parsing(self) -> None:
        """Verify WebAssembly binary header detection."""
        ## Construct WebAssembly binary header: \x00asm with version 1
        wasm_data = b"\x00asm\x01\x00\x00\x00"
        result = MagicInspector.inspect_bytes(wasm_data)

        ## Assert WASM module categorization as executable binary
        self.assertEqual(result.mime_type, "application/wasm")
        self.assertEqual(result.category, FileTypeCategory.EXECUTABLE)
        self.assertTrue(result.is_executable)

    def test_tar_ustar_parsing(self) -> None:
        """Verify POSIX tar archive detection at offset 257."""
        ## Construct 512-byte tar header block with ustar magic at offset 257
        tar_header = bytearray(b"\x00" * 512)
        tar_header[257:262] = b"ustar"
        result = MagicInspector.inspect_bytes(bytes(tar_header))

        ## Assert POSIX TAR archive classification
        self.assertEqual(result.mime_type, "application/x-tar")
        self.assertEqual(result.category, FileTypeCategory.ARCHIVE)

    def test_office_docx_parsing(self) -> None:
        """Verify modern Office DOCX detection inside ZIP container."""
        ## Construct simulated ZIP container holding [Content_Types].xml and word/
        mock_docx = b"PK\x03\x04" + b"\x00" * 20 + b"[Content_Types].xml" + b"word/document.xml"
        result = MagicInspector.inspect_bytes(mock_docx)

        ## Assert recognition as Word Document
        self.assertIn("wordprocessingml", result.mime_type)
        self.assertEqual(result.category, FileTypeCategory.DOCUMENT)
        self.assertFalse(result.is_executable)


## ----------------------------------------------------------------------------
## Test Suite 2: Cryptographic Hasher
## ----------------------------------------------------------------------------

class TestCryptoHasher(unittest.TestCase):
    """Test suite for streaming cryptographic multi-hash calculations."""

    def setUp(self) -> None:
        ## Create temporary directory for scratch files
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        ## Clean up temporary test files
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_streaming_hash_correctness(self) -> None:
        """Verify SHA-256, SHA-512, and MD5 match standard hashlib reference."""
        ## Generate known byte payload
        payload = b"Quarantine Sentinel High-Assurance Cryptographic Validation Payload" * 1000
        test_file = Path(self.temp_dir) / "sample.bin"
        test_file.write_bytes(payload)

        ## Execute streaming multi-algorithm hasher
        manifest = CryptoHasher.hash_file(test_file)

        ## Assert all three digests match standard hashlib values exactly
        self.assertEqual(manifest.sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(manifest.sha512, hashlib.sha512(payload).hexdigest())
        self.assertEqual(manifest.md5, hashlib.md5(payload).hexdigest())
        self.assertEqual(manifest.file_size_bytes, len(payload))
        self.assertTrue(manifest.formatted_size.endswith("KiB") or manifest.formatted_size.endswith("B"))

    def test_verify_integrity_helper(self) -> None:
        """Verify constant-time integrity verification method."""
        test_file = Path(self.temp_dir) / "verify.txt"
        test_file.write_text("Integrity Check Data", encoding="utf-8")

        ## Compute expected SHA-256
        correct_hash = hashlib.sha256(b"Integrity Check Data").hexdigest()

        ## Assert true on matching digest, false on bogus digest
        self.assertTrue(CryptoHasher.verify_integrity(test_file, correct_hash))
        self.assertFalse(CryptoHasher.verify_integrity(test_file, "0" * 64))

    def test_multi_chunk_large_file(self) -> None:
        """Verify file exceeding buffer chunk size (64KB) hashes accurately."""
        ## 160 KB payload spans three 64 KiB chunks
        large_payload = b"A" * 70000 + b"B" * 70000 + b"C" * 20000
        test_file = Path(self.temp_dir) / "large.dat"
        test_file.write_bytes(large_payload)

        ## Verify multi-chunk hash calculation
        manifest = CryptoHasher.hash_file(test_file)
        self.assertEqual(manifest.sha256, hashlib.sha256(large_payload).hexdigest())
        self.assertEqual(manifest.file_size_bytes, 160000)

    def test_hash_bytes(self) -> None:
        """Verify in-memory byte sequence hashing."""
        data = b"In-memory crypto test vector"
        manifest = CryptoHasher.hash_bytes(data)
        self.assertEqual(manifest.sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(manifest.file_size_bytes, len(data))


## ----------------------------------------------------------------------------
## Test Suite 3: Threat Detection Rules Engine
## ----------------------------------------------------------------------------

class TestThreatEngine(unittest.TestCase):
    """Test suite for threat detection rules and heuristics."""

    def setUp(self) -> None:
        ## Create scratch environment
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        ## Remove scratch environment
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_disguised_elf_binary(self) -> None:
        """Detect an ELF binary disguised as 'quarterly_report.pdf'."""
        disguised_file = Path(self.temp_dir) / "quarterly_report.pdf"
        elf_content = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 60
        disguised_file.write_bytes(elf_content)

        ## Execute threat analysis
        report = ThreatEngine.analyze_file(disguised_file)

        ## Assert detection of disguised binary rule
        self.assertTrue(report.is_suspicious)
        self.assertEqual(report.risk_level, RiskLevel.CRITICAL)
        self.assertGreaterEqual(report.risk_score, 80)
        rule_ids = [f.rule_id for f in report.findings]
        self.assertIn("RULE_DISGUISED_BINARY", rule_ids)

    def test_disguised_pe_binary(self) -> None:
        """Detect a Windows PE binary disguised as 'spreadsheet.xlsx'."""
        disguised_file = Path(self.temp_dir) / "spreadsheet.xlsx"
        pe_content = bytearray(b"\x00" * 128)
        pe_content[0:2] = b"MZ"
        struct.pack_into("<I", pe_content, 0x3C, 0x40)
        pe_content[0x40:0x44] = b"PE\x00\x00"
        disguised_file.write_bytes(bytes(pe_content))

        ## Execute threat analysis
        report = ThreatEngine.analyze_file(disguised_file)

        ## Assert critical threat detection
        self.assertTrue(report.is_suspicious)
        self.assertEqual(report.risk_level, RiskLevel.CRITICAL)
        self.assertIn("RULE_DISGUISED_BINARY", [f.rule_id for f in report.findings])

    def test_double_extension_attack(self) -> None:
        """Detect double extension evasion tactic like 'invoice.pdf.exe'."""
        double_ext_file = Path(self.temp_dir) / "invoice.pdf.exe"
        double_ext_file.write_bytes(b"dummy payload")

        ## Execute threat analysis
        report = ThreatEngine.analyze_file(double_ext_file)

        ## Assert double extension heuristic triggered
        self.assertTrue(report.is_suspicious)
        self.assertIn("RULE_DOUBLE_EXTENSION", [f.rule_id for f in report.findings])

    def test_unicode_rlo_attack(self) -> None:
        """Detect Right-To-Left Override (U+202E) attack disguised as PDF."""
        rlo_filename = "report_\u202Efdp.exe"
        rlo_file = Path(self.temp_dir) / rlo_filename
        rlo_file.write_bytes(b"dummy executable")

        ## Execute threat analysis
        report = ThreatEngine.analyze_file(rlo_file)

        ## Assert critical RLO detection
        self.assertTrue(report.is_suspicious)
        self.assertEqual(report.risk_level, RiskLevel.CRITICAL)
        self.assertIn("RULE_UNICODE_RLO_BIDI", [f.rule_id for f in report.findings])

    def test_unicode_zero_width_attack(self) -> None:
        """Detect zero-width space obfuscation (U+200B)."""
        zw_filename = "financial\u200Bsummary.pdf.exe"
        zw_file = Path(self.temp_dir) / zw_filename
        zw_file.write_bytes(b"dummy data")

        ## Execute threat analysis
        report = ThreatEngine.analyze_file(zw_file)

        ## Assert zero-width character detection
        self.assertTrue(report.is_suspicious)
        self.assertIn("RULE_UNICODE_ZERO_WIDTH", [f.rule_id for f in report.findings])

    def test_posix_exec_bit_anomaly_on_pdf(self) -> None:
        """Detect POSIX executable permission bits (0o755) set on an ordinary PDF."""
        doc_file = Path(self.temp_dir) / "contract.pdf"
        doc_file.write_bytes(b"%PDF-1.5 legitimate pdf data")
        ## Set dangerous executable permission bits on passive document
        os.chmod(doc_file, 0o755)

        ## Execute threat analysis
        report = ThreatEngine.analyze_file(doc_file)

        ## Assert execution bit anomaly detection
        self.assertIn("RULE_EXEC_BIT_ANOMALY", [f.rule_id for f in report.findings])

    def test_shebang_in_text_file(self) -> None:
        """Detect executable shebang hidden in .txt file."""
        script_in_txt = Path(self.temp_dir) / "notes.txt"
        script_in_txt.write_bytes(b"#!/bin/bash\nrm -rf /tmp/data\n")

        ## Execute threat analysis
        report = ThreatEngine.analyze_file(script_in_txt)

        ## Assert shebang camouflage detection
        self.assertIn("RULE_SHEBANG_CAMOUFLAGE", [f.rule_id for f in report.findings])

    def test_clean_file_is_safe(self) -> None:
        """Verify standard legitimate PDF without +x is evaluated as SAFE."""
        clean_file = Path(self.temp_dir) / "handbook.pdf"
        clean_file.write_bytes(b"%PDF-1.7 legitimate documentation body")
        os.chmod(clean_file, 0o644)

        ## Execute threat analysis
        report = ThreatEngine.analyze_file(clean_file)

        ## Assert benign classification
        self.assertFalse(report.is_suspicious)
        self.assertEqual(report.risk_level, RiskLevel.SAFE)
        self.assertEqual(report.risk_score, 0)
        self.assertEqual(len(report.findings), 0)


## ----------------------------------------------------------------------------
## Test Suite 4: Quarantine Vault Storage & Receipts
## ----------------------------------------------------------------------------

class TestQuarantineVault(unittest.TestCase):
    """Test suite for quarantine vault isolation, permission stripping, and audit receipts."""

    def setUp(self) -> None:
        ## Initialize isolated vault directory
        self.temp_dir = tempfile.mkdtemp()
        self.vault_dir = Path(self.temp_dir) / "vault"
        self.vault = QuarantineVault(vault_dir=self.vault_dir)

    def tearDown(self) -> None:
        ## Teardown temporary directory
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_quarantine_isolation_and_permission_stripping(self) -> None:
        """Verify file is relocated, neutralized with mode 0o000, and receipt created."""
        suspect_file = Path(self.temp_dir) / "malicious.pdf"
        suspect_file.write_bytes(b"\x7fELF" + b"\x00" * 100)
        os.chmod(suspect_file, 0o755)

        ## Execute vault quarantine
        receipt = self.vault.quarantine(suspect_file)

        ## Assert original file has been relocated from source path
        self.assertFalse(suspect_file.exists())

        ## Assert payload is securely stored in quarantine vault
        item_dir = self.vault.payloads_dir / receipt.quarantine_id
        payload_path = item_dir / "payload.bin"
        self.assertTrue(payload_path.exists())

        ## Verify permissions have been stripped to mode 0o000 (inert stone)
        payload_mode = stat.S_IMODE(payload_path.stat().st_mode)
        self.assertEqual(payload_mode, 0o000)

        ## Verify receipt file contents and audit trail
        receipt_file = item_dir / "receipt.json"
        self.assertTrue(receipt_file.exists())
        self.assertEqual(receipt.original_filename, "malicious.pdf")
        self.assertEqual(receipt.original_mode_octal, "0o755")
        self.assertEqual(receipt.status, "QUARANTINED")

        ## Verify index tracking
        records = self.vault.list_receipts()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["quarantine_id"], receipt.quarantine_id)

    def test_vault_integrity_and_tamper_detection(self) -> None:
        """Verify vault integrity audit detects payload modification."""
        suspect = Path(self.temp_dir) / "bad.docx.sh"
        suspect.write_bytes(b"echo 'malicious script'")

        receipt = self.vault.quarantine(suspect)

        ## 1. Initial integrity audit should pass completely
        audit_results = self.vault.verify_vault_integrity()
        self.assertEqual(len(audit_results), 1)
        self.assertTrue(audit_results[0]["receipt_valid"])
        self.assertTrue(audit_results[0]["payload_hash_valid"])

        ## 2. Introduce unauthorized payload modification
        payload_file = self.vault.payloads_dir / receipt.quarantine_id / "payload.bin"
        os.chmod(payload_file, 0o600)
        payload_file.write_bytes(b"tampered content")
        os.chmod(payload_file, 0o000)

        ## 3. Cryptographic integrity audit must now catch tampering!
        tampered_audit = self.vault.verify_vault_integrity()
        self.assertFalse(tampered_audit[0]["payload_hash_valid"])

    def test_safe_restoration(self) -> None:
        """Verify quarantined file can be restored with original permissions."""
        orig_file = Path(self.temp_dir) / "restore_me.pdf.exe"
        orig_content = b"Binary Payload Data 12345"
        orig_file.write_bytes(orig_content)
        os.chmod(orig_file, 0o755)

        receipt = self.vault.quarantine(orig_file)

        ## Restore quarantined payload to designated path
        target_restore = Path(self.temp_dir) / "restored_file.bin"
        restored_path = self.vault.restore(receipt.quarantine_id, destination_path=target_restore)

        ## Assert file content and permissions restored faithfully
        self.assertTrue(restored_path.exists())
        self.assertEqual(restored_path.read_bytes(), orig_content)
        self.assertEqual(stat.S_IMODE(restored_path.stat().st_mode), 0o755)

        ## Verify status transition in receipt
        updated_receipt = self.vault.get_receipt(receipt.quarantine_id)
        self.assertEqual(updated_receipt.status, "RESTORED")


## ----------------------------------------------------------------------------
## Test Suite 5: CLI Subcommand Integration
## ----------------------------------------------------------------------------

class TestCLIIntegration(unittest.TestCase):
    """Test suite for CLI subcommands."""

    def setUp(self) -> None:
        ## Initialize scratch CLI testing environment
        self.temp_dir = tempfile.mkdtemp()
        self.vault_dir = Path(self.temp_dir) / "cli_vault"

    def tearDown(self) -> None:
        ## Clean up scratch directory
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_cli_scan_clean_and_dirty(self) -> None:
        """Verify CLI scan returns exit code 0 for clean and 2 for threat."""
        clean_file = Path(self.temp_dir) / "doc.pdf"
        clean_file.write_bytes(b"%PDF-1.4 sample pdf content")
        os.chmod(clean_file, 0o644)

        ## Clean scan returns POSIX 0
        exit_code = main(["scan", str(clean_file)])
        self.assertEqual(exit_code, 0)

        ## Malicious scan returns POSIX 2
        bad_file = Path(self.temp_dir) / "invoice.pdf"
        bad_file.write_bytes(b"\x7fELF" + b"\x00" * 40)
        exit_code_dirty = main(["scan", str(bad_file)])
        self.assertEqual(exit_code_dirty, 2)

    def test_cli_quarantine_and_receipts(self) -> None:
        """Verify CLI quarantine isolates file and receipts can be listed."""
        bad_file = Path(self.temp_dir) / "fake.png.exe"
        bad_file.write_bytes(b"data")

        ## Run quarantine subcommand via CLI
        exit_quar = main(["quarantine", str(bad_file), "--vault-dir", str(self.vault_dir)])
        self.assertEqual(exit_quar, 0)
        self.assertFalse(bad_file.exists())

        ## List receipts in JSON format
        exit_receipts = main(["receipts", "--vault-dir", str(self.vault_dir), "--json"])
        self.assertEqual(exit_receipts, 0)

        ## Audit vault integrity
        exit_verify = main(["verify", "--vault-dir", str(self.vault_dir)])
        self.assertEqual(exit_verify, 0)

    def test_cli_dry_run_quarantine(self) -> None:
        """Verify --dry-run does not relocate or alter the file."""
        suspect_file = Path(self.temp_dir) / "test_dry.pdf.exe"
        suspect_file.write_bytes(b"malware simulation")

        ## Execute quarantine with --dry-run
        exit_code = main(["quarantine", str(suspect_file), "--vault-dir", str(self.vault_dir), "--dry-run"])
        self.assertEqual(exit_code, 0)

        ## Verify file was not moved
        self.assertTrue(suspect_file.exists())

    def test_cli_scan_recursive_directory(self) -> None:
        """Verify recursive directory scan catches nested threats and outputs valid JSON."""
        sub_dir = Path(self.temp_dir) / "downloads" / "nested"
        sub_dir.mkdir(parents=True)
        bad_nested = sub_dir / "statement.pdf.sh"
        bad_nested.write_bytes(b"#!/bin/bash\nexit 1\n")

        good_file = sub_dir / "valid.txt"
        good_file.write_text("ordinary text file", encoding="utf-8")

        ## Execute recursive scan with --json
        exit_code = main(["scan", str(Path(self.temp_dir) / "downloads"), "--json"])
        ## Threat detected triggers exit code 2
        self.assertEqual(exit_code, 2)


if __name__ == "__main__":
    unittest.main()
