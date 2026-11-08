"""
Comprehensive Unit Test Suite for Quarantine Sentinel.

Validates:
1. Binary Magic Byte Identification (ELF, PE, Mach-O, Shebangs, Zip, PDF, Images).
2. Streaming Cryptographic Hashing (SHA-256, SHA-512, MD5, Chunked Buffering).
3. Threat Detection Rules (Disguised Binaries, Double Extensions, Unicode RLO, Executable Bit Anomalies).
4. Atomic Vault Quarantine (Permission Neutralization to 0o000, Tamper-Evident Receipts, Indexing).
5. Safe Restoration and Vault Integrity Audits.
6. CLI Integration and Exit Codes.
"""

import hashlib
import json
import os
import shutil
import stat
import struct
import tempfile
import unittest
from pathlib import Path

from sentinel.cli import main
from sentinel.hasher import CryptoHasher
from sentinel.magic import FileTypeCategory, MagicInspector
from sentinel.rules import RiskLevel, ThreatEngine
from sentinel.vault import QuarantineVault


class TestMagicInspector(unittest.TestCase):
    """Test suite for binary header magic byte parsing."""

    def test_empty_payload(self) -> None:
        """Verify empty files are identified as zero-byte text."""
        result = MagicInspector.inspect_bytes(b"")
        self.assertEqual(result.mime_type, "application/x-empty")
        self.assertEqual(result.category, FileTypeCategory.TEXT)
        self.assertFalse(result.is_executable)

    def test_elf_binary_parsing(self) -> None:
        """Construct synthetic ELF64 Little-Endian binary header and verify parsing."""
        # \x7fELF + 2 (64-bit) + 1 (little-endian) + 1 (version) + 0 (SysV) + 8 zeros + e_type (2=exec)
        # Assemble 64-bit Little-Endian ELF executable header
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
        result = MagicInspector.inspect_bytes(elf_header)
        self.assertEqual(result.mime_type, "application/x-executable-elf")
        self.assertEqual(result.category, FileTypeCategory.EXECUTABLE)
        self.assertTrue(result.is_executable)
        self.assertEqual(result.details.get("bitness"), 64)
        self.assertEqual(result.details.get("endianness"), "little-endian")
        self.assertEqual(result.details.get("elf_type"), "Executable Binary")

    def test_pe_executable_parsing(self) -> None:
        """Construct synthetic Windows PE32+ (x64) executable header and verify parsing."""
        # MZ header with e_lfanew at 0x3C pointing to offset 0x80
        header = bytearray(b"\x00" * 256)
        header[0:2] = b"MZ"
        struct.pack_into("<I", header, 0x3C, 0x80)  # e_lfanew = 0x80
        # PE signature at 0x80: 'PE\0\0'
        header[0x80:0x84] = b"PE\x00\x00"
        # Machine type at 0x84: 0x8664 (AMD64)
        struct.pack_into("<H", header, 0x84, 0x8664)
        # Characteristics at 0x96: 0x0002 (EXECUTABLE_IMAGE)
        struct.pack_into("<H", header, 0x96, 0x0002)

        result = MagicInspector.inspect_bytes(bytes(header))
        self.assertEqual(result.mime_type, "application/x-dosexec")
        self.assertEqual(result.category, FileTypeCategory.EXECUTABLE)
        self.assertTrue(result.is_executable)
        self.assertIn("x86-64", str(result.details.get("machine")))

    def test_macho_binary_parsing(self) -> None:
        """Verify Mach-O 64-bit header detection."""
        macho_header = b"\xcf\xfa\xed\xfe" + b"\x00" * 32
        result = MagicInspector.inspect_bytes(macho_header)
        self.assertEqual(result.mime_type, "application/x-mach-binary")
        self.assertEqual(result.category, FileTypeCategory.EXECUTABLE)
        self.assertTrue(result.is_executable)
        self.assertEqual(result.details.get("bitness"), 64)

    def test_shebang_parsing(self) -> None:
        """Verify POSIX shebang scripts are recognized as executable scripts."""
        script_data = b"#!/bin/bash\necho 'hello world'\n"
        result = MagicInspector.inspect_bytes(script_data)
        self.assertEqual(result.mime_type, "text/x-shellscript")
        self.assertEqual(result.category, FileTypeCategory.SCRIPT)
        self.assertTrue(result.is_executable)
        self.assertEqual(result.details.get("interpreter"), "/bin/bash")

    def test_pdf_document_parsing(self) -> None:
        """Verify PDF document signature."""
        pdf_data = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n"
        result = MagicInspector.inspect_bytes(pdf_data)
        self.assertEqual(result.mime_type, "application/pdf")
        self.assertEqual(result.category, FileTypeCategory.DOCUMENT)
        self.assertFalse(result.is_executable)

    def test_image_formats_parsing(self) -> None:
        """Verify PNG and JPEG headers."""
        png_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        res_png = MagicInspector.inspect_bytes(png_data)
        self.assertEqual(res_png.mime_type, "image/png")
        self.assertEqual(res_png.category, FileTypeCategory.IMAGE)

        jpeg_data = b"\xff\xd8\xff\xe0\x00\x10JFIF"
        res_jpeg = MagicInspector.inspect_bytes(jpeg_data)
        self.assertEqual(res_jpeg.mime_type, "image/jpeg")
        self.assertEqual(res_jpeg.category, FileTypeCategory.IMAGE)

    def test_wasm_binary_parsing(self) -> None:
        """Verify WebAssembly binary header detection."""
        wasm_data = b"\x00asm\x01\x00\x00\x00"
        result = MagicInspector.inspect_bytes(wasm_data)
        self.assertEqual(result.mime_type, "application/wasm")
        self.assertEqual(result.category, FileTypeCategory.EXECUTABLE)
        self.assertTrue(result.is_executable)

    def test_tar_ustar_parsing(self) -> None:
        """Verify POSIX tar archive detection at offset 257."""
        tar_header = bytearray(b"\x00" * 512)
        tar_header[257:262] = b"ustar"
        result = MagicInspector.inspect_bytes(bytes(tar_header))
        self.assertEqual(result.mime_type, "application/x-tar")
        self.assertEqual(result.category, FileTypeCategory.ARCHIVE)

    def test_office_docx_parsing(self) -> None:
        """Verify modern Office DOCX detection inside ZIP container."""
        # Simulated ZIP header with [Content_Types].xml and word/
        mock_docx = b"PK\x03\x04" + b"\x00" * 20 + b"[Content_Types].xml" + b"word/document.xml"
        result = MagicInspector.inspect_bytes(mock_docx)
        self.assertIn("wordprocessingml", result.mime_type)
        self.assertEqual(result.category, FileTypeCategory.DOCUMENT)
        self.assertFalse(result.is_executable)


class TestCryptoHasher(unittest.TestCase):
    """Test suite for streaming cryptographic multi-hash calculations."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_streaming_hash_correctness(self) -> None:
        """Verify SHA-256, SHA-512, and MD5 match standard hashlib reference."""
        payload = b"Quarantine Sentinel High-Assurance Cryptographic Validation Payload" * 1000
        test_file = Path(self.temp_dir) / "sample.bin"
        test_file.write_bytes(payload)

        manifest = CryptoHasher.hash_file(test_file)

        self.assertEqual(manifest.sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(manifest.sha512, hashlib.sha512(payload).hexdigest())
        self.assertEqual(manifest.md5, hashlib.md5(payload).hexdigest())
        self.assertEqual(manifest.file_size_bytes, len(payload))
        self.assertTrue(manifest.formatted_size.endswith("KiB") or manifest.formatted_size.endswith("B"))

    def test_verify_integrity_helper(self) -> None:
        """Verify constant-time integrity verification method."""
        test_file = Path(self.temp_dir) / "verify.txt"
        test_file.write_text("Integrity Check Data", encoding="utf-8")

        correct_hash = hashlib.sha256(b"Integrity Check Data").hexdigest()
        self.assertTrue(CryptoHasher.verify_integrity(test_file, correct_hash))
        self.assertFalse(CryptoHasher.verify_integrity(test_file, "0" * 64))

    def test_multi_chunk_large_file(self) -> None:
        """Verify file exceeding buffer chunk size (64KB) hashes accurately."""
        # 160 KB payload (spans 3 chunks)
        large_payload = b"A" * 70000 + b"B" * 70000 + b"C" * 20000
        test_file = Path(self.temp_dir) / "large.dat"
        test_file.write_bytes(large_payload)

        manifest = CryptoHasher.hash_file(test_file)
        self.assertEqual(manifest.sha256, hashlib.sha256(large_payload).hexdigest())
        self.assertEqual(manifest.file_size_bytes, 160000)

    def test_hash_bytes(self) -> None:
        """Verify in-memory byte sequence hashing."""
        data = b"In-memory crypto test vector"
        manifest = CryptoHasher.hash_bytes(data)
        self.assertEqual(manifest.sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(manifest.file_size_bytes, len(data))


class TestThreatEngine(unittest.TestCase):
    """Test suite for threat detection rules and heuristics."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_disguised_elf_binary(self) -> None:
        """Detect an ELF binary disguised as 'quarterly_report.pdf'."""
        disguised_file = Path(self.temp_dir) / "quarterly_report.pdf"
        # Write valid ELF header
        elf_content = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 60
        disguised_file.write_bytes(elf_content)

        report = ThreatEngine.analyze_file(disguised_file)

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

        report = ThreatEngine.analyze_file(disguised_file)

        self.assertTrue(report.is_suspicious)
        self.assertEqual(report.risk_level, RiskLevel.CRITICAL)
        self.assertIn("RULE_DISGUISED_BINARY", [f.rule_id for f in report.findings])

    def test_double_extension_attack(self) -> None:
        """Detect double extension evasion tactic like 'invoice.pdf.exe'."""
        double_ext_file = Path(self.temp_dir) / "invoice.pdf.exe"
        double_ext_file.write_bytes(b"dummy payload")

        report = ThreatEngine.analyze_file(double_ext_file)

        self.assertTrue(report.is_suspicious)
        self.assertIn("RULE_DOUBLE_EXTENSION", [f.rule_id for f in report.findings])

    def test_unicode_rlo_attack(self) -> None:
        """Detect Right-To-Left Override (U+202E) attack disguised as PDF."""
        # Filename: 'report_\u202Efdp.exe'
        rlo_filename = "report_\u202Efdp.exe"
        rlo_file = Path(self.temp_dir) / rlo_filename
        rlo_file.write_bytes(b"dummy executable")

        report = ThreatEngine.analyze_file(rlo_file)

        self.assertTrue(report.is_suspicious)
        self.assertEqual(report.risk_level, RiskLevel.CRITICAL)
        self.assertIn("RULE_UNICODE_RLO_BIDI", [f.rule_id for f in report.findings])

    def test_unicode_zero_width_attack(self) -> None:
        """Detect zero-width space obfuscation (U+200B)."""
        zw_filename = "financial\u200Bsummary.pdf.exe"
        zw_file = Path(self.temp_dir) / zw_filename
        zw_file.write_bytes(b"dummy data")

        report = ThreatEngine.analyze_file(zw_file)

        self.assertTrue(report.is_suspicious)
        self.assertIn("RULE_UNICODE_ZERO_WIDTH", [f.rule_id for f in report.findings])

    def test_posix_exec_bit_anomaly_on_pdf(self) -> None:
        """Detect POSIX executable permission bits (0o755) set on an ordinary PDF."""
        doc_file = Path(self.temp_dir) / "contract.pdf"
        doc_file.write_bytes(b"%PDF-1.5 legitimate pdf data")
        os.chmod(doc_file, 0o755)  # Dangerous: executable bit on document

        report = ThreatEngine.analyze_file(doc_file)

        self.assertIn("RULE_EXEC_BIT_ANOMALY", [f.rule_id for f in report.findings])

    def test_shebang_in_text_file(self) -> None:
        """Detect executable shebang hidden in .txt file."""
        script_in_txt = Path(self.temp_dir) / "notes.txt"
        script_in_txt.write_bytes(b"#!/bin/bash\nrm -rf /tmp/data\n")

        report = ThreatEngine.analyze_file(script_in_txt)

        self.assertIn("RULE_SHEBANG_CAMOUFLAGE", [f.rule_id for f in report.findings])

    def test_clean_file_is_safe(self) -> None:
        """Verify standard legitimate PDF without +x is evaluated as SAFE."""
        clean_file = Path(self.temp_dir) / "handbook.pdf"
        clean_file.write_bytes(b"%PDF-1.7 legitimate documentation body")
        os.chmod(clean_file, 0o644)

        report = ThreatEngine.analyze_file(clean_file)

        self.assertFalse(report.is_suspicious)
        self.assertEqual(report.risk_level, RiskLevel.SAFE)
        self.assertEqual(report.risk_score, 0)
        self.assertEqual(len(report.findings), 0)


class TestQuarantineVault(unittest.TestCase):
    """Test suite for quarantine vault isolation, permission stripping, and audit receipts."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.vault_dir = Path(self.temp_dir) / "vault"
        self.vault = QuarantineVault(vault_dir=self.vault_dir)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_quarantine_isolation_and_permission_stripping(self) -> None:
        """Verify file is relocated, neutralized with mode 0o000, and receipt created."""
        suspect_file = Path(self.temp_dir) / "malicious.pdf"
        suspect_file.write_bytes(b"\x7fELF" + b"\x00" * 100)
        os.chmod(suspect_file, 0o755)

        receipt = self.vault.quarantine(suspect_file)

        # Source file should be gone
        self.assertFalse(suspect_file.exists())

        # Payload in vault must exist
        item_dir = self.vault.payloads_dir / receipt.quarantine_id
        payload_path = item_dir / "payload.bin"
        self.assertTrue(payload_path.exists())

        # Verify permission lockdown (mode 0o000)
        payload_mode = stat.S_IMODE(payload_path.stat().st_mode)
        self.assertEqual(payload_mode, 0o000)

        # Verify receipt contents
        receipt_file = item_dir / "receipt.json"
        self.assertTrue(receipt_file.exists())
        self.assertEqual(receipt.original_filename, "malicious.pdf")
        self.assertEqual(receipt.original_mode_octal, "0o755")
        self.assertEqual(receipt.status, "QUARANTINED")

        # Verify vault index updated
        records = self.vault.list_receipts()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["quarantine_id"], receipt.quarantine_id)

    def test_vault_integrity_and_tamper_detection(self) -> None:
        """Verify vault integrity audit detects payload modification."""
        suspect = Path(self.temp_dir) / "bad.docx.sh"
        suspect.write_bytes(b"echo 'malicious script'")

        receipt = self.vault.quarantine(suspect)

        # 1. Clean audit should pass
        audit_results = self.vault.verify_vault_integrity()
        self.assertEqual(len(audit_results), 1)
        self.assertTrue(audit_results[0]["receipt_valid"])
        self.assertTrue(audit_results[0]["payload_hash_valid"])

        # 2. Tamper with the payload
        payload_file = self.vault.payloads_dir / receipt.quarantine_id / "payload.bin"
        os.chmod(payload_file, 0o600)
        payload_file.write_bytes(b"tampered content")
        os.chmod(payload_file, 0o000)

        # 3. Audit should now fail!
        tampered_audit = self.vault.verify_vault_integrity()
        self.assertFalse(tampered_audit[0]["payload_hash_valid"])

    def test_safe_restoration(self) -> None:
        """Verify quarantined file can be restored with original permissions."""
        orig_file = Path(self.temp_dir) / "restore_me.pdf.exe"
        orig_content = b"Binary Payload Data 12345"
        orig_file.write_bytes(orig_content)
        os.chmod(orig_file, 0o755)

        receipt = self.vault.quarantine(orig_file)

        # Restore file to a custom target
        target_restore = Path(self.temp_dir) / "restored_file.bin"
        restored_path = self.vault.restore(receipt.quarantine_id, destination_path=target_restore)

        self.assertTrue(restored_path.exists())
        self.assertEqual(restored_path.read_bytes(), orig_content)
        # Verify permissions restored to 0o755
        self.assertEqual(stat.S_IMODE(restored_path.stat().st_mode), 0o755)

        # Verify receipt and index updated to RESTORED
        updated_receipt = self.vault.get_receipt(receipt.quarantine_id)
        self.assertEqual(updated_receipt.status, "RESTORED")


class TestCLIIntegration(unittest.TestCase):
    """Test suite for CLI subcommands."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.vault_dir = Path(self.temp_dir) / "cli_vault"

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_cli_scan_clean_and_dirty(self) -> None:
        """Verify CLI scan returns exit code 0 for clean and 2 for threat."""
        clean_file = Path(self.temp_dir) / "doc.pdf"
        clean_file.write_bytes(b"%PDF-1.4 sample pdf content")
        os.chmod(clean_file, 0o644)

        # Clean scan -> exit 0
        exit_code = main(["scan", str(clean_file)])
        self.assertEqual(exit_code, 0)

        # Disguised ELF -> exit 2
        bad_file = Path(self.temp_dir) / "invoice.pdf"
        bad_file.write_bytes(b"\x7fELF" + b"\x00" * 40)
        exit_code_dirty = main(["scan", str(bad_file)])
        self.assertEqual(exit_code_dirty, 2)

    def test_cli_quarantine_and_receipts(self) -> None:
        """Verify CLI quarantine isolates file and receipts can be listed."""
        bad_file = Path(self.temp_dir) / "fake.png.exe"
        bad_file.write_bytes(b"data")

        # Run quarantine via CLI
        exit_quar = main(["quarantine", str(bad_file), "--vault-dir", str(self.vault_dir)])
        self.assertEqual(exit_quar, 0)
        self.assertFalse(bad_file.exists())

        # List receipts via CLI
        exit_receipts = main(["receipts", "--vault-dir", str(self.vault_dir), "--json"])
        self.assertEqual(exit_receipts, 0)

        # Verify vault integrity via CLI
        exit_verify = main(["verify", "--vault-dir", str(self.vault_dir)])
        self.assertEqual(exit_verify, 0)

    def test_cli_dry_run_quarantine(self) -> None:
        """Verify --dry-run does not relocate or alter the file."""
        suspect_file = Path(self.temp_dir) / "test_dry.pdf.exe"
        suspect_file.write_bytes(b"malware simulation")

        exit_code = main(["quarantine", str(suspect_file), "--vault-dir", str(self.vault_dir), "--dry-run"])
        self.assertEqual(exit_code, 0)
        # File should still exist at original location
        self.assertTrue(suspect_file.exists())

    def test_cli_scan_recursive_directory(self) -> None:
        """Verify recursive directory scan catches nested threats and outputs valid JSON."""
        sub_dir = Path(self.temp_dir) / "downloads" / "nested"
        sub_dir.mkdir(parents=True)
        bad_nested = sub_dir / "statement.pdf.sh"
        bad_nested.write_bytes(b"#!/bin/bash\nexit 1\n")

        good_file = sub_dir / "valid.txt"
        good_file.write_text("ordinary text file", encoding="utf-8")

        exit_code = main(["scan", str(Path(self.temp_dir) / "downloads"), "--json"])
        # Exit code 2 because threat was detected
        self.assertEqual(exit_code, 2)


if __name__ == "__main__":
    unittest.main()
