"""Regression tests for magic-number heuristics (plaintext fallback)."""

import unittest

from sentinel.magic import FileTypeCategory, MagicInspector


class TestPlaintextFallback(unittest.TestCase):
    """The plaintext heuristic must classify non-UTF-8 text without any dead branch."""

    def test_latin1_text_is_plain_text(self):
        """Bytes that are invalid UTF-8 but contain no NUL decode via latin-1 as plain text."""
        result = MagicInspector.inspect_bytes(b"caf\xe9 au lait, no nul bytes here\n")
        self.assertEqual(result.mime_type, "text/plain")
        self.assertEqual(result.category, FileTypeCategory.TEXT)


if __name__ == "__main__":
    unittest.main()
