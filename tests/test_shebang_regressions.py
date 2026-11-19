"""Regression tests for shebang interpreter classification."""

import unittest

from sentinel.magic import MagicInspector


class TestShebangInterpreterMatching(unittest.TestCase):
    """Interpreter detection compares the program's basename exactly, not by substring."""

    def _desc(self, line: bytes) -> str:
        return MagicInspector.inspect_bytes(line + b"\necho hi\n").description

    def test_names_containing_sh_are_not_posix_shell(self):
        """'fish' and a directory called 'ashley' contain 'sh' but are not POSIX sh."""
        self.assertNotIn("POSIX", self._desc(b"#!/usr/bin/fish"))
        self.assertNotIn("POSIX", self._desc(b"#!/opt/ashley/tool"))

    def test_real_posix_shells_still_match(self):
        """sh and dash (including via env and with flags) remain POSIX Shell scripts."""
        self.assertIn("POSIX", self._desc(b"#!/bin/sh"))
        self.assertIn("POSIX", self._desc(b"#!/bin/dash -e"))
        self.assertIn("POSIX", self._desc(b"#!/usr/bin/env sh"))

    def test_other_interpreters_via_env(self):
        """env indirection is resolved to the real interpreter basename."""
        self.assertIn("Python", self._desc(b"#!/usr/bin/env python3"))
        self.assertIn("Bash", self._desc(b"#!/usr/bin/env bash"))


if __name__ == "__main__":
    unittest.main()
