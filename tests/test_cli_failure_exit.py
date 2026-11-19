"""Regression test: `quarantine` must exit nonzero when a file cannot be processed."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sentinel import cli


class TestQuarantineFailureExit(unittest.TestCase):
    """handle_quarantine used to return 0 even if every file failed."""

    def test_failed_file_gives_nonzero_exit(self):
        """If analysis raises for a file the command reports it and exits 1."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "bad.sh"
            target.write_bytes(b"#!/bin/bash\nrm -rf /\n")
            vault = Path(tmp) / "vault"
            err = io.StringIO()
            with mock.patch.object(cli.ThreatEngine, "analyze_file", side_effect=OSError("boom")), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                code = cli.main(["quarantine", str(target), "--vault-dir", str(vault)])
            self.assertEqual(code, 1)
            self.assertIn("could not be processed", err.getvalue())


if __name__ == "__main__":
    unittest.main()
