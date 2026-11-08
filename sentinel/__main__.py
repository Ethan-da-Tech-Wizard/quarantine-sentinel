"""
Executable Module Entrypoint for Quarantine Sentinel.

Enables invocation via `python3 -m sentinel`.
"""

import sys
from sentinel.cli import main

if __name__ == "__main__":
    sys.exit(main())
