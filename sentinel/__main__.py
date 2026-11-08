"""
Program: Quarantine Sentinel - Executable Module Entrypoint
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Enable direct module execution via `python3 -m sentinel` by routing command-line arguments to the CLI handler.
"""

## Standard system library import for process exit code management
import sys

## Import the CLI entrypoint dispatch function
from sentinel.cli import main

## Execute main() only when invoked directly as a Python module or executable script
if __name__ == "__main__":
    ## Pass control to the CLI parser and propagate return code to shell
    sys.exit(main())
