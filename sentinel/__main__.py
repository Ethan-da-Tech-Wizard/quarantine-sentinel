# Program: quarantine-sentinel - __main__.py
# Programmer: Ethan-da-Tech-Wizard (written with Claude, an AI assistant)
# Last Modified: 2026-11-18
# Purpose: Lets the package run with "python3 -m sentinel" by passing the command line to the CLI main() function and using its return value as the exit code.

"""
Enable direct module execution via `python3 -m sentinel` by routing command-line arguments to the CLI handler.
"""

## Standard system library import for process exit code management
import sys

## Import the CLI entrypoint dispatch function
from sentinel.cli import main

## Execute main() only when invoked directly as a Python module or executable script
if __name__ == "__main__":
    ## Pass control to the CLI parser and propagate return code to shell
    sys.exit(main())
