# Quarantine Sentinel

A Python project for inspecting files and moving selected files into a quarantine vault, with receipts and a restore workflow. It uses file characteristics and rules to identify items for review.

## Getting started

From the repository root, use Python 3.9 or later:

```sh
python3 -m sentinel --help
python3 -m sentinel scan /path/to/file --json
```

The `scan` command accepts a file or directory. The CLI also offers `quarantine`, `receipts`, `receipt`, `verify` and `restore`; see each subcommand’s `--help` for options.

```sh
python3 -m sentinel quarantine /path/to/file --dry-run
python3 -m sentinel receipts
```

Quarantine moves selected files and changes their permissions; restore moves a payload to a destination. The quarantine dry run does not move payloads, but initializes the vault and may create its directories. Review the target, vault location, permissions and recovery process before use.

## Scope

File heuristics can miss threats or flag harmless files. A clean result is not proof that a file is safe. Receipts and hash checks can help investigate changes, but do not make evidence or storage immutable. Handle untrusted files carefully and validate results independently.

The repository includes [tests](tests/), runnable with `python3 -m unittest discover -s tests -v`. Test results apply only to the revision and environment tested.

## License

[MIT](LICENSE)
