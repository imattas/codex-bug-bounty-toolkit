"""MCP stdio launcher: inject local credentials only into the server environment."""
from __future__ import annotations

import os
import argparse
from pathlib import Path
import sys

from credential_store import CredentialError, load_credentials


def prepare_launch(directory: Path, *, python: str | None = None, environ=None, enable_writes: bool = False):
    env = dict(os.environ if environ is None else environ)
    # Persisted credentials take precedence; empty storage allows local tools without an account.
    env.pop('H1_USERNAME', None)
    env.pop('H1_API_TOKEN', None)
    identifier, token = load_credentials(directory)
    if identifier and token:
        env['H1_USERNAME'] = identifier
        env['H1_API_TOKEN'] = token
    env['H1_ENABLE_WRITES'] = 'true' if enable_writes else 'false'
    return [python or sys.executable, '-B', '-m', 'hackerone_mcp'], env


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--enable-writes', action='store_true', help='operator opt-in; server still requires prepare/review/commit authorization')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        command, env = prepare_launch(root / 'private', enable_writes=args.enable_writes)
        # The process and its standard streams belong to the MCP client; never print to stdout.
        os.execve(command[0], command, env)
    except (CredentialError, OSError):
        print('HackerOne launcher could not load credentials or start its Python environment.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
