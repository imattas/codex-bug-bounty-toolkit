"""Cross-platform test entry point that stops on the first failing suite."""
from pathlib import Path
import subprocess
import sys


def run_commands(commands, *, cwd=None):
    for command in commands:
        subprocess.run(command,cwd=cwd,check=True)


def main():
    root=Path(__file__).resolve().parents[1]
    commands=[[sys.executable,"-B","-m","unittest","discover","-s",path,"-v"] for path in ("bug-bounty/tests","hackerone-mcp/tests","installer/tests","tools")]
    try: run_commands(commands,cwd=root)
    except subprocess.CalledProcessError as exc: return exc.returncode or 1
    return 0


if __name__=="__main__": raise SystemExit(main())
