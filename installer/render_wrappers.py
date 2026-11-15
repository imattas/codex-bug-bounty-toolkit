"""Regenerate reviewed native wrappers after editing the shared ZIP bootstrap."""
from pathlib import Path


def render(root: Path) -> None:
    code = (root / 'installer/archive_bootstrap.py').read_text(encoding='utf-8').rstrip()
    for name in ('install.ps1', 'install.sh'):
        template = (root / 'installer/templates' / (name + '.in')).read_text(encoding='utf-8')
        (root / name).write_text(template.replace('__EMBEDDED_BOOTSTRAP__', code), encoding='utf-8', newline='\n')


if __name__ == '__main__':
    render(Path(__file__).resolve().parents[1])
