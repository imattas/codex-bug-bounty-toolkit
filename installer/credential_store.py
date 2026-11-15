"""Private local credentials. Never accept credential values on the command line."""
from __future__ import annotations

import base64
import csv
import ctypes
from ctypes import wintypes
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile


class CredentialError(RuntimeError):
    pass


def is_redirect(path: Path) -> bool:
    """Include Windows junctions/reparse points on Python 3.11, not just symlinks."""
    try:
        info = Path(path).lstat()
        return Path(path).is_symlink() or bool(getattr(info, 'st_file_attributes', 0) & 0x400)
    except FileNotFoundError:
        return False


def validate_private_path(path: Path) -> None:
    if any(is_redirect(part) for part in (Path(path), *Path(path).parents)):
        raise CredentialError('Private paths must not traverse symbolic links, junctions or reparse points.')


def _current_user_sid() -> str:
    result = subprocess.run(['whoami', '/user', '/fo', 'csv', '/nh'],
                            capture_output=True, text=True, check=True)
    sid = next(csv.reader(io.StringIO(result.stdout.strip())))[-1]
    if not sid.startswith('S-1-') or any(c not in 'S-0123456789' for c in sid):
        raise CredentialError('Could not identify the current Windows user.')
    return sid


def _windows_owner_allowed(owner_sid: str, current_sid: str) -> bool:
    if owner_sid == current_sid:
        return True
    # Elevated Windows tokens may default new objects to the Administrators
    # group. Accept that owner only when this process actually has an enabled
    # administrator token; never accept arbitrary group or user owners.
    if owner_sid != 'S-1-5-32-544':
        return False
    shell = ctypes.WinDLL('shell32', use_last_error=True)
    check = shell.IsUserAnAdmin
    check.argtypes = []
    check.restype = wintypes.BOOL
    return bool(check())


def validate_directory_owner(directory: Path) -> None:
    """Validate a writable parent without changing its existing ACL or mode."""
    directory = Path(directory)
    validate_private_path(directory)
    if not directory.is_dir():
        raise CredentialError('The selected parent is not a directory.')
    if os.name != 'nt':
        if directory.stat().st_uid != os.getuid():
            raise CredentialError('The selected parent directory must be owned by the current user.')
        return
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    get_owner = advapi.GetNamedSecurityInfoW
    get_owner.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
                          ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_void_p,
                          ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    get_owner.restype = wintypes.DWORD
    stringify = advapi.ConvertSidToStringSidW
    stringify.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    stringify.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    sid, descriptor, text = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    if get_owner(str(directory), 1, 1, ctypes.byref(sid), None, None, None, ctypes.byref(descriptor)):
        raise CredentialError('Unable to inspect the selected parent directory owner.')
    try:
        if not stringify(sid, ctypes.byref(text)):
            raise CredentialError('Unable to inspect the selected parent directory owner.')
        if not _windows_owner_allowed(ctypes.wstring_at(text), _current_user_sid()):
            raise CredentialError('The selected parent directory must be owned by the current user.')
    finally:
        if text:
            kernel.LocalFree(text)
        kernel.LocalFree(descriptor)


def ensure_directory(directory: Path) -> None:
    """Create missing parents, preserving permissions on every existing directory."""
    directory = Path(directory)
    validate_private_path(directory)
    existing = directory
    while not existing.exists():
        existing = existing.parent
    validate_directory_owner(existing)
    directory.mkdir(mode=0o755, parents=True, exist_ok=True)
    validate_directory_owner(directory)


def secure_path(path: Path, *, directory: bool = False) -> None:
    """Use a protected current-user/SYSTEM DACL on Windows, 0700/0600 elsewhere."""
    path = Path(path)
    validate_private_path(path)
    if os.name != 'nt':
        os.chmod(path, 0o700 if directory else 0o600)
        if path.stat().st_uid != os.getuid():
            raise CredentialError('Private storage must be owned by the current user.')
        return
    # SID rather than a localized/domain account name. No credential data is passed.
    sid = _current_user_sid()
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    convert.restype = wintypes.BOOL
    apply = advapi.SetFileSecurityW
    apply.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    apply.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    descriptor = ctypes.c_void_p()
    inheritance = 'OICI' if directory else ''
    sddl = f'D:P(A;{inheritance};FA;;;{sid})(A;{inheritance};FA;;;SY)'
    if not convert(sddl, 1, ctypes.byref(descriptor), None):
        raise CredentialError('Unable to construct private Windows permissions.')
    try:
        if not apply(str(path.resolve()), 0x80000004, descriptor):
            raise CredentialError('Unable to restrict Windows permissions.')
    finally:
        kernel.LocalFree(descriptor)


def private_directory(directory: Path) -> None:
    directory = Path(directory)
    # Refuse symlink components, including a previously created target.
    validate_private_path(directory)
    ensure_directory(directory)
    secure_path(directory, directory=True)


def private_write(path: Path, data: bytes) -> None:
    path = Path(path)
    ensure_directory(path.parent)
    validate_private_path(path)
    fd, temporary = tempfile.mkstemp(prefix='.private-', dir=path.parent)
    temp = Path(temporary)
    try:
        secure_path(temp)
        with os.fdopen(fd, 'wb') as stream:
            fd = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        secure_path(path)
    finally:
        if fd != -1:
            os.close(fd)
        temp.unlink(missing_ok=True)


def _dpapi(data: bytes, *, decrypt: bool = False) -> bytes:
    class Blob(ctypes.Structure):
        _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_ubyte))]
    buffer = ctypes.create_string_buffer(data)
    source = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    output = Blob()
    crypt = ctypes.WinDLL('crypt32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    if decrypt:
        function = crypt.CryptUnprotectData
        function.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
                             ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
        ok = function(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(output))
    else:
        function = crypt.CryptProtectData
        function.argtypes = [ctypes.POINTER(Blob), wintypes.LPCWSTR, ctypes.c_void_p,
                             ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
        ok = function(ctypes.byref(source), 'Bug bounty toolkit credentials', None, None, None, 1,
                      ctypes.byref(output))
    if not ok:
        raise CredentialError('Windows DPAPI failed for the current user.')
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        kernel.LocalFree(output.pbData)


def keyring_available() -> bool:
    try:
        import keyring
        backend = keyring.get_keyring()
        trusted = ('keyring.backends.windows', 'keyring.backends.macos',
                   'keyring.backends.secretservice', 'keyring.backends.kwallet', 'keyring.backends.libsecret')
        candidates = list(backend.backends) if type(backend).__module__.lower() == 'keyring.backends.chainer' else [backend]
        for candidate in candidates:
            if type(candidate).__module__.lower().startswith(trusted) and candidate.priority > 0:
                keyring.set_keyring(candidate)
                return True
        return False
    except Exception:
        return False


def preferred_backend() -> str:
    return 'dpapi' if os.name == 'nt' else ('keyring' if keyring_available() else 'file')


def save_credentials(directory: Path, identifier: str, token: str, *, allow_plaintext: bool = False,
                     backend: str | None = None) -> None:
    if not identifier.strip() or not token.strip() or '\x00' in identifier + token:
        raise CredentialError('Identifier and token must be nonempty and contain no NUL characters.')
    backend = backend or preferred_backend()
    if backend == 'file' and not allow_plaintext:
        raise CredentialError('Plaintext credential storage requires explicit opt-in.')
    private_directory(directory)
    payload = json.dumps({'identifier': identifier, 'token': token}).encode('utf-8')
    if backend == 'dpapi' and os.name == 'nt':
        record = {'backend': 'dpapi', 'blob': base64.b64encode(_dpapi(payload)).decode('ascii')}
    elif backend == 'keyring' and keyring_available():
        import keyring
        account = hashlib.sha256(str(Path(directory).resolve()).encode()).hexdigest()
        try:
            keyring.set_password('codex-bug-bounty-toolkit', account, payload.decode())
        except Exception:
            raise CredentialError('System keyring could not store credentials.') from None
        record = {'backend': 'keyring', 'service': 'codex-bug-bounty-toolkit', 'account': account}
    elif backend == 'file':
        record = {'backend': 'file', 'identifier': identifier, 'token': token}
    else:
        raise CredentialError('Requested credential backend is unavailable.')
    private_write(Path(directory) / 'credentials.json', json.dumps(record).encode('utf-8'))


def load_credentials(directory: Path) -> tuple[str, str]:
    path = Path(directory) / 'credentials.json'
    validate_private_path(path)
    if not path.exists():
        return '', ''
    try:
        if path.stat().st_size > 1024 * 1024:
            raise CredentialError('Credential file exceeds the expected size.')
        secure_path(path.parent, directory=True)
        secure_path(path)
        record = json.loads(path.read_text(encoding='utf-8'))
        if record['backend'] == 'dpapi' and os.name == 'nt':
            payload = json.loads(_dpapi(base64.b64decode(record['blob'], validate=True), decrypt=True))
        elif record['backend'] == 'keyring':
            import keyring
            payload = json.loads(keyring.get_password(record['service'], record['account']) or '{}')
        elif record['backend'] == 'file':
            payload = record
        else:
            raise CredentialError('Credential backend is unavailable.')
        identifier, token = payload['identifier'], payload['token']
        if not isinstance(identifier, str) or not isinstance(token, str):
            raise ValueError('invalid credential values')
        return identifier, token
    except Exception:
        # Do not echo source JSON or library exception messages, which may include secrets.
        raise CredentialError('Unable to load private credentials for this user.') from None
