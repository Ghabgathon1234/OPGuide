"""Local administrator recovery; intentionally has no HTTP endpoint.

Run inside the deployed Railway container with its persistent volume mounted.
Authorization is provided by Railway's container access controls.
"""
from contextlib import closing
from getpass import getpass, GetPassWarning
import os
from pathlib import Path
import sqlite3
import sys
import warnings

from argon2 import PasswordHasher


def reset_password(path: str, password: str) -> None:
    if not 6 <= len(password) <= 256:
        raise ValueError('Password must contain 6–256 characters.')
    # mode=rw refuses to create a database when the volume/path is wrong.
    uri = Path(path).resolve().as_uri() + '?mode=rw'
    hashed = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1).hash(password)
    with closing(sqlite3.connect(uri, uri=True, timeout=30)) as db:
        with db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT COUNT(*) FROM auth').fetchone()[0] != 1:
                raise ValueError('Expected exactly one shared password; database left unchanged.')
            changed = db.execute('UPDATE auth SET hash=?, must_change=0 WHERE id=1', (hashed,))
            if changed.rowcount != 1:
                raise ValueError('Shared password record not found; database left unchanged.')
            db.execute('DELETE FROM attempts')


def main() -> int:
    if len(sys.argv) != 1:
        print('Run without arguments; passwords must not appear in shell history.', file=sys.stderr)
        return 1
    if not sys.stdin.isatty():
        print('An interactive terminal is required. Connect with railway ssh.', file=sys.stderr)
        return 1
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', GetPassWarning)
            password = getpass('New shared password (6–256 characters): ')
            confirmation = getpass('Repeat new password: ')
        if password != confirmation:
            raise ValueError('Passwords do not match; nothing changed.')
        reset_password(os.getenv('AUTH_DB_PATH', '/data/auth.sqlite3'), password)
    except (ValueError, sqlite3.Error, OSError, GetPassWarning) as error:
        print(f'Reset failed: {error}', file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print('\nReset cancelled; nothing changed.', file=sys.stderr)
        return 1
    print('Shared password reset. All publishers must now use the new password. No restart required.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
