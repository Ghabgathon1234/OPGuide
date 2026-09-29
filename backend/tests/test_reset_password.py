import sqlite3
from unittest.mock import patch

import pytest
from app import AuthStore, APIError, HASHER
from reset_password import reset_password, main


def test_reset_replaces_only_password_and_clears_lockout(tmp_path):
    path = str(tmp_path / 'auth.sqlite3')
    auth = AuthStore(path, HASHER.hash('old-password'))
    with auth.connect() as db:
        db.execute('INSERT INTO attempts VALUES (9999999999)')
        db.execute('CREATE TABLE unrelated (value TEXT)')
        db.execute("INSERT INTO unrelated VALUES ('keep')")
    reset_password(path, 'abc123')
    auth.authenticate('abc123')
    with auth.connect() as db:
        assert db.execute('SELECT COUNT(*) FROM auth').fetchone()[0] == 1
        assert db.execute('SELECT COUNT(*) FROM attempts').fetchone()[0] == 0
        assert db.execute('SELECT value FROM unrelated').fetchone()[0] == 'keep'
    with pytest.raises(APIError):
        auth.authenticate('old-password')
    restarted = AuthStore(path, HASHER.hash('652512'))
    restarted.authenticate('abc123')
    with pytest.raises(APIError):
        restarted.authenticate('652512')


def test_missing_db_is_not_created(tmp_path):
    path = tmp_path / 'missing.sqlite3'
    with pytest.raises(sqlite3.OperationalError):
        reset_password(str(path), 'abc123')
    assert not path.exists()


@pytest.mark.parametrize('password', ['short', 'x' * 257])
def test_invalid_length_leaves_password_unchanged(tmp_path, password):
    path = str(tmp_path / 'auth.sqlite3')
    auth = AuthStore(path, HASHER.hash('old-password'))
    with pytest.raises(ValueError):
        reset_password(path, password)
    auth.authenticate('old-password')


def test_failed_transaction_rolls_back(tmp_path):
    path = str(tmp_path / 'auth.sqlite3')
    auth = AuthStore(path, HASHER.hash('old-password'))
    with auth.connect() as db:
        before = db.execute('SELECT hash FROM auth').fetchone()[0]
        db.execute('DROP TABLE attempts')
    with pytest.raises(sqlite3.OperationalError):
        reset_password(path, 'abc123')
    with auth.connect() as db:
        assert db.execute('SELECT hash FROM auth').fetchone()[0] == before


def test_confirmation_mismatch_never_writes(capsys):
    with patch('sys.argv', ['reset_password.py']), patch('sys.stdin.isatty', return_value=True), patch('reset_password.getpass', side_effect=['abc123', 'abcdef']), patch('reset_password.reset_password') as reset:
        assert main() == 1
        reset.assert_not_called()
    assert 'do not match' in capsys.readouterr().err


def test_cli_does_not_echo_password(capsys):
    with patch('sys.argv', ['reset_password.py']), patch('sys.stdin.isatty', return_value=True), patch('reset_password.getpass', return_value='secret-new-password'), patch('reset_password.reset_password') as reset:
        assert main() == 0
        reset.assert_called_once()
    output = capsys.readouterr()
    assert 'secret-new-password' not in output.out + output.err
