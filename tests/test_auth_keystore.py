"""Tests for SQLiteKeyStore CRUD."""
import os
import sqlite3
import tempfile

import pytest

from illumio_mcp.auth.crypto import EnvelopeCipher, generate_kek
from illumio_mcp.auth.keystore import SQLiteKeyStore
from illumio_mcp.pce import PCECredentials


@pytest.fixture
def keystore(tmp_path):
    db_path = str(tmp_path / "keys.db")
    cipher = EnvelopeCipher(generate_kek())
    return SQLiteKeyStore(db_path=db_path, cipher=cipher)


def _creds():
    return PCECredentials(
        host="https://pce.example",
        port=8443,
        org_id=1,
        api_key="api_key_xyz",
        api_secret="api_secret_abc",
        tls_verify=True,
    )


def test_get_returns_none_for_unknown_user(keystore):
    assert keystore.get(sub="nobody", iss="https://idp.test/o") is None


def test_put_then_get_round_trip(keystore):
    creds = _creds()
    keystore.put(sub="alice", iss="https://idp.test/o", creds=creds)
    fetched = keystore.get(sub="alice", iss="https://idp.test/o")
    assert fetched == creds


def test_put_overwrites_existing(keystore):
    keystore.put(sub="alice", iss="https://idp.test/o", creds=_creds())
    new_creds = PCECredentials(
        host="https://pce.example",
        port=8443,
        org_id=2,                    # different org
        api_key="new_key",
        api_secret="new_secret",
        tls_verify=True,
    )
    keystore.put(sub="alice", iss="https://idp.test/o", creds=new_creds)
    fetched = keystore.get(sub="alice", iss="https://idp.test/o")
    assert fetched == new_creds
    # Only one row exists for this (sub, iss)
    assert keystore.count_for(sub="alice", iss="https://idp.test/o") == 1


def test_delete_removes_row(keystore):
    keystore.put(sub="alice", iss="https://idp.test/o", creds=_creds())
    assert keystore.delete(sub="alice", iss="https://idp.test/o") is True
    assert keystore.get(sub="alice", iss="https://idp.test/o") is None


def test_delete_missing_returns_false(keystore):
    assert keystore.delete(sub="ghost", iss="https://idp.test/o") is False


def test_users_with_same_sub_different_iss_are_isolated(keystore):
    keystore.put(sub="alice", iss="https://idp1.test/o", creds=_creds())
    keystore.put(sub="alice", iss="https://idp2.test/o", creds=PCECredentials(
        host="https://other.pce", port=443, org_id=99, api_key="k", api_secret="s",
    ))
    assert keystore.get(sub="alice", iss="https://idp1.test/o").org_id == 1
    assert keystore.get(sub="alice", iss="https://idp2.test/o").org_id == 99


def test_decryption_failure_raises_on_get(keystore, tmp_path):
    """Tamper with a stored row and verify the keystore raises on read."""
    keystore.put(sub="alice", iss="https://idp.test/o", creds=_creds())
    db_path = keystore.db_path
    with sqlite3.connect(db_path) as con:
        # Flip a byte in api_secret_enc
        row = con.execute("SELECT api_secret_enc FROM user_pce_credentials WHERE sub='alice'").fetchone()
        tampered = bytearray(row[0])
        tampered[-3] ^= 0x01
        con.execute("UPDATE user_pce_credentials SET api_secret_enc=? WHERE sub='alice'", (bytes(tampered),))
    with pytest.raises(Exception):
        keystore.get(sub="alice", iss="https://idp.test/o")


def test_db_file_created_with_sane_perms(keystore):
    """The SQLite DB should not be world-readable."""
    mode = os.stat(keystore.db_path).st_mode & 0o777
    assert mode & 0o077 == 0, f"db file is world/group-readable: {oct(mode)}"
