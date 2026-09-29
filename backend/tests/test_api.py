import hashlib
import io
import json
from datetime import datetime, timezone

import pytest
from google.api_core.exceptions import PreconditionFailed
from app import create_app, HASHER

PASSWORD = 'a long private test password'

class Blob:
    def __init__(self, bucket, name):
        self.bucket, self.name = bucket, name
        self.metadata, self.cache_control = None, None
        self.generation, self.size, self.updated = 0, 0, datetime.now(timezone.utc)

    def save(self, data, if_generation_match):
        old = self.bucket.objects.get(self.name)
        if (old.generation if old else 0) != if_generation_match:
            raise PreconditionFailed('generation mismatch')
        if self.name == self.bucket.fail_path:
            raise RuntimeError('injected storage failure')
        self.generation = (old.generation if old else 0) + 1
        self.data = data.encode() if isinstance(data, str) else data
        self.size = len(data)
        self.bucket.objects[self.name] = self
        self.bucket.writes.append(self.name)

    def upload_from_file(self, stream, *, size, content_type, if_generation_match, timeout):
        self.save(stream.read(), if_generation_match)

    def upload_from_string(self, data, *, content_type, if_generation_match, timeout):
        self.save(data, if_generation_match)

    def delete(self, *, if_generation_match, timeout):
        if self.name == self.bucket.fail_path:
            raise RuntimeError('injected delete failure')
        if self.bucket.objects[self.name].generation != if_generation_match:
            raise PreconditionFailed('generation mismatch')
        del self.bucket.objects[self.name]

    def download_as_bytes(self, *, start, end, if_generation_match, timeout):
        assert self.name == 'operator-guide/latest.json', 'Only legacy manifest may be read'
        assert start == 0 and end == 16384
        assert self.generation == if_generation_match
        self.bucket.reads.append(self.name)
        return self.data[start:end + 1]

    def download_as_text(self, **kwargs):
        raise AssertionError('Downloads are forbidden')

class Bucket:
    name = 'test-bucket'
    def __init__(self):
        self.objects, self.writes, self.fail_path = {}, [], None
        self.reads = []
    def get_blob(self, name, **kwargs):
        return self.objects.get(name)
    def blob(self, name):
        return Blob(self, name)
    def list_blobs(self, prefix, **kwargs):
        return [v for k, v in self.objects.items() if k.startswith(prefix)]

@pytest.fixture
def setup(tmp_path):
    bucket = Bucket()
    config = dict(TESTING=True, AUTH_DB_PATH=str(tmp_path / 'auth.db'),
                  INITIAL_PASSWORD_HASH=HASHER.hash('652512'))
    app = create_app(config, bucket)
    client = app.test_client()
    return client, bucket, config

def activate(client):
    response = client.post('/api/auth/password', json=dict(password='652512', new_password=PASSWORD))
    assert response.status_code == 200

def release(version='3', index=True):
    pdf = b'%PDF-1.7\n' + b'x' * 1100
    manifest = dict(version=version, documentPath=f'operator-guide/documents/{version}.pdf',
                    sha256=hashlib.sha256(pdf).hexdigest(), sizeBytes=len(pdf))
    files = {'password': PASSWORD, 'pdf': (io.BytesIO(pdf), 'guide.pdf')}
    if index:
        raw = json.dumps(dict(version=version, pageCount=1, entries=[dict(page=1, title='Topic')])).encode()
        manifest.update(indexPath=f'operator-guide/documents/{version}.index.json', indexSha256=hashlib.sha256(raw).hexdigest())
        files['index'] = (io.BytesIO(raw), 'index.json')
    files['manifest'] = (io.BytesIO(json.dumps(manifest).encode()), 'latest.json')
    return files

def test_initial_password_works_until_changed(setup):
    c, b, _ = setup
    assert c.post('/api/files/list', json={'password': '652512'}).status_code == 200
    assert not c.post('/api/auth/check', json={'password': '652512'}).json['must_change_password']
    files = release()
    files['password'] = '652512'
    assert c.post('/api/releases', data=files).status_code == 201
    assert c.post('/api/files/delete', json=dict(password='652512', paths=['operator-guide/latest.json'])).status_code == 200
    activate(c)
    assert c.post('/api/files/list', json={'password': '652512'}).status_code == 401
    assert c.post('/api/files/list', json={'password': PASSWORD}).status_code == 200


def test_rotation_persists_and_old_password_fails(setup):
    c, b, config = setup
    activate(c)
    new = 'another long password for testing'
    assert c.post('/api/auth/password', json=dict(password=PASSWORD, new_password=new)).status_code == 200
    restarted = create_app(config, b).test_client()
    assert restarted.post('/api/files/list', json={'password': PASSWORD}).status_code == 401
    assert restarted.post('/api/files/list', json={'password': new}).status_code == 200

def test_listing_and_publish_no_downloads(setup):
    c, b, _ = setup
    activate(c)
    assert c.post('/api/releases', data=release()).status_code == 201
    assert b.writes[-1] == 'operator-guide/latest.json'
    result = c.post('/api/files/list', json={'password': PASSWORD}).json
    assert result['manifest']['version'] == '3'
    assert b.reads == []
    assert len(result['objects']) == 3
    assert result['objects'][0]['version'] == '3'
    assert c.get('/api/files/operator-guide/documents/3.pdf').status_code == 404
    assert c.get('/api/files/list').status_code == 405

def test_manifest_tampering_and_traversal_rejected(setup):
    c, b, _ = setup
    activate(c)
    files = release()
    data = json.loads(files['manifest'][0].getvalue())
    data['documentPath'] = '../private.pdf'
    files['manifest'] = (io.BytesIO(json.dumps(data).encode()), 'latest.json')
    assert c.post('/api/releases', data=files).status_code == 400
    assert c.post('/api/files/delete', json=dict(password=PASSWORD, paths=['other-bucket/secrets'])).status_code == 400
    assert not b.writes

def test_failed_index_never_publishes_pointer(setup):
    c, b, _ = setup
    activate(c)
    b.fail_path = 'operator-guide/documents/3.index.json'
    assert c.post('/api/releases', data=release()).status_code == 502
    assert 'operator-guide/latest.json' not in b.objects
    b.fail_path = None
    assert c.post('/api/releases', data=release()).status_code == 409
    assert c.post('/api/files/delete', json=dict(password=PASSWORD, paths=['operator-guide/documents/3.pdf'])).status_code == 200
    assert c.post('/api/releases', data=release()).status_code == 201

def test_live_protection_and_unpublish(setup):
    c, b, _ = setup
    activate(c)
    assert c.post('/api/releases', data=release()).status_code == 201
    assert c.post('/api/releases', data=release()).status_code == 409
    assert c.post('/api/files/delete', json=dict(password=PASSWORD, paths=['operator-guide/documents/3.pdf'])).status_code == 409
    assert c.post('/api/files/delete', json=dict(password=PASSWORD, paths=['operator-guide/latest.json', 'operator-guide/documents/3.pdf', 'operator-guide/documents/3.index.json'])).status_code == 200
    assert not b.objects

def test_legacy_metadata_is_explicit_and_safe(setup):
    c, b, _ = setup
    activate(c)
    blob = b.blob('operator-guide/latest.json')
    blob.save('{}', 0)
    result = c.post('/api/files/list', json={'password': PASSWORD}).json
    assert result['legacy_manifest'] is True and result['manifest'] is None
    assert c.post('/api/files/delete', json=dict(password=PASSWORD, paths=['operator-guide/documents/2.pdf'])).status_code == 409

def test_rate_limit_persists_after_restart(setup):
    c, b, config = setup
    for _ in range(20):
        assert c.post('/api/auth/check', json={'password': 'wrong'}).status_code == 401
    c = create_app(config, b).test_client()
    assert c.post('/api/auth/check', json={'password': 'wrong'}).status_code == 429

def test_unauthorized_operations(setup):
    c, b, _ = setup
    for endpoint in ('/api/files/list', '/api/files/delete', '/api/auth/password'):
        assert c.post(endpoint, json={'password': 'wrong', 'new_password': PASSWORD}).status_code == 401
    assert c.post('/api/releases', data=release()).status_code == 401
    assert not b.writes

def test_limits_and_invalid_index(setup):
    c, b, _ = setup
    activate(c)
    files = release()
    files['index'] = (io.BytesIO(b'{"version":"3","pageCount":1,"entries":[{"page":2,"title":"x"}]}'), 'index.json')
    assert c.post('/api/releases', data=files).status_code == 400
    c.application.config['MAX_CONTENT_LENGTH'] = 1024
    assert c.post('/api/releases', data=release()).status_code == 413
    assert not b.writes

def test_delete_partial_failure_is_reported(setup):
    c, b, _ = setup
    activate(c)
    assert c.post('/api/releases', data=release()).status_code == 201
    b.fail_path = 'operator-guide/documents/3.pdf'
    result = c.post('/api/files/delete', json=dict(password=PASSWORD, paths=['operator-guide/latest.json', b.fail_path]))
    assert result.status_code == 502
    assert result.json['deleted'] == ['operator-guide/latest.json']
    assert b.fail_path in b.objects

@pytest.mark.parametrize('length,expected', [(5, 400), (6, 200), (256, 200), (257, 400)])
def test_password_length_boundaries(setup, length, expected):
    c, _, _ = setup
    activate(c)
    new = 'a' * length
    response = c.post('/api/auth/password', json=dict(password=PASSWORD, new_password=new))
    assert response.status_code == expected
    if expected == 200:
        assert c.post('/api/files/list', json={'password': new}).status_code == 200
        assert c.post('/api/auth/check', json={'password': PASSWORD}).status_code == 401
    else:
        assert c.post('/api/auth/check', json={'password': PASSWORD}).status_code == 200


def test_initial_setup_accepts_six_characters(setup):
    c, _, _ = setup
    response = c.post('/api/auth/password', json=dict(password='652512', new_password='abc123'))
    assert response.status_code == 200
    assert c.post('/api/files/list', json={'password': 'abc123'}).status_code == 200


def test_migration_preserves_single_existing_password(setup):
    import sqlite3
    c, b, config = setup
    activate(c)
    with sqlite3.connect(config['AUTH_DB_PATH']) as db:
        db.execute('UPDATE auth SET must_change=1 WHERE id=1')
    restarted = create_app(config, b).test_client()
    assert restarted.post('/api/files/list', json={'password': PASSWORD}).status_code == 200
    assert restarted.post('/api/files/list', json={'password': '652512'}).status_code == 401
    assert restarted.post('/api/auth/password', json=dict(password='wrong-old', new_password='abc123')).status_code == 401
    assert restarted.post('/api/files/list', json={'password': 'abc123'}).status_code == 401
    assert restarted.post('/api/files/list', json={'password': PASSWORD}).status_code == 200


def test_legacy_manifest_supplies_real_live_version_and_protects_pdf(setup):
    c, b, _ = setup
    activate(c)
    assert c.post('/api/releases', data=release('2')).status_code == 201
    b.objects['operator-guide/latest.json'].metadata = None
    response = c.post('/api/files/list', json={'password': PASSWORD})
    assert response.status_code == 200
    assert response.json['manifest']['version'] == '2'
    assert response.json['legacy_manifest'] is False
    assert b.reads == ['operator-guide/latest.json']
    assert c.post('/api/files/delete', json=dict(password=PASSWORD, paths=['operator-guide/documents/2.pdf'])).status_code == 409


def test_oversized_legacy_manifest_is_not_read(setup):
    c, b, _ = setup
    activate(c)
    b.blob('operator-guide/latest.json').save('x' * 16385, 0)
    response = c.post('/api/files/list', json={'password': PASSWORD})
    assert response.json['legacy_manifest'] is True
    assert b.reads == []


@pytest.mark.parametrize('candidate', ['1', '2', '2.0', '2.0.0', '02'])
def test_older_or_equal_release_never_changes_bucket(setup, candidate):
    c, b, _ = setup
    activate(c)
    assert c.post('/api/releases', data=release('2')).status_code == 201
    before = list(b.writes)
    result = c.post('/api/releases', data=release(candidate))
    assert result.status_code == 409
    assert 'higher than' in result.json['error']
    assert b.writes == before
    assert c.post('/api/files/list', json={'password': PASSWORD}).json['manifest']['version'] == '2'


def test_numeric_version_ordering_and_legacy_guard(setup):
    c, b, _ = setup
    activate(c)
    assert c.post('/api/releases', data=release('2.9')).status_code == 201
    b.objects['operator-guide/latest.json'].metadata = None
    assert c.post('/api/releases', data=release('2.8')).status_code == 409
    assert c.post('/api/releases', data=release('2.10')).status_code == 201


def test_unknown_live_version_blocks_publication(setup):
    c, b, _ = setup
    activate(c)
    b.blob('operator-guide/latest.json').save('{}', 0)
    before = list(b.writes)
    assert c.post('/api/releases', data=release('3')).status_code == 409
    assert b.writes == before
