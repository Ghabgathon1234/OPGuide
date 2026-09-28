"""Publisher API. All bucket paths are selected/validated on the server.

Passwords travel in request bodies protected by TLS; only Argon2id hashes persist.
One Gunicorn worker / one Railway replica is required for the mutation lock.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
import re
import sqlite3
import secrets
import threading
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from flask import Flask, jsonify, request
from google.api_core.exceptions import NotFound, PreconditionFailed
from google.cloud import storage
from google.oauth2 import service_account
from werkzeug.exceptions import HTTPException

VERSION = re.compile(r"[0-9]{1,12}(?:\.[0-9]{1,12}){0,2}\Z")
HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1)


class APIError(Exception):
    def __init__(self, message, status=400):
        self.message, self.status = message, status


class AuthStore:
    def __init__(self, path, initial_hash, bootstrap_token):
        self.bootstrap_token = bootstrap_token
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS auth (id INTEGER PRIMARY KEY, hash TEXT NOT NULL, must_change INTEGER NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS attempts (at REAL NOT NULL)')
            if not db.execute('SELECT 1 FROM auth WHERE id=1').fetchone():
                if len(bootstrap_token) < 32:
                    raise RuntimeError('Set BOOTSTRAP_TOKEN to a random secret of at least 32 characters')
                if not initial_hash or not initial_hash.startswith('$argon2id$'):
                    raise RuntimeError('Set INITIAL_PASSWORD_HASH to an Argon2id hash before first startup')
                db.execute('INSERT INTO auth VALUES (1, ?, 1)', (initial_hash,))
        os.chmod(path, 0o600)

    def connect(self):
        return sqlite3.connect(self.path, timeout=30)

    def authenticate(self, password, allow_initial=False, new_password=None, bootstrap_token=None):
        if not isinstance(password, str) or not 1 <= len(password) <= 256:
            raise APIError('Password required', 401)
        # Global limit is persisted and cannot be bypassed with forged IP headers.
        # Count before Argon2; keep failed attempts for 15 minutes.
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM attempts WHERE at < ?', (time.time() - 900,))
            if db.execute('SELECT COUNT(*) FROM attempts').fetchone()[0] >= 20:
                raise APIError('Too many authentication attempts; wait 15 minutes', 429)
            attempt = db.execute('INSERT INTO attempts VALUES (?)', (time.time(),)).lastrowid
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            stored, must_change = db.execute('SELECT hash, must_change FROM auth WHERE id=1').fetchone()
            try:
                HASHER.verify(stored, password)
            except (VerificationError, InvalidHashError):
                raise APIError('Invalid password', 401) from None
            db.execute('DELETE FROM attempts WHERE rowid=?', (attempt,))
            if must_change and not allow_initial:
                raise APIError('Change the initial password before using the bucket', 403)
            if new_password is not None:
                if must_change and (not isinstance(bootstrap_token, str) or not secrets.compare_digest(bootstrap_token, self.bootstrap_token)):
                    raise APIError("Initial setup requires the Railway BOOTSTRAP_TOKEN", 403)
                if not isinstance(new_password, str) or not 15 <= len(new_password) <= 256 or new_password == password:
                    raise APIError('Choose a different password of 15–256 characters')
                db.execute('UPDATE auth SET hash=?, must_change=0 WHERE id=1', (HASHER.hash(new_password),))
            return bool(must_change)


def create_app(config=None, bucket=None):
    app = Flask(__name__)
    app.config.update(
        MAX_CONTENT_LENGTH=int(os.getenv('MAX_UPLOAD_MB', '250')) * 1024 * 1024,
        MAX_FORM_MEMORY_SIZE=128 * 1024,
        MAX_FORM_PARTS=10,
        AUTH_DB_PATH=os.getenv('AUTH_DB_PATH', '/data/auth.sqlite3'),
        INITIAL_PASSWORD_HASH=os.getenv('INITIAL_PASSWORD_HASH', ''),
        BOOTSTRAP_TOKEN=os.getenv('BOOTSTRAP_TOKEN', ''),
        RELEASE_ROOT=os.getenv('RELEASE_ROOT', 'operator-guide'),
    )
    if config:
        app.config.update(config)
    root = app.config['RELEASE_ROOT']
    if not re.fullmatch(r'[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*', root):
        raise RuntimeError('Invalid RELEASE_ROOT')
    auth = AuthStore(app.config['AUTH_DB_PATH'], app.config['INITIAL_PASSWORD_HASH'], app.config['BOOTSTRAP_TOKEN'])
    if bucket is None:
        info = json.loads(os.environ['GOOGLE_CREDENTIALS_JSON'])
        credentials = service_account.Credentials.from_service_account_info(info)
        bucket = storage.Client(project=info['project_id'], credentials=credentials).bucket(os.environ['GCS_BUCKET_NAME'])
    mutation_lock = threading.RLock()
    latest_path = f'{root}/latest.json'
    object_pattern = re.compile(re.escape(root) + r'/documents/([0-9]{1,12}(?:\.[0-9]{1,12}){0,2})\.(pdf|index\.json)\Z')

    def payload():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise APIError('A JSON object is required')
        return data

    def get_blob(name):
        return bucket.get_blob(name, timeout=60)

    def latest_metadata():
        blob = get_blob(latest_path)
        if blob is None:
            return None, None
        # Only GCS object metadata is read. No download_as_* methods anywhere.
        encoded = (blob.metadata or {}).get('release_manifest')
        return blob, json.loads(encoded) if encoded else None

    def read_json(upload, limit):
        raw = upload.read(limit + 1)
        if len(raw) > limit:
            raise APIError('JSON file exceeds its size limit', 413)
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeError):
            raise APIError('Invalid JSON file') from None
        if not isinstance(data, dict):
            raise APIError('JSON file must contain an object')
        return raw, data

    @app.errorhandler(APIError)
    def api_error(error):
        return jsonify(error=error.message), error.status

    @app.errorhandler(Exception)
    def unexpected(error):
        if isinstance(error, HTTPException):
            return jsonify(error=error.description), error.code
        if isinstance(error, (PreconditionFailed, NotFound)):
            return jsonify(error='Bucket changed during the operation. Refresh before retrying.'), 409
        logging.getLogger(__name__).error('Operation failed: %s', type(error).__name__)
        return jsonify(error='Storage operation failed; inspect server configuration and retry after refreshing.'), 502

    @app.after_request
    def headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        return response

    @app.get('/health')
    def health():
        return jsonify(status='ok')

    @app.post('/api/auth/check')
    def check():
        required = auth.authenticate(payload().get('password'), allow_initial=True)
        return jsonify(must_change_password=required, bucket_name=bucket.name, release_root=root)

    @app.post('/api/auth/password')
    def change_password():
        data = payload()
        if not isinstance(data.get('new_password'), str):
            raise APIError('New password required')
        with mutation_lock:
            auth.authenticate(data.get('password'), allow_initial=True, new_password=data['new_password'], bootstrap_token=data.get('bootstrap_token'))
        return jsonify(changed=True)

    @app.post('/api/files/list')
    def list_files():
        # POST keeps authentication out of URLs and logs; this is the read/list operation.
        auth.authenticate(payload().get('password'))
        with mutation_lock:
            blob, manifest = latest_metadata()
            objects = []
            for item in bucket.list_blobs(prefix=f'{root}/', timeout=60):
                match = object_pattern.fullmatch(item.name)
                objects.append(dict(path=item.name, size_bytes=item.size or 0,
                                    updated=item.updated.isoformat() if item.updated else None,
                                    version=match.group(1) if match else None))
            return jsonify(bucket_name=bucket.name, release_root=root, manifest=manifest,
                           legacy_manifest=bool(blob and not manifest), objects=objects)

    @app.post('/api/releases')
    def publish():
        auth.authenticate(request.form.get('password'))
        pdf = request.files.get('pdf')
        manifest_file = request.files.get('manifest')
        index_file = request.files.get('index')
        if not pdf or not manifest_file:
            raise APIError('PDF and manifest files are required')
        _, manifest = read_json(manifest_file, 16384)
        version = manifest.get('version')
        if not isinstance(version, str) or not VERSION.fullmatch(version):
            raise APIError('Invalid release version')
        pdf_path = f'{root}/documents/{version}.pdf'
        index_path = f'{root}/documents/{version}.index.json'
        digest, size = hashlib.sha256(), 0
        header = pdf.stream.read(5)
        if header != b'%PDF-':
            raise APIError('Invalid PDF signature')
        pdf.stream.seek(0)
        while chunk := pdf.stream.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
        pdf.stream.seek(0)
        expected = dict(version=version, documentPath=pdf_path, sha256=digest.hexdigest(), sizeBytes=size)
        index_raw = None
        if index_file:
            index_raw, index = read_json(index_file, 16 * 1024 * 1024)
            count, entries = index.get('pageCount'), index.get('entries')
            if index.get('version') != version or type(count) is not int or count < 1 or not isinstance(entries, list):
                raise APIError('Invalid search index version or structure')
            for entry in entries:
                if (not isinstance(entry, dict) or type(entry.get('page')) is not int
                        or not 1 <= entry['page'] <= count or not isinstance(entry.get('title'), str)):
                    raise APIError('Invalid search index entry')
            expected.update(indexPath=index_path, indexSha256=hashlib.sha256(index_raw).hexdigest())
        if size < 1024 or manifest != expected:
            raise APIError('Manifest paths, size or hashes do not match the uploaded files')
        with mutation_lock:
            # Recheck after waiting: password may have been rotated during upload.
            auth.authenticate(request.form.get('password'))
            current, _ = latest_metadata()
            pdf_blob, index_blob = bucket.blob(pdf_path), bucket.blob(index_path)
            if get_blob(pdf_path) or get_blob(index_path):
                raise APIError('Version already exists. Publish a new version.', 409)
            pdf_blob.cache_control = 'public, max-age=3600'
            pdf_blob.metadata = {'version': version, 'sha256': expected['sha256']}
            pdf_blob.upload_from_file(pdf.stream, size=size, content_type='application/pdf', if_generation_match=0, timeout=300)
            if index_raw:
                index_blob.cache_control = 'public, max-age=300'
                index_blob.upload_from_string(index_raw, content_type='application/json', if_generation_match=0, timeout=120)
            # Commit point: latest.json becomes visible only after its files exist.
            latest = bucket.blob(latest_path)
            latest.cache_control = 'public, max-age=300'
            latest.metadata = {'release_manifest': json.dumps(expected, separators=(',', ':'))}
            latest.upload_from_string(json.dumps(expected, indent=2), content_type='application/json',
                                      if_generation_match=int(current.generation) if current else 0, timeout=60)
        return jsonify(manifest=expected, bucket_name=bucket.name), 201

    @app.post('/api/files/delete')
    def delete_files():
        data = payload()
        with mutation_lock:
            auth.authenticate(data.get('password'))
            paths = data.get('paths')
            if not isinstance(paths, list) or not 1 <= len(paths) <= 100 or any(not isinstance(p, str) for p in paths):
                raise APIError('Provide 1–100 object paths')
            paths = list(dict.fromkeys(paths))
            if any(p != latest_path and not object_pattern.fullmatch(p) for p in paths):
                raise APIError('Only publisher release files can be deleted')
            latest, manifest = latest_metadata()
            if latest and latest_path not in paths:
                if manifest is None:
                    raise APIError('Legacy latest.json has no version metadata. Publish a new version before deleting old files.', 409)
                if any(p in (manifest['documentPath'], manifest.get('indexPath')) for p in paths):
                    raise APIError('Live release files are protected. Select latest.json as well to unpublish.', 409)
            # Resolve all generations first, remove the live pointer before its files.
            targets = [(p, get_blob(p)) for p in sorted(paths, key=lambda p: p != latest_path)]
            deleted = []
            try:
                for path, blob in targets:
                    if blob:
                        blob.delete(if_generation_match=int(blob.generation), timeout=60)
                    deleted.append(path)
            except Exception:
                return jsonify(error='Deletion stopped partway. Refresh the list before retrying.', deleted=deleted), 502
        return jsonify(deleted=deleted)

    return app
