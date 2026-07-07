"""
Remote storage for backup files.

Two engine-agnostic backends:
  * S3 / S3-compatible (boto3)         -> [s3:<name>] sections
  * WebDAV / HTTP(S) file shares       -> [fileshare:<name>] sections
    (uses urllib3, already pulled in transitively by botocore -> no new dependency)

The local backup directory stays the working area:
  * "push"  uploads a local backup file to a remote target
  * "pull"  downloads a remote object / link back into the local backup directory,
            after which it can be restored like any other local backup.

All filename / size / path-traversal guards are shared with backup_restore so a
remote object can never be written outside the backup directory or exceed the
configured size limit.
"""

import base64
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote, unquote, urlparse, urlunparse

from . import config as cfg
from . import backup_restore as br

logger = logging.getLogger(__name__)

# Stream chunk size for uploads/downloads (8 MiB).
_CHUNK = 8 * 1024 * 1024


# =============================================================================
# Shared helpers
# =============================================================================

def _max_bytes() -> int:
    """Size ceiling for pulled files (reuses the upload limit)."""
    return cfg.get_settings().max_upload_size_gb * 1024 * 1024 * 1024


def _local_backup_path(filename: str):
    """Validate a local backup filename and return (path, error).

    Returns (Path, None) on success or (None, error_message) on failure.
    The returned path is guaranteed to sit inside the backup directory.
    """
    ok, err = br.validate_backup_filename(filename)
    if not ok:
        return None, err
    backup_dir = br.get_backup_dir()
    path = backup_dir / filename
    try:
        path.resolve().relative_to(backup_dir.resolve())
    except ValueError:
        return None, "Invalid file path"
    return path, None


def _safe_target(filename: str):
    """Resolve a safe, non-existing local target for a pulled file.

    Returns (path, error). Errors if the sanitized name is invalid or a file
    with that name already exists locally.
    """
    safe = br.sanitize_backup_filename(Path(filename).name)
    ok, err = br.validate_backup_filename(safe)
    if not ok:
        return None, err
    backup_dir = br.get_backup_dir()
    target = backup_dir / safe
    try:
        target.resolve().relative_to(backup_dir.resolve())
    except ValueError:
        return None, "Invalid file path"
    if target.exists():
        return None, f"File {safe} already exists locally"
    return target, None


def _redact_url(url: str) -> str:
    """Strip any user:pass@ userinfo from a URL so it is safe to log."""
    try:
        p = urlparse(url)
        if p.username or p.password:
            netloc = p.hostname or ''
            if p.port:
                netloc += f":{p.port}"
            return urlunparse((p.scheme, netloc, p.path, p.params, p.query, p.fragment))
    except Exception:
        pass
    return url


def _url_within_base(url: str, base_url: str) -> bool:
    """True only if `url` provably belongs to `base_url`: identical scheme +
    host(:port) and a path equal to, or nested under, the base path at a '/'
    boundary. Gates whether a file share's credentials may be sent to a link,
    so an operator can't point a share's stored credentials at an arbitrary host.
    """
    if not base_url:
        return False
    u = urlparse(url)
    b = urlparse(base_url.rstrip('/'))
    if (u.scheme, u.netloc) != (b.scheme, b.netloc):
        return False
    if not b.path:
        return True  # base is a bare origin -> the whole host is the share root
    return u.path == b.path or u.path.startswith(b.path + '/')


# =============================================================================
# S3 / S3-compatible
# =============================================================================

def _s3_client(store: cfg.S3StorageConfig):
    """Build a boto3 S3 client for a storage config.

    Credentials come either from a referenced [aws:*] account or from the
    dedicated keys stored on the S3 config. endpoint_url + path-style addressing
    make it work against S3-compatible servers (MinIO, Ceph, Wasabi, ...).
    """
    import boto3
    from botocore.config import Config as BotoConfig

    boto_cfg = BotoConfig(
        signature_version='s3v4',
        s3={'addressing_style': 'path' if store.path_style else 'auto'},
        retries={'max_attempts': 3, 'mode': 'standard'},
    )

    if store.cred_mode == 'aws_account':
        from .aws_service import get_boto3_session
        session = get_boto3_session(store.aws_account_alias or None)
    else:
        session = boto3.Session(
            aws_access_key_id=store.access_key_id or None,
            aws_secret_access_key=store.secret_access_key or None,
            region_name=store.region or 'us-east-1',
        )

    kwargs: Dict[str, Any] = {'config': boto_cfg}
    if store.endpoint_url:
        kwargs['endpoint_url'] = store.endpoint_url
    if store.region:
        kwargs['region_name'] = store.region
    return session.client('s3', **kwargs)


def _s3_prefix(store: cfg.S3StorageConfig) -> str:
    """Normalized key prefix: no leading slash, trailing slash if non-empty."""
    prefix = (store.prefix or '').strip().lstrip('/')
    if prefix and not prefix.endswith('/'):
        prefix += '/'
    return prefix


def s3_test_connection(store_name: Optional[str] = None,
                       store: Optional[cfg.S3StorageConfig] = None) -> Dict[str, Any]:
    """Verify credentials + bucket access (head_bucket)."""
    store = store or (cfg.get_s3_storage_config(store_name) if store_name else None)
    if not store:
        return {"success": False, "error": "S3 storage not found"}
    if not store.bucket:
        return {"success": False, "error": "Bucket name is empty"}
    try:
        client = _s3_client(store)
        client.head_bucket(Bucket=store.bucket)
        return {"success": True, "message": f"Connected to bucket '{store.bucket}'"}
    except Exception as e:
        logger.warning(f"S3 test failed for '{store.name}': {e}")
        return {"success": False, "error": str(e)}


def s3_upload_backup(store_name: str, filename: str) -> Dict[str, Any]:
    """Upload a local backup file to the configured S3 bucket."""
    store = cfg.get_s3_storage_config(store_name)
    if not store:
        return {"success": False, "error": f"S3 storage '{store_name}' not found"}

    local_path, err = _local_backup_path(filename)
    if err:
        return {"success": False, "error": err}
    if not local_path.exists():
        return {"success": False, "error": f"Backup '{filename}' not found locally"}

    key = f"{_s3_prefix(store)}{filename}"
    try:
        client = _s3_client(store)
        client.upload_file(str(local_path), store.bucket, key)
        size = local_path.stat().st_size
        return {
            "success": True,
            "message": f"Uploaded to s3://{store.bucket}/{key}",
            "bucket": store.bucket,
            "key": key,
            "size": size,
            "size_human": br._format_size(size),
        }
    except Exception as e:
        logger.error(f"S3 upload failed ({store_name}/{filename}): {e}")
        return {"success": False, "error": str(e)}


def s3_list_backups(store_name: str) -> Dict[str, Any]:
    """List .backup objects in the bucket under the configured prefix."""
    store = cfg.get_s3_storage_config(store_name)
    if not store:
        return {"success": False, "error": f"S3 storage '{store_name}' not found"}

    prefix = _s3_prefix(store)
    try:
        client = _s3_client(store)
        paginator = client.get_paginator('list_objects_v2')
        objects: List[Dict[str, Any]] = []
        for page in paginator.paginate(Bucket=store.bucket, Prefix=prefix):
            for obj in page.get('Contents', []):
                key = obj['Key']
                if not key.endswith('.backup'):
                    continue
                name = key[len(prefix):] if prefix and key.startswith(prefix) else key
                if not name:
                    continue
                modified = obj.get('LastModified')
                objects.append({
                    "key": key,
                    "name": name,
                    "size": obj['Size'],
                    "size_human": br._format_size(obj['Size']),
                    "modified": modified.isoformat() if modified else "",
                })
        objects.sort(key=lambda x: x["modified"], reverse=True)
        return {"success": True, "objects": objects}
    except Exception as e:
        logger.error(f"S3 list failed ({store_name}): {e}")
        return {"success": False, "error": str(e)}


def s3_download_backup(store_name: str, key: str) -> Dict[str, Any]:
    """Download an object from the bucket into the local backup directory."""
    store = cfg.get_s3_storage_config(store_name)
    if not store:
        return {"success": False, "error": f"S3 storage '{store_name}' not found"}
    if not key:
        return {"success": False, "error": "Object key is required"}
    if not key.endswith('.backup'):
        return {"success": False, "error": "Only .backup objects can be downloaded"}

    target, err = _safe_target(key)
    if err:
        return {"success": False, "error": err}

    tmp = target.with_suffix('.tmp')
    try:
        client = _s3_client(store)
        head = client.head_object(Bucket=store.bucket, Key=key)
        size = head.get('ContentLength', 0)
        ok, size_err = br.check_file_size_limit(size, cfg.get_settings().max_upload_size_gb)
        if not ok:
            return {"success": False, "error": size_err}

        client.download_file(store.bucket, key, str(tmp))
        # Re-check the actual downloaded size: an S3-compatible server may
        # under-report ContentLength, or the object may have grown.
        actual = tmp.stat().st_size
        ok2, size_err2 = br.check_file_size_limit(actual, cfg.get_settings().max_upload_size_gb)
        if not ok2:
            tmp.unlink()
            return {"success": False, "error": size_err2}
        tmp.rename(target)
        return {
            "success": True,
            "message": f"Downloaded {target.name}",
            "filename": target.name,
            "size": actual,
            "size_human": br._format_size(actual),
        }
    except Exception as e:
        logger.error(f"S3 download failed ({store_name}/{key}): {e}")
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
        return {"success": False, "error": str(e)}


# =============================================================================
# WebDAV / HTTP(S) file shares
# =============================================================================

def _http_pool(verify_ssl: bool = True):
    import ssl
    import urllib3

    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        urllib3.disable_warnings()
    return urllib3.PoolManager(ssl_context=ctx)


def _basic_auth_header(username: str, password: str) -> Dict[str, str]:
    if not username:
        return {}
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def _join_url(base_url: str, filename: str) -> str:
    return base_url.rstrip('/') + '/' + quote(filename)


def webdav_test_connection(share_name: Optional[str] = None,
                           share: Optional[cfg.FileShareConfig] = None) -> Dict[str, Any]:
    """Probe a WebDAV/HTTP endpoint (PROPFIND, with a HEAD fallback)."""
    share = share or (cfg.get_fileshare_config(share_name) if share_name else None)
    if not share:
        return {"success": False, "error": "File share not found"}
    if not share.base_url:
        return {"success": False, "error": "Base URL is empty"}

    parsed = urlparse(share.base_url)
    if parsed.scheme not in ('http', 'https'):
        return {"success": False, "error": "Base URL must be http(s)"}

    try:
        pool = _http_pool(share.verify_ssl)
        import urllib3
        timeout = urllib3.Timeout(connect=15.0, read=15.0)
        headers = _basic_auth_header(share.username, share.password)
        headers['Depth'] = '0'
        resp = pool.request('PROPFIND', share.base_url, headers=headers,
                            preload_content=False, timeout=timeout)
        resp.release_conn()
        if resp.status in (200, 207):
            return {"success": True, "message": f"Connected (HTTP {resp.status})"}
        if resp.status in (401, 403):
            return {"success": False, "error": f"Authentication failed (HTTP {resp.status})"}
        if resp.status == 405:
            # PROPFIND not allowed -> generic HTTP host, try a HEAD
            resp2 = pool.request('HEAD', share.base_url,
                                headers=_basic_auth_header(share.username, share.password),
                                preload_content=False, timeout=timeout)
            resp2.release_conn()
            if resp2.status < 400:
                return {"success": True, "message": f"Reachable (HTTP {resp2.status}, not WebDAV)"}
            return {"success": False, "error": f"HTTP {resp2.status}"}
        return {"success": False, "error": f"HTTP {resp.status}"}
    except Exception as e:
        logger.warning(f"WebDAV test failed for '{share.name}': {e}")
        return {"success": False, "error": str(e)}


def webdav_upload_backup(share_name: str, filename: str) -> Dict[str, Any]:
    """Upload a local backup file to a WebDAV/HTTP file share via HTTP PUT."""
    share = cfg.get_fileshare_config(share_name)
    if not share:
        return {"success": False, "error": f"File share '{share_name}' not found"}
    if not share.base_url:
        return {"success": False, "error": "File share base URL is empty"}

    local_path, err = _local_backup_path(filename)
    if err:
        return {"success": False, "error": err}
    if not local_path.exists():
        return {"success": False, "error": f"Backup '{filename}' not found locally"}

    url = _join_url(share.base_url, filename)
    size = local_path.stat().st_size
    resp = None
    try:
        import urllib3
        pool = _http_pool(share.verify_ssl)
        headers = _basic_auth_header(share.username, share.password)
        headers['Content-Length'] = str(size)
        headers['Content-Type'] = 'application/octet-stream'
        with open(local_path, 'rb') as f:
            resp = pool.request('PUT', url, body=f, headers=headers,
                                preload_content=False,
                                timeout=urllib3.Timeout(connect=15.0, read=None))
        if resp.status not in (200, 201, 204):
            return {"success": False, "error": f"Server returned HTTP {resp.status}"}
        return {
            "success": True,
            "message": f"Uploaded to {url}",
            "url": url,
            "size": size,
            "size_human": br._format_size(size),
        }
    except Exception as e:
        logger.error(f"WebDAV upload failed ({share_name}/{filename}): {e}")
        return {"success": False, "error": str(e)}
    finally:
        if resp is not None:
            resp.release_conn()


def download_from_link(url: str, share_name: Optional[str] = None) -> Dict[str, Any]:
    """Download a backup from an arbitrary http(s) link into the local backup dir.

    Credentials are applied if an explicit file share is chosen, or auto-matched
    when the link starts with a configured share's base URL.
    """
    if not url:
        return {"success": False, "error": "URL is required"}
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return {"success": False, "error": "URL must be http(s)"}

    raw_name = unquote(Path(parsed.path).name)
    target, err = _safe_target(raw_name or 'download.backup')
    if err:
        return {"success": False, "error": err}

    # Pick credentials. Credentials are ONLY attached when the URL provably
    # belongs to the file share's base URL, so a stored (admin-only) secret is
    # never sent to an arbitrary host chosen by a lower-privileged operator.
    creds_share = None
    if share_name:
        share = cfg.get_fileshare_config(share_name)
        if not share:
            return {"success": False, "error": f"File share '{share_name}' not found"}
        if not _url_within_base(url, share.base_url):
            return {"success": False, "error": "The URL is not within the selected file share's base URL"}
        creds_share = share
    else:
        for candidate in cfg.get_fileshare_configs().values():
            if _url_within_base(url, candidate.base_url):
                creds_share = candidate
                break

    verify_ssl = creds_share.verify_ssl if creds_share else True
    headers = _basic_auth_header(creds_share.username, creds_share.password) if creds_share else {}

    max_bytes = _max_bytes()
    max_gb = cfg.get_settings().max_upload_size_gb
    tmp = target.with_suffix('.tmp')
    resp = None
    try:
        import urllib3
        pool = _http_pool(verify_ssl)
        resp = pool.request('GET', url, headers=headers, preload_content=False,
                            timeout=urllib3.Timeout(connect=15.0, read=None))
        if resp.status != 200:
            return {"success": False, "error": f"Server returned HTTP {resp.status}"}

        clen = resp.headers.get('Content-Length')
        if clen and clen.isdigit() and int(clen) > max_bytes:
            return {"success": False, "error": f"Remote file exceeds limit of {max_gb}GB"}

        written = 0
        too_big = False
        with open(tmp, 'wb') as f:
            for chunk in resp.stream(_CHUNK):
                written += len(chunk)
                if written > max_bytes:
                    too_big = True
                    break
                f.write(chunk)

        if too_big:
            if tmp.exists():
                tmp.unlink()
            return {"success": False, "error": f"Remote file exceeds limit of {max_gb}GB"}

        tmp.rename(target)
        return {
            "success": True,
            "message": f"Downloaded {target.name}",
            "filename": target.name,
            "size": written,
            "size_human": br._format_size(written),
        }
    except Exception as e:
        logger.error(f"Download from link failed ({_redact_url(url)}): {e}")
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
        return {"success": False, "error": str(e)}
    finally:
        if resp is not None:
            resp.release_conn()
