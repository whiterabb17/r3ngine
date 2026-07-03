"""Evidence storage abstraction.

Supports three backends based on EVIDENCE_STORAGE_BACKEND setting:
  - 'filesystem': Local filesystem under EVIDENCE_STORAGE_ROOT
  - 'minio': MinIO (S3-compatible) object storage
  - 's3': AWS S3

Usage:
    from evidence.storage import get_storage_backend
    storage = get_storage_backend()
    path = storage.save(file_bytes, 'filename.png', 'screenshots/')
    url = storage.get_signed_url(path)
    content = storage.read(path)
    storage.delete(path)
"""
import hashlib
import io
import os
import uuid
from datetime import timedelta
from typing import Optional, Tuple

from django.conf import settings


class BaseEvidenceStorage:
    """Abstract base for evidence storage backends.

    All backends must implement save, read, delete, exists, and get_signed_url.
    """

    def save(self, content: bytes, filename: str, subfolder: str = '') -> str:
        """Persist content and return the storage key/path.

        Args:
            content (bytes): Raw file content to store.
            filename (str): Original filename (used for extension).
            subfolder (str): Optional subfolder / prefix within the store.

        Returns:
            str: Storage key (path or S3 object key) for later retrieval.
        """
        raise NotImplementedError

    def read(self, storage_key: str) -> bytes:
        """Read and return raw bytes from storage.

        Args:
            storage_key (str): The key returned by save().

        Returns:
            bytes: Raw file content.
        """
        raise NotImplementedError

    def delete(self, storage_key: str) -> None:
        """Delete an evidence file from storage.

        Args:
            storage_key (str): The key returned by save().
        """
        raise NotImplementedError

    def exists(self, storage_key: str) -> bool:
        """Check whether a storage key exists.

        Args:
            storage_key (str): The key returned by save().

        Returns:
            bool: True if the object exists.
        """
        raise NotImplementedError

    def get_signed_url(self, storage_key: str, expiry_seconds: Optional[int] = None) -> str:
        """Return a time-limited URL for accessing the stored file.

        For filesystem storage, this returns a Django media-serve URL.
        For S3/MinIO, returns a pre-signed URL.

        Args:
            storage_key (str): The key returned by save().
            expiry_seconds (int, optional): URL lifetime. Defaults to EVIDENCE_SIGNED_URL_EXPIRY.

        Returns:
            str: Signed or serve URL.
        """
        raise NotImplementedError

    def _unique_key(self, filename: str, subfolder: str = '') -> str:
        """Generate a collision-resistant storage key for a file.

        Args:
            filename (str): Original filename.
            subfolder (str): Optional subdirectory prefix.

        Returns:
            str: Unique key like 'screenshots/2026/07/01/{uuid}.png'
        """
        from django.utils import timezone
        ext = os.path.splitext(filename)[-1].lower()
        date_prefix = timezone.now().strftime('%Y/%m/%d')
        unique_id = uuid.uuid4().hex
        parts = [p for p in [subfolder, date_prefix, f"{unique_id}{ext}"] if p]
        return '/'.join(parts)


class FilesystemEvidenceStorage(BaseEvidenceStorage):
    """Stores evidence files on the local filesystem.

    Root directory is configured via EVIDENCE_STORAGE_ROOT (default: /usr/src/app/evidence/).
    """

    def __init__(self):
        self.root = getattr(settings, 'EVIDENCE_STORAGE_ROOT', '/usr/src/app/evidence/')
        os.makedirs(self.root, exist_ok=True)

    def save(self, content: bytes, filename: str, subfolder: str = '') -> str:
        """Save content to the filesystem and return a relative path key."""
        key = self._unique_key(filename, subfolder)
        abs_path = os.path.join(self.root, key)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, 'wb') as f:
            f.write(content)
        return key

    def read(self, storage_key: str) -> bytes:
        """Read raw bytes from the filesystem."""
        abs_path = os.path.join(self.root, storage_key)
        with open(abs_path, 'rb') as f:
            return f.read()

    def delete(self, storage_key: str) -> None:
        """Delete a file from the filesystem. Silently ignores missing files."""
        abs_path = os.path.join(self.root, storage_key)
        try:
            os.remove(abs_path)
        except FileNotFoundError:
            pass

    def exists(self, storage_key: str) -> bool:
        """Check if a file exists on the filesystem."""
        return os.path.isfile(os.path.join(self.root, storage_key))

    def get_signed_url(self, storage_key: str, expiry_seconds: Optional[int] = None) -> str:
        """Return the internal serve URL for this evidence file.

        Django's serve_protected_media view handles authentication.
        The URL is relative: /media/<storage_key>
        """
        return f"/evidence/download/{storage_key}"


class MinioEvidenceStorage(BaseEvidenceStorage):
    """Stores evidence in a MinIO (S3-compatible) object store.

    Configuration via settings:
        EVIDENCE_MINIO_ENDPOINT, EVIDENCE_MINIO_ACCESS_KEY,
        EVIDENCE_MINIO_SECRET_KEY, EVIDENCE_MINIO_BUCKET
    """

    def __init__(self):
        try:
            from minio import Minio
        except ImportError:
            raise ImportError("minio package required for MinioEvidenceStorage. Run: pip install minio")
        self.bucket = getattr(settings, 'EVIDENCE_MINIO_BUCKET', 'r3ngine-evidence')
        self.expiry = getattr(settings, 'EVIDENCE_SIGNED_URL_EXPIRY', 300)
        self.client = Minio(
            endpoint=settings.EVIDENCE_MINIO_ENDPOINT,
            access_key=settings.EVIDENCE_MINIO_ACCESS_KEY,
            secret_key=settings.EVIDENCE_MINIO_SECRET_KEY,
            secure=False,
        )
        if not self.client.bucket_exists(self.bucket):
            self.client.make_bucket(self.bucket)

    def save(self, content: bytes, filename: str, subfolder: str = '') -> str:
        """Upload content to MinIO and return the object key."""
        key = self._unique_key(filename, subfolder)
        self.client.put_object(
            self.bucket, key,
            data=io.BytesIO(content),
            length=len(content),
        )
        return key

    def read(self, storage_key: str) -> bytes:
        """Download and return object bytes from MinIO."""
        response = self.client.get_object(self.bucket, storage_key)
        return response.read()

    def delete(self, storage_key: str) -> None:
        """Delete object from MinIO."""
        try:
            self.client.remove_object(self.bucket, storage_key)
        except Exception:
            pass

    def exists(self, storage_key: str) -> bool:
        """Check if an object exists in MinIO."""
        try:
            self.client.stat_object(self.bucket, storage_key)
            return True
        except Exception:
            return False

    def get_signed_url(self, storage_key: str, expiry_seconds: Optional[int] = None) -> str:
        """Return a pre-signed GET URL valid for expiry_seconds."""
        from datetime import timedelta
        expiry = expiry_seconds or self.expiry
        url = self.client.presigned_get_object(
            self.bucket, storage_key,
            expires=timedelta(seconds=expiry),
        )
        return url


class S3EvidenceStorage(BaseEvidenceStorage):
    """Stores evidence in AWS S3.

    Configuration via settings:
        EVIDENCE_S3_BUCKET, EVIDENCE_S3_REGION
    Also uses standard AWS SDK environment variables (AWS_ACCESS_KEY_ID, etc.)
    """

    def __init__(self):
        try:
            import boto3
            self.s3 = boto3.client('s3', region_name=getattr(settings, 'EVIDENCE_S3_REGION', 'us-east-1'))
        except ImportError:
            raise ImportError("boto3 package required for S3EvidenceStorage. Run: pip install boto3")
        self.bucket = settings.EVIDENCE_S3_BUCKET
        self.expiry = getattr(settings, 'EVIDENCE_SIGNED_URL_EXPIRY', 300)

    def save(self, content: bytes, filename: str, subfolder: str = '') -> str:
        """Upload content to S3 and return the object key."""
        key = self._unique_key(filename, subfolder)
        self.s3.put_object(Bucket=self.bucket, Key=key, Body=content)
        return key

    def read(self, storage_key: str) -> bytes:
        """Download and return object bytes from S3."""
        response = self.s3.get_object(Bucket=self.bucket, Key=storage_key)
        return response['Body'].read()

    def delete(self, storage_key: str) -> None:
        """Delete object from S3."""
        try:
            self.s3.delete_object(Bucket=self.bucket, Key=storage_key)
        except Exception:
            pass

    def exists(self, storage_key: str) -> bool:
        """Check if an object exists in S3."""
        try:
            self.s3.head_object(Bucket=self.bucket, Key=storage_key)
            return True
        except Exception:
            return False

    def get_signed_url(self, storage_key: str, expiry_seconds: Optional[int] = None) -> str:
        """Return a pre-signed GET URL for the S3 object."""
        expiry = expiry_seconds or self.expiry
        return self.s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': self.bucket, 'Key': storage_key},
            ExpiresIn=expiry,
        )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_backend_instance: Optional[BaseEvidenceStorage] = None


def get_storage_backend() -> BaseEvidenceStorage:
    """Return the configured storage backend singleton.

    The backend is selected via EVIDENCE_STORAGE_BACKEND setting:
      'filesystem' (default), 'minio', 's3'

    Returns:
        BaseEvidenceStorage: The active storage backend instance.
    """
    global _backend_instance
    if _backend_instance is not None:
        return _backend_instance

    backend = getattr(settings, 'EVIDENCE_STORAGE_BACKEND', 'filesystem')
    if backend == 'minio':
        _backend_instance = MinioEvidenceStorage()
    elif backend == 's3':
        _backend_instance = S3EvidenceStorage()
    else:
        _backend_instance = FilesystemEvidenceStorage()

    return _backend_instance
