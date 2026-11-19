"""Shared configuration and validated, non-sensitive boundaries."""
from pathlib import Path
import hashlib
import logging
import os
import re

ROOT = Path(__file__).resolve().parents[1]
MAX_UPLOAD = min(50, max(1, int(os.getenv('MALGUARD_MAX_UPLOAD_MB', '20')))) * 1024 * 1024
LOGGER = logging.getLogger('malguard')


class AnalysisError(ValueError):
    """An actionable error safe to display to an analyst."""


def validate_bytes(data: bytes, limit: int = MAX_UPLOAD, allow_empty: bool = False) -> None:
    if not isinstance(data, bytes) or (not data and not allow_empty):
        raise AnalysisError('Select a nonempty file.')
    if len(data) > limit:
        raise AnalysisError(f'File exceeds the {limit // 1024 // 1024} MiB limit.')


def safe_name(name: str) -> str:
    name = re.split(r'[/\\]', str(name))[-1]
    return re.sub(r'[^\w. ()-]', '_', name, flags=re.ASCII)[:120].strip('. ') or 'upload'


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
