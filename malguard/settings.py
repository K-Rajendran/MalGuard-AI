"""Deployment settings: explicit storage and stable authenticated ownership."""
from dataclasses import dataclass
import hashlib
import json
import os
import time
from collections.abc import Mapping
from sqlalchemy.engine import make_url
from .core import AnalysisError


@dataclass(frozen=True)
class Settings:
    production: bool
    database_url: str | None
    retention_days: int
    allowed_subjects: tuple[str, ...]


def load_settings(secrets: Mapping | None = None, environ: Mapping | None = None) -> Settings:
    secrets = secrets or {}
    environ = os.environ if environ is None else environ
    def value(key, default=''):
        return environ.get(key, secrets.get(key, default))
    mode = value('MALGUARD_MODE', 'local')
    if mode not in ('local', 'production'):
        raise AnalysisError('MALGUARD_MODE must be local or production.')
    try:
        days = int(value('MALGUARD_RETENTION_DAYS', 30))
        if not 1 <= days <= 3650: raise ValueError()
    except (TypeError, ValueError):
        raise AnalysisError('Retention must be 1–3650 days.') from None
    url = value('MALGUARD_DATABASE_URL') or None
    allowed = value('MALGUARD_ALLOWED_SUBJECTS', [])
    if isinstance(allowed, str): allowed = [s.strip() for s in allowed.split(',') if s.strip()]
    if not isinstance(allowed, (list, tuple)) or any(not isinstance(s,str) or not s or len(s)>255 for s in allowed):
        raise AnalysisError('Allowed subjects must be a list of identity-provider subject IDs.')
    if mode == 'production':
        try:
            parsed = make_url(url or '')
            if parsed.drivername != 'postgresql+psycopg' or not parsed.host or not parsed.database:
                raise ValueError()
            if parsed.query.get('sslmode') not in ('verify-full', 'verify-ca'):
                raise ValueError()
        except Exception:
            raise AnalysisError('Production requires a PostgreSQL URL with sslmode=verify-full (or verify-ca) and a trusted CA. Local SQLite is disabled in production.') from None
        auth = secrets.get('auth', {})
        required = ('redirect_uri','cookie_secret','client_id','client_secret','server_metadata_url')
        if not isinstance(auth, Mapping) or any(not auth.get(k) for k in required):
            raise AnalysisError('Configure the default OpenID Connect provider in Streamlit secrets [auth] before enabling production.')
        if not str(auth['redirect_uri']).startswith('https://') or not str(auth['server_metadata_url']).startswith('https://') or len(str(auth['cookie_secret'])) < 32:
            raise AnalysisError('Production sign-in requires HTTPS URLs and a random cookie secret of at least 32 characters.')
    return Settings(mode == 'production', url, days, tuple(allowed))


def authenticated_owner(claims: Mapping, allowed_subjects: tuple[str, ...] = ()) -> str:
    """Only call with claims already verified by Streamlit's OIDC integration."""
    issuer, subject = claims.get('iss'), claims.get('sub')
    if not isinstance(issuer,str) or not issuer or not isinstance(subject,str) or not subject:
        raise AnalysisError('Your sign-in provider must return issuer and subject identifiers.')
    try:
        expires = float(claims['exp'])
        if not time.time() < expires < float('inf'): raise ValueError()
    except (KeyError, ValueError, TypeError, OverflowError):
        raise AnalysisError('Your sign-in has expired. Sign out and sign in again.') from None
    if allowed_subjects and subject not in allowed_subjects:
        raise AnalysisError('This account is not authorized to use this workspace.')
    identity = json.dumps([issuer,subject],separators=(',',':')).encode()
    return 'oidc:' + hashlib.sha256(identity).hexdigest()
