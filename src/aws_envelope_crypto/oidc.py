import os
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime

import boto3


@dataclass
class STSCredentials:
    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: datetime | None = None

    def is_expired(self, buffer_seconds: int = 300) -> bool:
        if self.expiration is None:
            return False
        now = datetime.now(UTC)
        return (self.expiration - now).total_seconds() < buffer_seconds


@dataclass
class CredentialsCache:
    _credentials: STSCredentials | None = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def get(self) -> STSCredentials | None:
        with self._lock:
            if self._credentials and not self._credentials.is_expired():
                return self._credentials
            return None

    def set(self, credentials: STSCredentials) -> None:
        with self._lock:
            self._credentials = credentials

    def clear(self) -> None:
        with self._lock:
            self._credentials = None


_credentials_cache = CredentialsCache()


def get_modal_identity_token() -> str:
    token = os.environ.get("MODAL_IDENTITY_TOKEN")
    if not token:
        raise RuntimeError("MODAL_IDENTITY_TOKEN not found. Are you running in Modal?")
    return token


def assume_role_with_web_identity(
    oidc_token: str,
    role_arn: str,
    role_session_name: str = "modal-session",
    region: str = "us-east-1",
) -> STSCredentials:
    sts_client = boto3.client("sts", region_name=region)

    response = sts_client.assume_role_with_web_identity(
        RoleArn=role_arn,
        RoleSessionName=role_session_name,
        WebIdentityToken=oidc_token,
    )

    creds = response["Credentials"]

    return STSCredentials(
        access_key_id=creds["AccessKeyId"],
        secret_access_key=creds["SecretAccessKey"],
        session_token=creds["SessionToken"],
        expiration=creds.get("Expiration"),
    )


def get_sts_credentials(
    role_arn: str | None = None,
    region: str = "us-east-1",
    use_cache: bool = True,
) -> STSCredentials:
    if use_cache:
        cached = _credentials_cache.get()
        if cached:
            return cached

    resolved_role_arn = role_arn or os.environ.get("AWS_ROLE_ARN")
    if not resolved_role_arn:
        raise ValueError("AWS_ROLE_ARN is required")

    token = get_modal_identity_token()

    credentials = assume_role_with_web_identity(
        oidc_token=token,
        role_arn=resolved_role_arn,
        region=region,
    )

    if use_cache:
        _credentials_cache.set(credentials)

    return credentials


def clear_credentials_cache() -> None:
    _credentials_cache.clear()
