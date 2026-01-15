import boto3


class KMSClient:
    def __init__(
        self,
        key_id: str,
        region: str = "us-east-1",
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
        session_token: str | None = None,
    ):
        self.key_id = key_id
        self.region = region

        self.client = boto3.client(
            "kms",
            region_name=region,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            aws_session_token=session_token,
        )

    @classmethod
    def from_sts_credentials(cls, key_id: str, credentials, region: str = "us-east-1"):
        return cls(
            key_id=key_id,
            region=region,
            access_key_id=credentials.access_key_id,
            secret_access_key=credentials.secret_access_key,
            session_token=credentials.session_token,
        )

    def encrypt_dek(self, dek: bytes) -> bytes:
        response = self.client.encrypt(
            KeyId=self.key_id,
            Plaintext=dek,
        )
        return response["CiphertextBlob"]

    def decrypt_dek(self, encrypted_dek: bytes) -> bytes:
        response = self.client.decrypt(
            CiphertextBlob=encrypted_dek,
        )
        return response["Plaintext"]
