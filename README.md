# aws-envelope-crypto

该项目是一个支持 Modal OIDC 认证的 AWS KMS 信封加密工具。用于在本地加密模型权重等敏感文件，并在 Modal 冷启动阶段通过 OIDC 获取临时凭证从而解密模型。

## 安装方式

```bash
pip install git+https://github.com/k1tyoo/aws-envelope-crypto.git
```

## 配置流程

## CLI 使用方式

### 加密（本地）

```bash
# 单文件
aws-envelope-crypto encrypt -i data.bin -o ./encrypted --kms-key-id alias/my-key

# 目录（每个文件独立 DEK）
aws-envelope-crypto encrypt -i ./data_dir -o ./encrypted --pattern "*.bin"

# 目录（共享 DEK，生成 manifest）
aws-envelope-crypto encrypt -i ./data_dir -o ./encrypted --pattern "*.bin" --shared-dek
```

### 解密（本地测试）

```bash
# 单文件
aws-envelope-crypto decrypt --enc data.bin.enc --key data.bin.key -o ./decrypted

# 批量解密（使用 manifest）
aws-envelope-crypto decrypt --manifest ./encrypted/manifest.json -o ./decrypted --workers 4
```

## API 使用方式

### 基础加解密

```python
from aws_envelope_crypto import encrypt_data, decrypt, generate_dek

dek = generate_dek()
ciphertext = encrypt_data(b"secret data", dek)
plaintext = decrypt(ciphertext, dek)
```

### 文件操作

```python
from pathlib import Path
from aws_envelope_crypto import KMSClient, encrypt_file, decrypt_file

kms = KMSClient(key_id="alias/my-key", region="ap-southeast-1")

# 加密
enc_file, key_file = encrypt_file(Path("data.bin"), Path("./output"), kms)

# 解密
data = decrypt_file(enc_file, key_file, kms)
```

### 批量文件加 / 解密（共享 DEK）

```python
from pathlib import Path
from aws_envelope_crypto import KMSClient, encrypt_files_shared_dek, decrypt_files_parallel

kms = KMSClient(key_id="alias/my-key", region="ap-southeast-1")
files = list(Path("./data").glob("*.bin"))

# 加密
enc_files, key_file, manifest_file = encrypt_files_shared_dek(files, Path("./output"), kms)

# 解密
results = decrypt_files_parallel(manifest_file, kms, num_workers=4)
for name, data in results.items():
    Path(f"./decrypted/{name}").write_bytes(data)
```

### Modal 冷启动解密

```python
import modal
from pathlib import Path
from aws_envelope_crypto import KMSClient, get_sts_credentials, decrypt_files_parallel

app = modal.App()
volume = modal.Volume.from_name("weights-volume")

@app.cls(volumes={"/weights": volume})
class Model:
    @modal.enter()
    def load_weights(self):
        creds = get_sts_credentials(role_arn="arn:aws:iam::123456789:role/modal-decrypt-role")
        kms = KMSClient.from_sts_credentials(key_id="alias/my-key", credentials=creds)

        results = decrypt_files_parallel(Path("/weights/manifest.json"), kms)
        for name, data in results.items():
            Path(f"/tmp/weights/{name}").write_bytes(data)

        self.model = load_model("/tmp/weights")
```
