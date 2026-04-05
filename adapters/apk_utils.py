from __future__ import annotations

import hashlib
from pathlib import Path

# 收集目标应用程序.apk的sha256（数字指纹）
def calc_sha256(file_path: str | Path) -> str:
    path = Path(file_path).expanduser().resolve()
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

# 获取.apk的基本信息：名称、路径、大小、指纹，把这些内容填到表（字典）中
def get_apk_basic_info(apk_path: str | Path) -> dict:
    path = Path(apk_path).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"APK not found: {path}")
    if not path.is_file():
        raise FileNotFoundError(f"APK path is not a file: {path}")

    stat = path.stat()
    return {
        "name": path.name,
        "path": str(path),
        "file_size": stat.st_size,
        "sha256": calc_sha256(path),
    }
