from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

# 项目根目录
BASE_DIR = Path(__file__).resolve().parent

# ── 输入 / 输出 ──────────────────────────────────────────────
INPUT_DIR  = BASE_DIR / "inputs"
OUTPUT_DIR = BASE_DIR / "outputs"
LOG_DIR    = OUTPUT_DIR / "logs"
RAW_DIR    = OUTPUT_DIR / "raw"
REPORT_DIR = OUTPUT_DIR / "reports"

# ── 数据层 ───────────────────────────────────────────────────
DATA_DIR    = BASE_DIR / "data"
PATCH_DIR   = DATA_DIR / "patches"
CVE_KB_PATH = DATA_DIR / "cve_kb.json"

# TPL 特征库目录（在 data/ 下，由用户自行准备）
#   tpl_dex/  ← .dex 格式特征文件，对应 LibHunter -ld 参数
#   tpl_jar/  ← .jar 格式特征文件，对应 LibHunter -lf 参数
LIBHUNTER_TPLS_DEX = DATA_DIR / "tpl_dex"   # 注意：是 tpl_dex，不是 tpls_dex
LIBHUNTER_TPLS_JAR = DATA_DIR / "tpl_jar"

# ── LibHunter 工具 ────────────────────────────────────────────
# LibHunter/
# ├── libs/        ← 工具依赖（d8.jar、android.jar 等）
# ├── module/      ← 核心模块包
# ├── androguard/
# ├── dex_pickles/
# └── LibHunter.py
LIBHUNTER_DIR    = BASE_DIR / "LibHunter"
LIBHUNTER_SCRIPT = LIBHUNTER_DIR / "LibHunter.py"

_LH_VENV_PYTHON = LIBHUNTER_DIR / ".venv" / "bin" / "python"
PYTHON_BIN = _LH_VENV_PYTHON if _LH_VENV_PYTHON.exists() else Path(sys.executable)

# ── PHunter 工具 ──────────────────────────────────────────────
PHUNTER_DIR = BASE_DIR / "PHunter"
PHUNTER_JAR = PHUNTER_DIR / "PHunter.jar"
ANDROID_JAR = PHUNTER_DIR / "android-31" / "android.jar"

# ── 系统工具 ──────────────────────────────────────────────────
JAVA_BIN = Path(shutil.which("java") or "java")

# ── 超时 / 线程 ───────────────────────────────────────────────
DEFAULT_PHUNTER_THREADS   = 8
DEFAULT_LIBHUNTER_TIMEOUT = 60 * 60
DEFAULT_PHUNTER_TIMEOUT   = 15 * 60


def build_pythonpath() -> str:
    """将 LibHunter 根目录注入 PYTHONPATH，让子进程能找到 module 包"""
    paths = [str(LIBHUNTER_DIR)]
    existing = os.environ.get("PYTHONPATH")
    if existing:
        paths.append(existing)
    return os.pathsep.join(paths)


def ensure_runtime_dirs() -> None:
    for path in (INPUT_DIR, OUTPUT_DIR, LOG_DIR, RAW_DIR,
                 REPORT_DIR, DATA_DIR, PATCH_DIR):
        path.mkdir(parents=True, exist_ok=True)