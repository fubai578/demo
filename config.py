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

# ── 【新增】LibHunter pickle 全局缓存目录 ────────────────────
# 使用绝对路径，切换工作目录后仍然有效
PICKLE_CACHE_DIR = DATA_DIR / "lib_pickle_cache"

# TPL 特征库目录
LIBHUNTER_TPLS_DEX = DATA_DIR / "tpl_dex"
LIBHUNTER_TPLS_JAR = DATA_DIR / "tpl_jar"

# ── LibHunter 工具 ────────────────────────────────────────────
LIBHUNTER_DIR    = BASE_DIR / "LibHunter"
LIBHUNTER_SCRIPT = LIBHUNTER_DIR / "LibHunter.py"

if sys.platform == "win32":
    _LH_VENV_PYTHON = LIBHUNTER_DIR / ".venv" / "Scripts" / "python.exe"
else:
    _LH_VENV_PYTHON = LIBHUNTER_DIR / ".venv" / "bin" / "python"
PYTHON_BIN = _LH_VENV_PYTHON if _LH_VENV_PYTHON.exists() else Path(sys.executable)

# ── PHunter 工具 ──────────────────────────────────────────────
PHUNTER_DIR = BASE_DIR / "PHunter"
PHUNTER_JAR = PHUNTER_DIR / "PHunter.jar"
ANDROID_JAR = PHUNTER_DIR / "android-31" / "android.jar"

# ── 系统工具 ──────────────────────────────────────────────────
JAVA_BIN = Path(shutil.which("java") or "java")

# ── 超时 / 线程 ───────────────────────────────────────────────
# 【修改】缩短超时，避免卡死服务器
DEFAULT_PHUNTER_THREADS   = 8
DEFAULT_LIBHUNTER_TIMEOUT = 20 * 60   # 原 3600s → 20 min
DEFAULT_PHUNTER_TIMEOUT   = 5  * 60   # 原 900s  → 5  min

# 【新增】PHunter 并发限制：同时运行的 JVM 实例数上限
MAX_PHUNTER_CONCURRENT = int(os.getenv("MAX_PHUNTER_CONCURRENT", "3"))

# 【新增】相似度阈值，支持环境变量覆盖
LIB_SIMILAR_THRESHOLD = float(os.getenv("LH_LIB_THRESHOLD", "0.85"))

# 【新增】心跳超时：子进程超过此秒数无新输出则视为卡死
SUBPROCESS_HEARTBEAT_TIMEOUT = int(os.getenv("HEARTBEAT_TIMEOUT", "60"))


def build_pythonpath() -> str:
    """将 LibHunter 根目录注入 PYTHONPATH，让子进程能找到 module 包"""
    paths = [str(LIBHUNTER_DIR)]
    existing = os.environ.get("PYTHONPATH")
    if existing:
        paths.append(existing)
    return os.pathsep.join(paths)


def ensure_runtime_dirs() -> None:
    for path in (INPUT_DIR, OUTPUT_DIR, LOG_DIR, RAW_DIR,
                 REPORT_DIR, DATA_DIR, PATCH_DIR, PICKLE_CACHE_DIR):
        path.mkdir(parents=True, exist_ok=True)