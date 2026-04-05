import logging
import logging.handlers
import multiprocessing
import os
import os.path
from pathlib import Path

# ── 运行参数 ──────────────────────────────────────────────────
max_thread_num = multiprocessing.cpu_count()

# ── 【修改】pickle 缓存目录：优先使用环境变量传入的绝对路径 ──
# libhunter_adapter.py 在启动子进程前会通过环境变量 LH_PICKLE_DIR 传入
# BASE_DIR / data / lib_pickle_cache，确保跨工作目录有效。
_env_pickle_dir = os.environ.get("LH_PICKLE_DIR", "")
if _env_pickle_dir:
    pickle_dir = _env_pickle_dir
else:
    # 回退：以本文件位置推算项目根
    _module_dir = Path(__file__).resolve().parent        # LibHunter/module/
    _project_root = _module_dir.parent.parent            # project/
    pickle_dir = str(_project_root / "data" / "lib_pickle_cache")

os.makedirs(pickle_dir, exist_ok=True)

# 检测模式
detect_type = "lib_version"

class_similar  = 1
method_similar = 0.75
lib_similar    = float(os.environ.get("LH_LIB_THRESHOLD", "0.85"))  # 不再硬编码 0.1

log_file = "log.txt"


def clear_log():
    if os.path.exists(log_file):
        os.remove(log_file)


def setup_logger():
    logger = logging.getLogger()
    if not logger.handlers:
        if multiprocessing.current_process().name == "MainProcess":
            logger.setLevel(logging.INFO)
            fh = logging.FileHandler(log_file, 'a', encoding='utf-8')
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - [%(lineno)d] - %(message)s'
            )
            fh.setFormatter(formatter)
            logger.addHandler(fh)
    return logger


def listener_process(queue):
    logger = logging.getLogger()
    fh = logging.FileHandler(log_file, 'a', encoding='utf-8')
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - [%(lineno)d] - %(message)s'
    )
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    logger.setLevel(logging.INFO)

    while True:
        record = queue.get()
        if record is None:
            break
        logger.handle(record)

    logger.removeHandler(fh)
    fh.close()


def worker_init(queue):
    h = logging.handlers.QueueHandler(queue)
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(h)
    root.setLevel(logging.INFO)