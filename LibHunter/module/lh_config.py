# LibHunter 操作参数配置
import logging
import logging.handlers
import multiprocessing
import os.path

# ── 并发 ──────────────────────────────────────────────────────────────────────
# 最大进程数，默认使用所有 CPU 核心
# max_thread_num = multiprocessing.cpu_count()
max_thread_num = 2  # 调试时可限制并发数

# ── 缓存目录 ──────────────────────────────────────────────────────────────────
pickle_dir = "dex_pickles"
if not os.path.exists(pickle_dir):
    os.makedirs(pickle_dir)

# ── 检测粒度 ──────────────────────────────────────────────────────────────────
# "lib"         = TPL 级别检测（只识别库名）
# "lib_version" = TPL 版本级别检测（识别库名 + 版本号）
# 默认为版本级检测，需要在 conf/lib_name_map.csv 中提供映射
detect_type = "lib_version"

# ── 相似度阈值 ────────────────────────────────────────────────────────────────
# class_similar : 类级别匹配阈值（theta），1.0 = 要求完全匹配
# method_similar: 方法级别匹配阈值，0.75 经过论文验证
class_similar  = 1
method_similar = 0.75

# lib_similar   : 库级别匹配阈值（theta2），0.85 为论文推荐值
# 原始代码中此变量被连续赋值两次：先 0.85，再立刻被 0.1 覆盖，导致误报率极高。
# 修复：只保留一次赋值，使用论文推荐值 0.85。
lib_similar = 0.85

# ── 日志 ─────────────────────────────────────────────────────────────────────
log_file = "log.txt"


def clear_log():
    if os.path.exists(log_file):
        os.remove(log_file)


def setup_logger():
    logger = logging.getLogger()
    if not logger.handlers:
        if multiprocessing.current_process().name == "MainProcess":
            logger.setLevel(logging.INFO)
            fh = logging.FileHandler(log_file, "a", encoding="utf-8")
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - [%(lineno)d] - %(message)s"
            )
            fh.setFormatter(formatter)
            logger.addHandler(fh)
    return logger


def listener_process(queue):
    logger = logging.getLogger()
    fh = logging.FileHandler(log_file, "a", encoding="utf-8")
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - [%(lineno)d] - %(message)s"
    )
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    logger.setLevel(logging.INFO)

    while True:
        record = queue.get()
        if record is None:  # None 作为哨兵，通知监听进程退出
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