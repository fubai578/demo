# LibHunter 程序入口
import argparse
import os
import sys
import zipfile

from module.lh_config import setup_logger, clear_log

sys.path.append(os.getcwd() + "/module")
from module.analyzer import search_lib_in_app, search_libs_in_app


def parse_arguments():
    parser = argparse.ArgumentParser(description="LibHunter: Android TPL detection")
    subparsers = parser.add_subparsers(help="sub-command help", dest="subparser_name")

    # ── detect_one：单库模式（多 APK 并行） ───────────────────────────────
    parser_one = subparsers.add_parser(
        "detect_one",
        help="Detection mode (Single): detect if multiple apps contain a specific TPL version",
    )
    parser_one.add_argument("-o",  metavar="FOLDER", type=str, default="outputs",
                            help="Output directory")
    parser_one.add_argument("-p",  metavar="num_processes", type=int, default=None,
                            help="Max number of processes (default=#CPU_cores)")
    parser_one.add_argument("-af", metavar="FOLDER", type=str, help="Directory of APKs")
    parser_one.add_argument("-lf", metavar="FOLDER", type=str, help="Directory of TPL JARs")
    parser_one.add_argument("-ld", metavar="FOLDER", type=str, help="Directory of TPL DEXes")

    # ── detect_all：多库模式（多库并行） ─────────────────────────────────
    parser_specific = subparsers.add_parser(
        "detect_all",
        help="Detection mode (Multiple): detect if multiple apps contain multiple TPL versions",
    )
    parser_specific.add_argument("-o",  metavar="FOLDER", type=str, default="outputs",
                                 help="Output directory")
    parser_specific.add_argument("-p",  metavar="num_processes", type=int, default=None,
                                 help="Max number of processes (default=#CPU_cores)")
    parser_specific.add_argument("-af", metavar="FOLDER", type=str, help="Directory of APKs")
    parser_specific.add_argument("-lf", metavar="FOLDER", type=str, help="Directory of TPL JARs")
    parser_specific.add_argument("-ld", metavar="FOLDER", type=str, help="Directory of TPL DEXes")

    return parser.parse_args()


def jar_to_dex(libs_folder, lib_dex_folder):
    """用 D8 把 JAR 转成 DEX 文件。"""
    for file in os.listdir(libs_folder):
        target_dex = lib_dex_folder + "/" + file[: file.rfind(".")] + ".dex"
        if os.path.exists(target_dex):
            continue
        input_file = libs_folder + "/" + file
        tmp_file = f"{lib_dex_folder}/classes.dex"
        if os.path.exists(tmp_file):
            os.remove(tmp_file)
        cmd = (
            f"java -cp libs/d8.jar com.android.tools.r8.D8 "
            f"--lib libs/android.jar --output {lib_dex_folder} {input_file}"
        )
        print(cmd)
        os.system(cmd)
        if os.path.exists(tmp_file):
            os.rename(tmp_file, target_dex)
        else:
            raise Exception("Dex file not converted!")


def arr_to_jar(libs_folder):
    """把 AAR 文件解压为 JAR 文件。"""
    for file in os.listdir(libs_folder):
        if file.endswith(".aar"):
            os.rename(
                libs_folder + "/" + file,
                libs_folder + "/" + file[: file.rfind(".")] + ".zip",
            )
    for file in os.listdir(libs_folder):
        target_name = libs_folder + "/" + file[: file.rfind(".")] + ".jar"
        if os.path.exists(target_name):
            return
        if file.endswith(".zip"):
            zip_file = zipfile.ZipFile(libs_folder + "/" + file)
            zip_file.extract("classes.jar", ".")
            for f in os.listdir(libs_folder):
                if f == "classes.jar":
                    os.rename(libs_folder + "/" + f, target_name)
            zip_file.close()
            os.remove(libs_folder + "/" + file)


def main(
    lib_folder="libs",
    lib_dex_folder="libs_dex",
    apk_folder="apks",
    output_folder="outputs",
    processes=None,
    model="multiple",
):
    if model == "multiple":
        search_libs_in_app(
            os.path.abspath(lib_dex_folder),
            os.path.abspath(apk_folder),
            os.path.abspath(output_folder),
            processes,
        )
    elif model == "one":
        search_lib_in_app(
            os.path.abspath(lib_dex_folder),
            os.path.abspath(apk_folder),
            os.path.abspath(output_folder),
            processes,
        )


if __name__ == "__main__":
    args = parse_arguments()

    # ── 路径解析修复 ──────────────────────────────────────────────────────
    # 原版代码：对相对路径做二次拼接到 SYSTEM_DATA_DIR，但适配器已传入绝对路径，
    # 导致路径变成 /project/data//absolute/path/xxx 之类的无效路径。
    # 修复策略：
    #   - 如果路径已经是绝对路径，直接使用，不做任何拼接。
    #   - 如果是相对路径，才拼接到脚本所在目录的上级 data/ 目录。
    SYSTEM_DATA_DIR = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "data")
    )

    def _resolve_path(p: str | None) -> str | None:
        if p is None:
            return None
        if os.path.isabs(p):
            return p                                   # 已是绝对路径，直接用
        return os.path.join(SYSTEM_DATA_DIR, os.path.basename(p))  # 相对路径，拼到 data/

    args.ld = _resolve_path(args.ld)
    args.lf = _resolve_path(args.lf)

    clear_log()
    LOGGER = setup_logger()
    LOGGER.debug("args: %s", args)

    if not os.path.exists(args.o):
        os.makedirs(args.o)

    if args.subparser_name == "detect_one":
        main(
            lib_folder=args.lf,
            lib_dex_folder=args.ld,
            apk_folder=args.af,
            output_folder=args.o,
            processes=args.p,
            model="one",
        )
    elif args.subparser_name == "detect_all":
        main(
            lib_folder=args.lf,
            lib_dex_folder=args.ld,
            apk_folder=args.af,
            output_folder=args.o,
            processes=args.p,
            model="multiple",
        )
    else:
        LOGGER.debug("Detection mode input error!")