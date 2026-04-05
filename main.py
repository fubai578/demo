from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from config import REPORT_DIR, ensure_runtime_dirs
from engine.scanner import AndroidVulnScanner


def print_banner() -> None:
    banner = """
    ========================================================
     Android TPL & Vulnerability Detection System (Scanner)
     -> Powered by LibHunter & PHunter Probes
    ========================================================
    """
    print(banner)


def save_final_report(apk_name: str, report_data: dict) -> Path:
    report_path = REPORT_DIR / f"{apk_name}_vuln_report.json"
    report_path.write_text(
        json.dumps(report_data, indent=4, ensure_ascii=False),
        encoding="utf-8",
    )
    return report_path


def main() -> int:
    ensure_runtime_dirs()
    print_banner()

    parser = argparse.ArgumentParser(description="一键化安卓第三方库与已知 CVE 漏洞扫描系统")
    parser.add_argument("--apk", required=True, help="目标 APK 文件路径")
    args = parser.parse_args()

    apk_path = Path(args.apk).expanduser().resolve()
    if not apk_path.exists():
        print(f"[-] 错误: 找不到目标 APK 文件 -> {apk_path}")
        return 1

    start_time = time.time()
    try:
        scanner = AndroidVulnScanner(apk_path)
    except Exception as e:
        print(f"[-] 引擎初始化失败: {e}")
        return 1

    try:
        final_report = scanner.scan()
    except Exception as e:
        print(f"\n[-] 严重错误: 扫描过程中断 -> {e}")
        import traceback
        traceback.print_exc()
        return 1

    report_file = save_final_report(scanner.apk_info["name"], final_report)
    elapsed_time = time.time() - start_time

    print("\n" + "=" * 56)
    print(" [✓] 分 析 完 成 ")
    print("=" * 56)
    print(f"  - 目标应用: {scanner.apk_info['name']}")
    print(f"  - 使用组件: {len(final_report.get('used_libraries', []))} 个")
    print(f"  - 发现漏洞: {len(final_report.get('vulnerabilities', []))} 个")
    print(f"  - 耗时总计: {elapsed_time:.2f} 秒")
    print(f"  - 报告路径: {report_file}")
    print("=" * 56 + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
