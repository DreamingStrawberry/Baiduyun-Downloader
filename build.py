#!/usr/bin/env python3
"""PyInstaller 빌드 스크립트 - 바이두 클라우드 다운로더"""
import subprocess
import sys

def main():
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--windowed",
        "--name", "BaiduyunDownloader",
        "--noconfirm",
        "--icon", "app_icon.ico",
        "--add-data", "app_icon.ico;.",
        "--exclude-module", "playwright",
        "baidu_dl.py",
    ]
    print("빌드 시작...")
    print(f"명령: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if result.returncode == 0:
        print("\n빌드 완료! dist/BaiduDownloader.exe")
    else:
        print(f"\n빌드 실패 (exit code {result.returncode})")
        sys.exit(1)


if __name__ == "__main__":
    main()
