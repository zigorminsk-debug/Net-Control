#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Сборка Net-Control в setup.exe (Windows) через PyInstaller.

Запуск:
    python build_setup.py

Результат: dist/Net-Control.exe — одинарный исполняемый файл,
не требующий установленного Python.

Сборку setup.exe можно выполнить только на Windows (PyInstaller не
создает кросс-платформенные Windows-исполняемые файлы). На сервере
GitHub Actions сборка выполняется автоматически в workflow
.github/workflows/build-setup.yml.
"""
from __future__ import annotations

import os
import subprocess
import sys

BASE = os.path.dirname(os.path.abspath(__file__))


def main() -> int:
    if sys.platform != "win32":
        print("[!] Сборка setup.exe возможна только на Windows.\n"
              "    PyInstaller не создает Windows-исполняемые файлы "
              "на других платформах.\n"
              "    Чтобы получить setup.exe:\n"
              "      1. Запустите этот скрипт на Windows (py build_setup.py)\n"
              "      2. Или запустите GitHub Actions workflow "
              ".github/workflows/build-setup.yml — артефакт скачается "
              "из вкладки Actions.")
        return 1

    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("[!] PyInstaller не установлен. Выполняю: pip install pyinstaller")
        subprocess.check_call([sys.executable, "-m", "pip", "install",
                               "pyinstaller"])

    web_src = os.path.join(BASE, "app", "web")
    web_dst = os.path.join("app", "web")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",            # один файл setup.exe
        "--windowed",           # без консоли
        "--name", "Net-Control",
        "--clean",
        "--noconfirm",
        "--exclude-module", "tkinter",
        "--exclude-module", "matplotlib",
        "--add-data", f"{web_src}{os.pathsep}{web_dst}",
        os.path.join(BASE, "main.py"),
    ]
    print("[*] Команда сборки:", " ".join(cmd))
    subprocess.check_call(cmd, cwd=BASE)

    exe = os.path.join(BASE, "dist", "Net-Control.exe")
    if os.path.exists(exe):
        size_mb = os.path.getsize(exe) / (1024 * 1024)
        print(f"[+] Сборка успешна: {exe} ({size_mb:.1f} МБ)")
        return 0
    print("[!] Ошибка: исполняемый файл не создан.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
