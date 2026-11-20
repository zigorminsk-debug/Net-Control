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

# Скоп логирования сборки (остаётся доступным для _write_log)
_LOG: list[str] = []


def main() -> int:
    def _log(msg: str) -> None:
        print(msg)
        _LOG.append(msg)

    if sys.platform != "win32":
        msg = ("[!] Сборка setup.exe возможна только на Windows.\n"
               "    PyInstaller не создает Windows-исполняемые файлы "
               "на других платформах.\n"
               "    Чтобы получить setup.exe:\n"
               "      1. Запустите этот скрипт на Windows (py build_setup.py)\n"
               "      2. Или запустите GitHub Actions workflow "
               ".github/workflows/build-setup.yml — артефакт скачается "
               "из вкладки Actions.")
        _log(msg)
        _write_log()
        return 1

    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        _log("[!] PyInstaller не установлен. Выполняю: pip install pyinstaller")
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
        "--distpath", os.path.join(BASE, "dist"),
        "--workpath", os.path.join(BASE, "build"),
        "--specpath", os.path.join(BASE, "build"),
        "--exclude-module", "tkinter",
        "--add-data", f"{web_src}{os.pathsep}{web_dst}",
        os.path.join(BASE, "main.py"),
    ]
    _log("[*] Команда сборки: " + " ".join(cmd))

    # Получаем полный вывод PyInstaller и сохраняем в build.log,
    # чтобы лог ошибки доступен даже при сбое шага (через артефакт).
    try:
        proc = subprocess.run(cmd, cwd=BASE, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True)
        _log(proc.stdout or "")
        rc = proc.returncode
    except Exception as e:  # сбой запуска самого PyInstaller
        _log(f"[!] Не удалось запустить PyInstaller: {e!r}")
        import traceback
        _log(traceback.format_exc())
        rc = 1

    _log(f"[*] Код возврата PyInstaller: {rc}")
    _write_log()

    if rc != 0:
        _log("[!] Сборка завершилась с ошибкой. Полный лог: build.log")
        return 1

    exe = os.path.join(BASE, "dist", "Net-Control.exe")
    if os.path.exists(exe):
        size_mb = os.path.getsize(exe) / (1024 * 1024)
        _log(f"[+] Сборка успешна: {exe} ({size_mb:.1f} МБ)")
        return 0
    _log("[!] Ошибка: исполняемый файл не создан.")
    return 1


def _write_log() -> None:
    """Сохранить накопленный лог сборки в build.log (в любом случае)."""
    path = os.path.join(BASE, "build.log")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(_LOG))
    except OSError:
        pass


if __name__ == "__main__":
    sys.exit(main())
