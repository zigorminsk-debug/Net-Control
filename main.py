#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Точка входа Net-Control.

Запускает локальный HTTP-сервер с HTML-интерфейсом и открывает
браузер. Используется как для разработки, так и для упаковки в
setup.exe через PyInstaller (build_setup.py).
"""
from __future__ import annotations

import argparse
import threading
import time
import webbrowser


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="Net-Control",
        description="Анализатор сетевого трафика: детектирование майнеров, "
                    "спамеров, C2-трафика и других угроз")
    parser.add_argument("--host", default="127.0.0.1",
                        help="хост для слушающего сокета (по умолчанию 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8123,
                        help="порт HTTP-интерфейса (по умолчанию 8123)")
    parser.add_argument("--no-browser", action="store_true",
                        help="не открывать браузер автоматически")
    args = parser.parse_args()

    from app.server import create_server

    server, port = create_server(args.host, args.port)
    url = f"http://127.0.0.1:{port}"
    print("=" * 60)
    print("  Net-Control — анализатор сетевого трафика")
    print("=" * 60)
    print(f"  Интерфейс:   {url}")
    print("  Закройте окно, чтобы завершить работу.")
    print("=" * 60)

    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nВыключение Net-Control…")
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
