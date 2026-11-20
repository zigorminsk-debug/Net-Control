# -*- coding: utf-8 -*-
"""Хранение последнего результата анализа в JSON (data/last_analysis.json).

Позволяет сохранить результат после анализа файла/демо и восстановить
его после перезапуска программы.
"""
from __future__ import annotations

import json
import os
import threading

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "data")
RESULT_PATH = os.path.join(DATA_DIR, "last_analysis.json")

_lock = threading.Lock()


def save_result(result: dict) -> bool:
    try:
        with _lock:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(RESULT_PATH, "w", encoding="utf-8") as f:
                json.dump(result, f, ensure_ascii=False)
        return True
    except OSError:
        return False


def load_result() -> dict | None:
    try:
        with open(RESULT_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
