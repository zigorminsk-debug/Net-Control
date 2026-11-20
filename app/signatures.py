# -*- coding: utf-8 -*-
"""Сигналы угроз и правила определения подозрительной активности.

Списки можно дополнять вручную, либо создать файл signatures.user.json
в каталоге приложения со следующей структурой:

{
  "mining_domains": ["my-pool.example"],
  "c2_ips":        ["1.2.3.4"],
  "c2_domains":    ["bad.example"],
  "scan_paths":    ["/admin.php"],
  "spam_keywords": ["lotto winner"]
}

Списки из пользовательского файла merge-ятся со встроенными.
"""
from __future__ import annotations

import json
import os

# ---------------------------------------------------------------------------
# Криптомайнинг
# ---------------------------------------------------------------------------

# Порты, характерные для майнинг-пулов (Stratum и аналоги)
MINING_PORTS = {
    3333, 3334, 3335, 3336,
    4444, 4445, 4446,
    5555, 5556,
    7777,
    14444,
    18080,
    3032, 3033,
    13333,
    14433,
    27173,
}

# Известные пулы и сервисы майнинга (SNI, DNS-запросы, Host)
MINING_DOMAINS = {
    "minexmr.com",
    "nicehash.com",
    "nanopool.org",
    "minergate.com",
    "xmrpool.eu",
    "miner.farm",
    "crypto-pool.fr",
    "dwarfpool.com",
    "flypool.com",
    "rigpool.ru",
    "pool.minergate.com",
    "moneropool.com",
    "supportxmr.com",
    "miningpoolhub.net",
    "hashrate.net",
    "cryptonight.net",
    "hash-to-loot.com",
    "monerominer.rocks",
}

# Маркеры в полезной нагрузке, указывающие на майнинг-трафик
MINING_PAYLOAD_MARKERS = (
    b"stratum",
    b"xpub",
    b"xmr",
    b"ethpool",
    b"\"method\":\"login\"",
    b"\"method\":\"submit\"",
)

# ---------------------------------------------------------------------------
# C2 / ботнеты
# ---------------------------------------------------------------------------

# Примеры известных C2-адресов (примерный список, дополняйте)
C2_IPS = {
    "45.137.21.10",
    "91.218.114.12",
    "104.244.79.63",
}

C2_DOMAINS = {
    "c2.badactor.xyz",
    "cmd.evil-c2.net",
    "agent.telegram-c2.xyz",
    "update.malware-c2.example",
}

# ---------------------------------------------------------------------------
# Спам и фишинг
# ---------------------------------------------------------------------------

SPAM_KEYWORDS = {
    "free money",
    "loan approved",
    "viagra",
    "casino bonus",
    "crypto giveaway",
    "urgent business proposal",
    "you have won",
    "weight loss",
    "cheap loans",
}

# ---------------------------------------------------------------------------
# Сканирование и эксплойты
# ---------------------------------------------------------------------------

SCAN_PATHS = {
    "/wp-login.php",
    "/wp-admin/",
    "/wp-content/",
    "/xmlrpc.php",
    "/.env",
    "/.git/config",
    "/phpmyadmin/",
    "/phpmyadmin",
    "/administrator/",
    "/admin/",
    "/backup.zip",
    "/server-status",
    "/.ssh/id_rsa",
    "/manager/html",
    "/actuator/env",
    "/shell.php",
    "/cgi-bin/",
    "/webadmin/",
    "/login.php",
}

SQLI_PATTERNS = (
    b"union select",
    b"or 1=1",
    b"1' or '1'='1",
    b"drop table",
    b"exec(",
    b"xp_cmdshell",
)

# ---------------------------------------------------------------------------
# DGA-подобные DNS-запросы
# ---------------------------------------------------------------------------

#「Подозрительные」TLD, часто используемые ботнетами и майнерами
SUSPECT_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq",
    "click", "link", "pw", "cc", "su", "biz",
}

# ---------------------------------------------------------------------------
# Порты почтовых серверов (спам-рассылки)
# ---------------------------------------------------------------------------

SMTP_PORTS = {25, 465, 587, 2525}

# ---------------------------------------------------------------------------
# Default-настройки порогов детектирования
# ---------------------------------------------------------------------------

DEFAULT_SETTINGS = {
    # Сканирование: число различных портов-целей с одного хоста
    "scan_ports_warn": 20,
    "scan_ports_crit": 60,
    # Бипинг: минимум пакетов в потоке и максимум среднего интервала (сек)
    "beacon_min_count": 6,
    "beacon_max_interval": 3600,
    # Эксфильтрация: минимальный объём исходящих данных (МБ) и коэффициент
    "exfil_mb": 10,
    "exfil_ratio": 4,
    # Подозрительные DNS: энтропия домена
    "dns_entropy": 4.0,
    # Син-флуд: число SYN-пакетов с одного хоста
    "syn_flood_count": 200,
    # DDoS: число различных источников SYN на одну цель
    "ddos_src_count": 80,
}

# ---------------------------------------------------------------------------
# Пользовательские сигнатуры
# ---------------------------------------------------------------------------

def load_user_signatures(path: str | None = None) -> dict:
    """Загрузить пользовательские сигнатуры из JSON (если файл существует)."""
    if path is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "signatures.user.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    out = {}
    for key in ("mining_domains", "c2_ips", "c2_domains", "scan_paths",
                "spam_keywords"):
        val = data.get(key)
        if isinstance(val, list):
            out[key] = {str(v).lower() for v in val}
    return out
