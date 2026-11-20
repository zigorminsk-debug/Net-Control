#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Smoke-тест ядра анализатора: демо-pcap → парсинг → детекции → результат.

Запуск:  python tests/test_smoke.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.analyzer import AnalysisEngine, parse_pcap_bytes
from app.demo_gen import build_demo_pcap


def main() -> int:
    pcap = build_demo_pcap()
    assert len(pcap) > 1000, "demo pcap слишком мал"

    engine = AnalysisEngine()
    packets = 0
    for pkt in parse_pcap_bytes(pcap):
        engine.process_packet(pkt)
        packets += 1
    engine.finalize()

    result = engine.build_result()
    meta, stats = result["meta"], result["stats"]

    assert packets > 500, f"парсинг произвёл слишком мало пакетов: {packets}"
    assert meta["packets"] == packets
    assert stats["hosts_count"] >= 5
    assert stats["alerts_count"] >= 5

    hosts = {h["ip"]: h for h in result["hosts"]}
    assert "192.168.1.20" in hosts, "не найден майнер"
    assert "192.168.1.30" in hosts, "не найден спаммер"
    assert "192.168.1.40" in hosts, "не найден C2-хост"
    assert "192.168.1.50" in hosts, "не найден сканер"
    assert "192.168.1.60" in hosts, "не найден эксфильтрационный хост"
    assert "192.168.1.70" in hosts, "не найдена жертва DDoS"

    miner = hosts["192.168.1.20"]
    assert miner["cats"].get("mining", 0) >= 1, "майнер не зафиксирован"
    assert miner["cats"].get("dns", 0) >= 1, "майнер не зафиксирован по DNS"
    assert miner["severity"] == "critical", miner

    c2 = hosts["192.168.1.40"]
    assert c2["cats"].get("c2", 0) >= 1
    assert c2["cats"].get("beacon", 0) >= 1, "бипинг не зафиксирован"
    assert c2["severity"] == "critical"

    scanner = hosts["192.168.1.50"]
    assert scanner["cats"].get("scan", 0) >= 1

    spam = hosts["192.168.1.30"]
    assert spam["cats"].get("spam", 0) >= 1
    assert spam["cats"].get("scan", 0) >= 1

    exfil = hosts["192.168.1.60"]
    assert exfil["cats"].get("exfil", 0) >= 1

    victim = hosts["192.168.1.70"]
    assert victim["cats"].get("ddos", 0) >= 1

    # нормальный хост не должен быть поднят выше информации
    normal = hosts.get("192.168.1.10")
    assert normal is not None and normal["severity"] == "info", normal

    # детализация доступна
    detail = result["detail"]["192.168.1.20"]
    assert detail["connections"], "нет детализации соединений"
    assert detail["timeline"], "нет временного ряда"

    categories = stats["categories"]
    for cat in ("mining", "c2", "spam", "scan", "beacon", "exfil", "ddos"):
        assert cat in categories, f"нет категории {cat}"

    print("smoke OK:", packets, "пакетов,",
          stats["hosts_count"], "хостов,",
          stats["alerts_count"], "тревог,",
          stats["critical_count"], "критических")
    print("категории:", dict(categories))
    return 0


if __name__ == "__main__":
    sys.exit(main())
