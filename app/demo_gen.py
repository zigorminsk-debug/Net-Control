# -*- coding: utf-8 -*-
"""Генерация демонстрационного pcap-файла с разнообразными сценариями
сетевой активности, включая вредоносную (майнер, спаммер, C2-бипинг,
сканирование, эксфильтрация, DDoS).

Используется для демо-анализа и тестов.
"""
from __future__ import annotations

import os
import random
import struct

BASE_TS = 1700000000.0


def _ip(s: str) -> bytes:
    return bytes(int(x) for x in s.split("."))


def _eth(dst_mac: bytes, src_mac: bytes, etype: int, payload: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", etype) + payload


def _ipv4(src: str, dst: str, proto: int, payload: bytes,
          ident: int = 0) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident & 0xFFFF, 0,
                      64, proto, 0, _ip(src), _ip(dst))
    return hdr + payload


def _tcp(sport: int, dport: int, flags: int, payload: bytes,
         seq: int = 1000, ack: int = 1000) -> bytes:
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack,
                      0x50, flags, 8192, 0, 0)
    return hdr + payload


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _dns(domain: str, qid: int = 0x1234) -> bytes:
    qname = b""
    for label in domain.split("."):
        qname += bytes([len(label)]) + label.encode()
    qname += b"\x00"
    return (struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
            + qname + struct.pack("!HH", 1, 1))


def _tls_hello(sni: str) -> bytes:
    name = sni.encode()
    list_len = 3 + len(name)
    entry = b"\x00" + struct.pack("!H", len(name)) + name
    ext_data = struct.pack("!H", list_len) + entry
    ext = struct.pack("!HH", 0, len(ext_data)) + ext_data
    body = (b"\x03\x03" + b"\x00"
            + struct.pack("!H", 2) + b"\x00\x2f"
            + b"\x01\x00"
            + struct.pack("!H", len(ext)) + ext)
    hs = b"\x01" + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def _pcap(records) -> bytes:
    out = bytearray()
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, data in records:
        out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6),
                           len(data), len(data))
        out += data
    return bytes(out)


def _inc(rnd: random.Random, fast, slow, fast_p: float) -> float:
    """Бимодальный интервал между пакетами — для естественной
    нерегулярности нормального трафика (cv > 0.5, чтобы бипинг
    детектировал только настоящую C2-регулярность)."""
    if rnd.random() < fast_p:
        return rnd.uniform(*fast)
    return rnd.uniform(*slow)


def build_demo_pcap() -> bytes:
    rnd = random.Random(42)
    records = []
    ident = 1

    def emit(ts: float, data: bytes):
        nonlocal ident
        ident += 1
        records.append((ts, data))

    MACS = {
        "192.168.1.10": b"\x00\x11\x22\x33\x44\x01",
        "192.168.1.11": b"\x00\x11\x22\x33\x44\x02",
        "192.168.1.12": b"\x00\x11\x22\x33\x44\x03",
        "192.168.1.20": b"\x00\x11\x22\x33\x44\x14",
        "192.168.1.30": b"\x00\x11\x22\x33\x44\x1e",
        "192.168.1.40": b"\x00\x11\x22\x33\x44\x28",
        "192.168.1.50": b"\x00\x11\x22\x33\x44\x32",
        "192.168.1.60": b"\x00\x11\x22\x33\x44\x3c",
        "192.168.1.70": b"\x00\x11\x22\x33\x44\x46",
    }
    gw_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    gw_ip = "192.168.1.1"

    def to_gw(src: str, data: bytes, proto: int = 17) -> bytes:
        return _eth(gw_mac, MACS.get(src, b"\x00\x00\x00\x00\x00\x00"),
                    0x0800, _ipv4(src, gw_ip, proto, data, ident))

    def from_gw(dst: str, data: bytes) -> bytes:
        return _eth(MACS.get(dst, b"\x00\x00\x00\x00\x00\x00"), gw_mac,
                    0x0800, _ipv4(gw_ip, dst, 0, data, ident))

    def conn(src: str, dst: str, sport: int, dport: int,
             flags: int, payload: bytes, ts: float,
             via_gw: bool = True) -> None:
        seg = _tcp(sport, dport, flags, payload)
        pkt = _ipv4(src, dst, 6, seg, ident)
        if via_gw:
            emit(ts, _eth(gw_mac, MACS.get(src, b"\x00" * 6),
                          0x0800, pkt))
        else:
            emit(ts, _eth(b"\x02\x00\x00\x00\x00\x01",
                          MACS.get(src, b"\x00" * 6), 0x0800, pkt))

    # ------------------------------------------------------------------
    # 1) Нормальные хосты — веб- browsing, потоковое видео, DNS
    # ------------------------------------------------------------------
    web_ip = "93.184.216.34"
    stream_ip = "203.0.113.20"

    cursor = BASE_TS
    for i in range(12):
        cursor += _inc(rnd, (8, 15), (30, 55), 0.75)
        ts = cursor
        # DNS-запрос
        q = _udp(5353 + i, 53, _dns("example.com"))
        emit(ts, to_gw("192.168.1.10", q, 17))
        # TLS к сайту
        conn("192.168.1.10", web_ip, 40000 + i, 443, 0x18,
             _tls_hello("example.com"), ts + 0.1)
        # HTTP-запрос и ответ
        req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        conn("192.168.1.10", web_ip, 40010 + i, 80, 0x18, req, ts + 0.2)

    cursor = BASE_TS
    for i in range(10):
        cursor += _inc(rnd, (10, 18), (35, 60), 0.8)
        ts = cursor
        q = _udp(5400 + i, 53, _dns("cdn.example.org"))
        emit(ts, to_gw("192.168.1.12", q, 17))
        conn("192.168.1.12", web_ip, 41000 + i, 443, 0x18,
             _tls_hello("cdn.example.org"), ts + 0.1)

    cursor = BASE_TS + 5
    for i in range(20):
        cursor += _inc(rnd, (4, 9), (20, 35), 0.8)
        ts = cursor
        conn("192.168.1.11", stream_ip, 42000 + i, 80, 0x18,
             b"GET /video HTTP/1.1\r\nHost: stream.example\r\n\r\n", ts)
        conn("192.168.1.11", stream_ip, 42000 + i, 80, 0x10,
             b"\x00" * 50000, ts + 0.01)  # входящий ответ (большие данные внутрь)

    # ------------------------------------------------------------------
    # 2) Криптомайнер 192.168.1.20
    # ------------------------------------------------------------------
    pool = "185.220.101.45"
    ts = BASE_TS + 20
    q = _udp(5500, 53, _dns("pool.minexmr.com"))
    emit(ts, to_gw("192.168.1.20", q, 17))
    # подключение к пулу на порту 3333 + сдача хэшей
    conn("192.168.1.20", pool, 45000, 3333, 0x02, b"", ts + 0.5)
    conn("192.168.1.20", pool, 45000, 3333, 0x10, b"", ts + 0.51)
    login = b'{"id":1,"method":"login","params":["stratum","worker","x"]}'
    conn("192.168.1.20", pool, 45001, 3333, 0x18, login, ts + 0.6)
    for i in range(40):
        t = ts + 1 + i * 3 + rnd.uniform(-2.5, 4)
        share = b'{"id":2,"method":"submit","params":["share", 0x0a, 0x0b]}'
        conn("192.168.1.20", pool, 45001 + i % 4, 3333, 0x18, share, t)
    # DGA-подобные DNS-запросы
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    for i in range(8):
        dga = "".join(rnd.choice(alphabet) for _ in range(22)) + ".xyz"
        t = ts + 30 + i * 12 + rnd.uniform(-4, 6)
        q = _udp(5600 + i, 53, _dns(dga))
        emit(t, to_gw("192.168.1.20", q, 17))

    # ------------------------------------------------------------------
    # 3) Спаммер 192.168.1.30
    # ------------------------------------------------------------------
    ts = BASE_TS + 40
    spam_rcpts = "".join(f"RCPT TO:<user{i}@mail.example>\r\n" for i in range(15))
    mail = (b"EHLO mx.local\r\nMAIL FROM:<spam@evil.example>\r\n"
            + spam_rcpts.encode()
            + b"DATA\r\nSubject: Free money!!!\r\n\r\nYou have won "
              b"a crypto giveaway, send your wallet.\r\n.\r\nQUIT\r\n")
    conn("192.168.1.30", "87.255.200.10", 46000, 25, 0x18, mail, ts)
    mail_cursor = ts
    for i in range(10):
        mail_cursor += _inc(rnd, (3.5, 6), (12, 20), 0.7)
        t = mail_cursor
        conn("192.168.1.30", "87.255.200.11", 46001, 25, 0x18,
             b"EHLO x\r\nMAIL FROM:<s@e.x>\r\n"
             b"RCPT TO:<a1@x>\r\nRCPT TO:<a2@x>\r\nRCPT TO:<a3@x>\r\n"
             b"DATA\r\nloan approved\r\n.\r\n", t)
    # сканирование WP-сайтов + SQL-инъекции
    for i in range(14):
        t = ts + 10 + i * 2 + rnd.uniform(-1.2, 2.5)
        conn("192.168.1.30", "198.51.100.20", 46100 + i, 80, 0x18,
             b"GET /wp-login.php HTTP/1.1\r\nHost: site.example\r\n\r\n", t)
        conn("192.168.1.30", "198.51.100.21", 46110 + i, 80, 0x18,
             b"POST / HTTP/1.1\r\nHost: site2.example\r\n\r\n"
             b"id=1' UNION SELECT password FROM users--", t + 0.5)
        conn("192.168.1.30", "198.51.100.22", 46120 + i, 80, 0x18,
             b"GET /xmlrpc.php HTTP/1.1\r\nHost: site3.example\r\n\r\n", t + 1)

    # ------------------------------------------------------------------
    # 4) C2-бипинг 192.168.1.40
    # ------------------------------------------------------------------
    ts = BASE_TS + 60
    conn("192.168.1.40", "45.137.21.10", 47000, 7443, 0x02, b"", ts)
    conn("192.168.1.40", "45.137.21.10", 47000, 7443, 0x18, b"\x02\x01\x00\x00", ts)
    for i in range(7):
        t = ts + (i + 1) * 60
        conn("192.168.1.40", "45.137.21.10", 47000, 7443, 0x18,
             b"\x02\x01\x00\x00", t)
    q = _udp(5700, 53, _dns("c2.badactor.xyz"))
    emit(ts, to_gw("192.168.1.40", q, 17))

    # ------------------------------------------------------------------
    # 5) Сканер 192.168.1.50
    # ------------------------------------------------------------------
    ts = BASE_TS + 120
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443,
                  445, 993, 995, 1433, 3306, 3389, 5432, 5900,
                  6379, 8080]
    scan_targets = ["10.0.0.5", "10.0.0.9", "10.0.0.12",
                    "10.0.0.20", "10.0.0.30"]
    for target in scan_targets:
        for port in scan_ports:
            t = ts + rnd.uniform(0, 0.5)
            conn("192.168.1.50", target, 48000, port, 0x02, b"", t)
            conn("192.168.1.50", target, 48000, port, 0x12, b"", t + 0.001)

    # ------------------------------------------------------------------
    # 6) Эксфильтрация 192.168.1.60
    # ------------------------------------------------------------------
    ts = BASE_TS + 200
    exfil_dst = "188.166.32.10"
    conn("192.168.1.60", exfil_dst, 49000, 8443, 0x02, b"", ts)
    conn("192.168.1.60", exfil_dst, 49000, 8443, 0x10, b"", ts + 0.01)
    exfil_payload = os.urandom(60000)
    for i in range(200):
        t = ts + 0.1 + i * 0.4
        conn("192.168.1.60", exfil_dst, 49000, 8443, 0x18, exfil_payload, t)

    # ------------------------------------------------------------------
    # 7) DDoS на 192.168.1.70
    # ------------------------------------------------------------------
    ts = BASE_TS + 300
    for i in range(150):
        src = f"10.0.{i // 250}.{i % 250 + 1}"
        for _ in range(2):
            t = ts + rnd.uniform(0, 2)
            conn(src, "192.168.1.70", 50000 + i, 80, 0x02, b"", t,
                 via_gw=False)

    return _pcap(records)


if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "demo.pcap"
    with open(out, "wb") as f:
        f.write(build_demo_pcap())
    print("demo pcap written:", out, os.path.getsize(out), "bytes")
