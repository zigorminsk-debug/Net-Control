# -*- coding: utf-8 -*-
"""Ядро анализатора сетевого трафика Net-Control.

Парсинг pcap-файлов и живого трафика + детектирование подозрительной
активности хостов: криптомайнинг, спам, сканирование, C2-бипинг,
эксфильтрация данных, син-флуд, DDoS, DGA-подобные DNS-запросы.

Модуль работает только на стандартной библиотеке Python.
"""
from __future__ import annotations

import math
import re
import struct
import threading
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .signatures import (
    DEFAULT_SETTINGS,
    MINING_DOMAINS,
    MINING_PORTS,
    MINING_PAYLOAD_MARKERS,
    C2_DOMAINS,
    C2_IPS,
    SCAN_PATHS,
    SPAM_KEYWORDS,
    SQLI_PATTERNS,
    SUSPECT_TLDS,
    SMTP_PORTS,
    load_user_signatures,
)

# ---------------------------------------------------------------------------
# Константы
# ---------------------------------------------------------------------------

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 12
LINKTYPE_RAW_IP = 101
LINKTYPE_LINUX_SLL2 = 276

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

SEVERITY_CRITICAL = "critical"
SEVERITY_WARNING = "warning"
SEVERITY_INFO = "info"

SEVERITY_RU = {
    SEVERITY_CRITICAL: "критический",
    SEVERITY_WARNING: "предупреждение",
    SEVERITY_INFO: "информация",
}

WEIGHTS = {
    "mining": 45,
    "c2": 45,
    "ddos": 35,
    "exfil": 30,
    "scan": 25,
    "beacon": 20,
    "flood": 20,
    "spam": 18,
    "dns": 15,
    "crypto": 5,
}

ALERT_TEXTS = {
    "mining": ("Криптомайнинг",
               "Хост подключается к майнинг-пулу (порт Stratum или домен пула)"),
    "c2": ("C2-командный центр",
           "Обнаружена связь с известным C2-адресом или доменом"),
    "spam": ("Спам-активность",
             "Хост выполняет спам-рассылку (SMTP) или фишинговые запросы"),
    "scan": ("Сканирование и эксплойты",
             "Хост сканирует порты или отправляет запросы к exploit-пути"),
    "beacon": ("Бипинг (потенциальный C2-канал)",
               "Регулярные периодические подключения к одному внешнему адресу"),
    "exfil": ("Эксфильтрация данных",
              "Резкий выброс исходящих данных на внешний адрес"),
    "dns": ("Подозрительные DNS-запросы",
            "Запросы к доменам с высокой случайностью (DGA-подобные)"),
    "flood": ("Син-флуд",
              "Массовая отправка SYN-пакетов с хоста"),
    "ddos": ("DDoS-атака",
             "Массовые SYN-запросы со многих источников на один хост"),
    "crypto": ("Криптовалютные адреса",
               "В трафике найдены биткоин-адреса"),
}

DEFAULT_SEVERITY = {
    "mining": SEVERITY_CRITICAL,
    "c2": SEVERITY_CRITICAL,
    "ddos": SEVERITY_CRITICAL,
    "exfil": SEVERITY_WARNING,
    "scan": SEVERITY_WARNING,
    "beacon": SEVERITY_WARNING,
    "flood": SEVERITY_WARNING,
    "spam": SEVERITY_WARNING,
    "dns": SEVERITY_WARNING,
    "crypto": SEVERITY_INFO,
}

WALLET_RE = re.compile(r"\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b")

_METHODS = {b"GET", b"POST", b"PUT", b"DELETE", b"HEAD",
            b"OPTIONS", b"CONNECT", b"TRACE", b"PATCH"}

# Ограничения памяти (защита от огромных capture-ов)
MAX_HOSTS = 5000
MAX_CONNS_PER_HOST = 500
MAX_DNS_PER_HOST = 200
MAX_BUCKETS = 600           # 10 сек * 600 = 100 минут окна
MAX_FLOWS = 30000
MAX_TS_LIST = 150
MAX_EVIDENCE = 8
MAX_ALERTS = 3000


# ---------------------------------------------------------------------------
# Основные структуры
# ---------------------------------------------------------------------------

@dataclass
class Packet:
    ts: float
    src: str
    dst: str
    proto: str
    sport: int = 0
    dport: int = 0
    flags: str = ""
    payload: bytes = b""
    sni: str = ""
    dns_queries: List[str] = field(default_factory=list)
    http_path: str = ""
    http_host: str = ""


@dataclass
class ConnAgg:
    dst: str
    dport: int
    proto: str
    packets: int = 0
    bytes_out: int = 0      # с хоста → dst
    bytes_in: int = 0       # с dst → хост
    first_ts: float = 0.0
    last_ts: float = 0.0
    cats: Set[str] = field(default_factory=set)


@dataclass
class FlowAgg:
    src: str
    dst: str
    dport: int
    proto: str
    ts_list: List[float] = field(default_factory=list)
    packets: int = 0
    bytes_total: int = 0


@dataclass
class HostAgg:
    ip: str
    first_ts: float = 0.0
    last_ts: float = 0.0
    packets: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    conns: Counter = field(default_factory=Counter)
    ports: Set[int] = field(default_factory=set)
    protos: Counter = field(default_factory=Counter)
    dns_domains: Set[str] = field(default_factory=set)
    external_dsts: Set[str] = field(default_factory=set)
    syn_count: int = 0
    connections: List[ConnAgg] = field(default_factory=list)
    buckets: Dict[int, List[int]] = field(default_factory=lambda: defaultdict(lambda: [0, 0]))
    cat_counts: Counter = field(default_factory=Counter)
    cat_sev: Dict[str, str] = field(default_factory=dict)
    evidence: Dict[str, List[str]] = field(default_factory=lambda: defaultdict(list))


# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------

def is_private_ip(ip: str) -> bool:
    """Приватный/локальный адрес (IPv4). Для IPv6 приближённо."""
    try:
        parts = ip.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            a, b = int(parts[0]), int(parts[1])
            return (a == 10 or a == 127 or
                    (a == 172 and 16 <= b <= 31) or
                    (a == 192 and b == 168) or
                    (a == 169 and b == 254) or
                    a == 0)
    except (ValueError, AttributeError):
        pass
    return (ip.startswith("fe80") or ip.startswith("fc") or
            ip.startswith("fd") or ip == "::1")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def flags_to_str(f: int) -> str:
    parts = []
    if f & 0x02: parts.append("SYN")
    if f & 0x10: parts.append("ACK")
    if f & 0x01: parts.append("FIN")
    if f & 0x04: parts.append("RST")
    if f & 0x08: parts.append("PSH")
    if f & 0x20: parts.append("URG")
    return ",".join(parts)


def _ipv6_str(b: bytes) -> str:
    groups = [b[i:i + 2] for i in range(0, 16, 2)]
    return ":".join(f"{int.from_bytes(g, 'big'):x}" for g in groups)


# ---------------------------------------------------------------------------
# Парсинг пакетов
# ---------------------------------------------------------------------------

def parse_dns(payload: bytes) -> List[str]:
    """Извлечь имена вопросов из DNS-пакета (только запросы)."""
    if len(payload) < 12:
        return []
    queries: List[str] = []
    try:
        qd = struct.unpack("!H", payload[4:6])[0]
        pos = 12
        for _ in range(qd):
            labels: List[str] = []
            while pos < len(payload):
                l = payload[pos]
                if l == 0:
                    pos += 1
                    break
                if l & 0xC0:  # указатель на отдельную секцию — стоп
                    return queries
                pos += 1
                if pos + l > len(payload):
                    return queries
                labels.append(payload[pos:pos + l].decode("ascii", "ignore"))
                pos += l
            if pos + 4 > len(payload):
                break
            pos += 4  # qtype + qclass
            if labels:
                queries.append(".".join(labels).lower())
    except Exception:
        pass
    return queries


def parse_tls_sni(payload: bytes) -> str:
    """Извлечь SNI из TLS ClientHello."""
    try:
        if len(payload) < 40 or payload[0] != 0x16 or payload[5] != 0x01:
            return ""
        pos = 6
        sid_len = payload[pos]
        pos += 1 + sid_len
        if pos + 2 > len(payload):
            return ""
        cs_len = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2 + cs_len
        if pos >= len(payload):
            return ""
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return ""
        ext_total = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2
        end = pos + ext_total
        while pos + 4 <= end and pos + 4 <= len(payload):
            etype, elen = struct.unpack("!HH", payload[pos:pos + 4])
            pos += 4
            if pos + elen > len(payload):
                break
            if etype == 0:  # server_name
                if pos + 2 > len(payload):
                    break
                nlen = struct.unpack("!H", payload[pos:pos + 2])[0]
                pos += 2
                if pos + 3 > len(payload):
                    break
                ntype = payload[pos]
                nl = struct.unpack("!H", payload[pos + 1:pos + 3])[0]
                if ntype == 0 and pos + 3 + nl <= len(payload):
                    return payload[pos + 3:pos + 3 + nl].decode("ascii", "ignore")
                pos = pos + nlen if nlen else pos
                break
            pos += elen
    except Exception:
        return ""
    return ""


def parse_http(payload: bytes) -> Tuple[str, str]:
    """Извлечь Host и путь из запроса HTTP (упрощённо, без состояния)."""
    try:
        head = payload.split(b"\r\n\r\n", 1)[0]
        first = head.split(b"\r\n", 1)[0]
        parts = first.split()
        if len(parts) >= 2 and parts[0] in _METHODS and parts[-1].startswith(b"HTTP/"):
            path = parts[1].decode("latin1", "ignore")
        else:
            path = ""
        host = ""
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"host:"):
                host = line.split(b":", 1)[1].strip().decode("latin1", "ignore")
                break
        return host, path
    except Exception:
        return "", ""


def parse_link(data: bytes, linktype: int) -> Tuple[int, bytes]:
    """Разделить кадр на канальный уровень и payload. Вернуть (etype, payload)."""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return 0, b""
        etype = struct.unpack("!H", data[12:14])[0]
        off = 14
        if etype == 0x8100:  # VLAN
            if len(data) < 18:
                return 0, b""
            etype = struct.unpack("!H", data[16:18])[0]
            off = 18
        return etype, data[off:]

    if linktype == LINKTYPE_RAW_IP:
        return 0x0800 if (data and data[0] >> 4 == 4) else 0x86DD, data

    if linktype == LINKTYPE_NULL:
        if len(data) < 4:
            return 0, b""
        return 0x0800 if (data[0] >> 4 == 4) else 0x86DD, data[4:]

    if linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return 0, b""
        etype = struct.unpack("!H", data[14:16])[0]
        return etype, data[16:]

    if linktype == LINKTYPE_LINUX_SLL2:
        if len(data) < 20:
            return 0, b""
        etype = struct.unpack("!H", data[0:2])[0]
        return etype, data[20:]

    # Неизвестный linktype — пробуем как Ethernet
    if len(data) >= 14:
        etype = struct.unpack("!H", data[12:14])[0]
        if etype in (0x0800, 0x86DD):
            return etype, data[14:]
    return 0, b""


def parse_ip(data: bytes) -> Optional[Tuple[str, str, str, bytes]]:
    """Разобрать IPv4/IPv6. Вернуть (proto, src, dst, payload_transport)."""
    if not data:
        return None
    try:
        if data[0] >> 4 == 4:
            if len(data) < 20:
                return None
            ihl = (data[0] & 0x0F) * 4
            proto = data[9]
            src = ".".join(str(b) for b in data[12:16])
            dst = ".".join(str(b) for b in data[16:20])
            frag_off = struct.unpack("!H", data[6:8])[0] & 0x1FFF
            if frag_off != 0:  # фрагмент — анализ невозможен
                return (str(proto), src, dst, b"")
            return (str(proto), src, dst, data[ihl:])

        if data[0] >> 4 == 6:
            if len(data) < 40:
                return None
            nh = data[6]
            src = _ipv6_str(data[8:24])
            dst = _ipv6_str(data[24:40])
            off = 40
            # пропуск扩展-заголовков
            while nh in (0, 43, 60):
                if len(data) < off + 2:
                    break
                plen = (data[off + 1] + 1) * 8
                off += plen
                if off >= len(data):
                    break
                nh = data[off]
            if nh == 44:  # фрагмент
                off += 8
                if off < len(data):
                    nh = data[off]
                else:
                    return None
            if off >= len(data):
                return None
            return (str(nh), src, dst, data[off:])
    except (IndexError, struct.error):
        return None
    return None


def parse_transport(proto: str, data: bytes) -> Packet:
    """Разобрать TCP/UDP на уровне транспорта и собрать Packet."""
    sport = dport = 0
    flags = ""
    payload = data
    if proto == "6":  # TCP
        if len(data) < 20:
            return Packet(ts=0, src="", dst="", proto="OTHER")
        sport, dport = struct.unpack("!HH", data[0:4])
        flags = flags_to_str(data[13])
        doff = (data[12] >> 4) * 4
        if doff < len(data):
            payload = data[doff:]
    elif proto == "17":  # UDP
        if len(data) < 8:
            return Packet(ts=0, src="", dst="", proto="OTHER")
        sport, dport = struct.unpack("!HH", data[0:4])
        payload = data[8:]
    else:
        return Packet(ts=0, src="", dst="", proto="OTHER")
    return Packet(ts=0, src="", dst="", proto="TCP" if proto == "6" else "UDP",
                  sport=sport, dport=dport, flags=flags, payload=payload)


def parse_record(data: bytes, linktype: int, ts: float) -> Optional[Packet]:
    """Разобрать один пакет (кадр) со временной меткой."""
    etype, payload = parse_link(data, linktype)
    if etype not in (0x0800, 0x86DD):
        return None
    ip = parse_ip(payload)
    if ip is None:
        return None
    proto, src, dst, tdata = ip
    if proto == "1":
        pkt = Packet(ts=ts, src=src, dst=dst, proto="ICMP")
        return pkt
    if proto not in ("6", "17"):
        return Packet(ts=ts, src=src, dst=dst, proto="OTHER")
    pkt = parse_transport(proto, tdata)
    pkt.ts, pkt.src, pkt.dst = ts, src, dst
    if not pkt.payload:
        return pkt
    low = pkt.payload[:2048].lower()
    # DNS
    if pkt.dport == 53 or pkt.sport == 53:
        if pkt.dport == 53:
            pkt.dns_queries = parse_dns(pkt.payload)
    # TLS SNI
    sni = parse_tls_sni(pkt.payload)
    if sni:
        pkt.sni = sni.lower()
    # HTTP
    if pkt.dport in (80, 8080, 8000, 8888) or pkt.sport in (80, 8080, 8000, 8888):
        h, p = parse_http(pkt.payload)
        pkt.http_host, pkt.http_path = h, p
    return pkt


# ---------------------------------------------------------------------------
# Парсинг pcap-файла
# ---------------------------------------------------------------------------

def parse_pcap_bytes(data: bytes):
    """Генератор пакетов из pcap-файла (micro/nanosecond, LE/BE)."""
    if len(data) < 24:
        return
    if data[:4] == PCAPNG_MAGIC:
        raise ValueError(
            "Формат pcapng не поддерживается. Откройте файл в Wireshark "
            "и сохраните в формат pcap (File → Export Packets → as pcap).")
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, nano = "<", False
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, nano = ">", False
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, nano = "<", True
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, nano = ">", True
    else:
        raise ValueError("Недопустимый формат файла: это не pcap-файл.")
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    n = len(data)
    while off + 16 <= n:
        ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(
            endian + "IIII", data[off:off + 16])
        off += 16
        if incl_len > 0x4000000:  # защищён от ошибок размера
            break
        if off + incl_len > n:
            break
        chunk = data[off:off + incl_len]
        off += incl_len
        ts = ts_sec + (ts_frac / 1e9 if nano else ts_frac / 1e6)
        pkt = parse_record(chunk, linktype, ts)
        if pkt is not None:
            yield pkt


# ---------------------------------------------------------------------------
# Детектирование
# ---------------------------------------------------------------------------

class AnalysisEngine:
    """Конечный автомат анализа: накапливает агрегированные статистики
    по хостам и потокам, затем вычисляет тревоги и риск-баллы."""

    def __init__(self, settings: Optional[dict] = None):
        self.settings = dict(DEFAULT_SETTINGS)
        if settings:
            self.settings.update(settings)
        self.lock = threading.RLock()

        user = load_user_signatures()
        self.mining_ports = set(MINING_PORTS)
        self.mining_domains = set(MINING_DOMAINS) | user.get("mining_domains", set())
        self.c2_ips = set(C2_IPS) | user.get("c2_ips", set())
        self.c2_domains = set(C2_DOMAINS) | user.get("c2_domains", set())
        self.scan_paths = set(SCAN_PATHS) | user.get("scan_paths", set())
        self.spam_keywords = set(SPAM_KEYWORDS) | user.get("spam_keywords", set())
        self.reset()

    # ------------------------------------------------------------------
    def reset(self) -> None:
        with self.lock:
            self.hosts: Dict[str, HostAgg] = {}
            self.flows: Dict[Tuple, FlowAgg] = {}
            self.syn_victims: Dict[str, Counter] = {}
            self.alerts: List[dict] = []
            self.alert_buckets: Counter = Counter()
            self.packets = 0
            self.bytes_total = 0
            self.start_ts: Optional[float] = None
            self.end_ts: Optional[float] = None
            self.proto_counts: Counter = Counter()

    # ------------------------------------------------------------------
    def _host_for(self, ip: str) -> Optional[HostAgg]:
        if ip not in self.hosts:
            if len(self.hosts) >= MAX_HOSTS:
                return None
            h = HostAgg(ip=ip)
            self.hosts[ip] = h
        return self.hosts[ip]

    def _flag(self, h: HostAgg, cat: str, evidence: str,
              sev: Optional[str] = None, count: int = 1) -> None:
        if cat not in h.cat_counts:
            h.cat_counts[cat] = count
            if len(h.evidence[cat]) < MAX_EVIDENCE:
                h.evidence[cat].append(evidence)
            if sev:
                h.cat_sev[cat] = sev
        else:
            h.cat_counts[cat] += count
        if self.start_ts is not None:
            bucket = int(((h.last_ts or self.start_ts) - self.start_ts) // 10)
            if 0 <= bucket < MAX_BUCKETS:
                self.alert_buckets[bucket] += 1

    def _bucket(self, ts: float) -> int:
        return int((ts - self.start_ts) // 10)

    # ------------------------------------------------------------------
    def process_packet(self, pkt: Packet) -> None:
        with self.lock:
            if self.start_ts is None:
                self.start_ts = pkt.ts
            self.end_ts = pkt.ts
            self.packets += 1

            dlen = len(pkt.payload)
            self.bytes_total += dlen
            self.proto_counts[pkt.proto] += 1

            ext = not is_private_ip(pkt.dst)
            host = self._host_for(pkt.src)
            if host is None:
                return
            if host.first_ts == 0.0:
                host.first_ts = pkt.ts
            host.last_ts = pkt.ts
            host.packets += 1
            host.bytes_out += dlen

            if pkt.dst != pkt.src:
                rhost = self._host_for(pkt.dst)
                if rhost is not None:
                    rhost.bytes_in += dlen
                    rhost.packets += 1
                    if rhost.first_ts == 0.0:
                        rhost.first_ts = pkt.ts
                    rhost.last_ts = pkt.ts

            # агрегация соединений
            key = (pkt.dst, pkt.dport, pkt.proto)
            conn = None
            for c in host.connections:
                if (c.dst, c.dport, c.proto) == key:
                    conn = c
                    break
            if conn is None:
                if len(host.connections) >= MAX_CONNS_PER_HOST:
                    conn = None
                else:
                    conn = ConnAgg(dst=pkt.dst, dport=pkt.dport, proto=pkt.proto,
                                   first_ts=pkt.ts, last_ts=pkt.ts)
                    host.connections.append(conn)
            if conn is not None:
                conn.packets += 1
                conn.bytes_out += dlen
                conn.last_ts = pkt.ts
                if pkt.dst == host.ip:
                    conn.bytes_in += dlen
                if ext:
                    host.external_dsts.add(pkt.dst)

            host.conns[pkt.dst] += 1
            if pkt.dport:
                host.ports.add(pkt.dport)
            host.protos[pkt.proto] += 1

            # времёня-ряд по хосту (10-сековые бикеты)
            b = self._bucket(pkt.ts)
            if 0 <= b < MAX_BUCKETS:
                hb = host.buckets[b]
                hb[0] += 1
                hb[1] += dlen

            # ---- сигнатурные проверки (протокольный уровень) ----
            payload_low = pkt.payload[:2048].lower() if dlen else b""

            # 1) Криптомайнинг
            if pkt.dport in self.mining_ports:
                self._flag(host, "mining",
                           f"порт {pkt.dport} → {pkt.dst} (характерный для Stratum)")
            if pkt.sni and pkt.sni in self.mining_domains:
                self._flag(host, "mining", f"SNI {pkt.sni} (майнинг-пул)")
            if pkt.http_host and pkt.http_host.split(":")[0] in self.mining_domains:
                self._flag(host, "mining", f"HTTP Host {pkt.http_host} (майнинг-пул)")
            for q in pkt.dns_queries:
                if q in self.mining_domains:
                    self._flag(host, "mining", f"DNS-запрос к пулу {q}")
            for marker in MINING_PAYLOAD_MARKERS:
                if marker in payload_low:
                    self._flag(host, "mining", "в payload найден маркер майнинга")
                    break

            # 2) C2
            if pkt.dst in self.c2_ips:
                self._flag(host, "c2", f"соединение с известным C2-адресом {pkt.dst}")
            if pkt.sni and pkt.sni in self.c2_domains:
                self._flag(host, "c2", f"SNI {pkt.sni} (C2-домен)")
            for q in pkt.dns_queries:
                if q in self.c2_domains:
                    self._flag(host, "c2", f"DNS-запрос к C2-домену {q}")

            # 3) Спам
            if pkt.dport in SMTP_PORTS and payload_low:
                rcpt = payload_low.count(b"rcpt to:") + payload_low.count(b"to:")
                if rcpt >= 8:
                    self._flag(host, "spam",
                               f"SMTP-рассылка, адресатов в пакете: {rcpt}")
                for kw in self.spam_keywords:
                    if kw.encode() in payload_low:
                        self._flag(host, "spam", f"в payload найден спам-ключ «{kw}»")
                        break
            if pkt.http_path:
                if pkt.http_path in self.scan_paths:
                    self._flag(host, "scan",
                               f"HTTP-запрос к exploit-пути {pkt.http_path}")
                for pat in SQLI_PATTERNS:
                    if pat in payload_low:
                        self._flag(host, "scan",
                                   f"подозрительный SQL-инъекционный payload ({pat.decode()})")
                        break

            # 4) Криптовалютные адреса
            if dlen:
                m = WALLET_RE.search(pkt.payload[:2048].decode("latin1", "ignore"))
                if m:
                    self._flag(host, "crypto", f"биткоин-адрес в payload: {m.group(0)}")

            # 5) DNS-запросы
            for q in pkt.dns_queries:
                if len(host.dns_domains) < MAX_DNS_PER_HOST:
                    host.dns_domains.add(q)

            # 6) SYN-статы (для флуда / DDoS)
            if "SYN" in pkt.flags and "ACK" not in pkt.flags:
                host.syn_count += 1
                victims = self.syn_victims.setdefault(pkt.dst, Counter())
                if len(victims) < 500:
                    victims[pkt.src] += 1

            # 7) потоки для бипинг-анализа
            if len(self.flows) < MAX_FLOWS:
                fkey = (pkt.src, pkt.dst, pkt.dport, pkt.proto)
                fl = self.flows.get(fkey)
                if fl is None:
                    fl = FlowAgg(src=pkt.src, dst=pkt.dst,
                                 dport=pkt.dport, proto=pkt.proto)
                    self.flows[fkey] = fl
                fl.packets += 1
                fl.bytes_total += dlen
                if len(fl.ts_list) < MAX_TS_LIST:
                    fl.ts_list.append(pkt.ts)

    # ------------------------------------------------------------------
    def _finalize_host(self, h: HostAgg) -> None:
        """Вычислить статистически-ориентированные детекции для хоста."""
        if "beacon" not in h.cat_counts:
            for fl in self.flows.values():
                if fl.src != h.ip or len(fl.ts_list) < 6:
                    continue
                if fl.dport == 53:  # DNS-опросы часто периодичны — исключаем
                    continue
                ts_list = fl.ts_list
                intervals = [b - a for a, b in zip(ts_list, ts_list[1:])]
                if len(intervals) < 4:
                    continue
                mean = sum(intervals) / len(intervals)
                if mean < 2 or mean > self.settings["beacon_max_interval"]:
                    continue
                var = sum((x - mean) ** 2 for x in intervals) / len(intervals)
                std = math.sqrt(var)
                cv = std / mean if mean else 0
                if cv <= 0.5:
                    self._flag(h, "beacon",
                               f"бипинг → {fl.dst}:{fl.dport}, "
                               f"средний интервал {mean:.0f} с (cv={cv:.2f})")
                    break

        if "scan" not in h.cat_counts and len(h.ports) >= self.settings["scan_ports_warn"]:
            sev = (SEVERITY_CRITICAL if
                   len(h.ports) >= self.settings["scan_ports_crit"]
                   else SEVERITY_WARNING)
            self._flag(h, "scan",
                       f"просканировано портов: {len(h.ports)}", sev=sev)

        if "flood" not in h.cat_counts and h.syn_count >= self.settings["syn_flood_count"]:
            self._flag(h, "flood", f"SYN-пакетов: {h.syn_count}")

        if "exfil" not in h.cat_counts:
            for c in h.connections:
                out = c.bytes_out
                if out < self.settings["exfil_mb"] * 1_000_000:
                    continue
                ratio = out / (c.bytes_in + 1)
                if ratio >= self.settings["exfil_ratio"]:
                    sev = (SEVERITY_CRITICAL if out >= 100 * 1_000_000
                           else SEVERITY_WARNING)
                    self._flag(h, "exfil",
                               f"исходящих данных → {c.dst}:{c.dport}: "
                               f"{out / 1e6:.0f} МБ (коэффициент {ratio:.0f})",
                               sev=sev)
                    break

        if "dns" not in h.cat_counts:
            for d in h.dns_domains:
                tld = d.rsplit(".", 1)[-1]
                if (tld in SUSPECT_TLDS and len(d) >= 14 and
                        shannon_entropy(d) >= self.settings["dns_entropy"]):
                    self._flag(h, "dns",
                               f"DGA-подобный домен: {d} "
                               f"(энтропия {shannon_entropy(d):.1f})")
                    break

    def finalize(self) -> None:
        with self.lock:
            for h in self.hosts.values():
                self._finalize_host(h)
            # DDoS: жертвы с массовым потоком SYN
            for dst, srcs in self.syn_victims.items():
                if len(srcs) < self.settings["ddos_src_count"]:
                    continue
                victim = self._host_for(dst)
                if victim is None:
                    continue
                if victim.first_ts == 0.0:
                    victim.first_ts = self.start_ts or 0.0
                victim.last_ts = self.end_ts or victim.first_ts
                if "ddos" not in victim.cat_counts:
                    self._flag(victim, "ddos",
                               f"SYN-запросов из {len(srcs)} источников")

    # ------------------------------------------------------------------
    def score_host(self, h: HostAgg) -> Tuple[int, str]:
        total = sum(WEIGHTS.get(c, 5) for c in h.cat_counts)
        if any(v == SEVERITY_CRITICAL for v in h.cat_sev.values()):
            total += 15
        total = min(100, total)
        if total >= 60:
            sev = SEVERITY_CRITICAL
        elif total >= 25:
            sev = SEVERITY_WARNING
        else:
            sev = SEVERITY_INFO
        return total, sev

    # ------------------------------------------------------------------
    def build_result(self) -> dict:
        with self.lock:
            hosts_out = []
            for ip, h in self.hosts.items():
                if h.packets == 0 and not h.cat_counts:
                    continue
                score, sev = self.score_host(h)
                hosts_out.append({
                    "ip": ip,
                    "score": score,
                    "severity": sev,
                    "severity_ru": SEVERITY_RU[sev],
                    "packets": h.packets,
                    "bytes_in": h.bytes_in,
                    "bytes_out": h.bytes_out,
                    "conns": len(h.conns),
                    "external_conns": len(h.external_dsts),
                    "ports": sorted(h.ports)[:50],
                    "ports_count": len(h.ports),
                    "protos": dict(h.protos),
                    "dns_count": len(h.dns_domains),
                    "first_ts": h.first_ts,
                    "last_ts": h.last_ts,
                    "cats": dict(h.cat_counts),
                })
            hosts_out.sort(key=lambda x: (-x["score"], x["ip"]))

            alerts = []
            for ip, h in self.hosts.items():
                for cat, cnt in h.cat_counts.items():
                    sev = h.cat_sev.get(cat, DEFAULT_SEVERITY.get(cat, SEVERITY_WARNING))
                    title, base = ALERT_TEXTS.get(cat, (cat, "Подозрительная активность"))
                    alerts.append({
                        "host": ip,
                        "category": cat,
                        "category_ru": title,
                        "severity": sev,
                        "severity_ru": SEVERITY_RU[sev],
                        "title": title,
                        "detail": f"{base}. Сигналов: {cnt}.",
                        "evidence": h.evidence.get(cat, [])[:5],
                        "ts": h.last_ts or h.first_ts or (self.start_ts or 0),
                    })
            alerts.sort(key=lambda a: a["ts"])
            for i, a in enumerate(alerts):
                a["id"] = i + 1
            alerts = alerts[-MAX_ALERTS:]

            detail = {}
            for ip, h in self.hosts.items():
                conns = []
                for c in sorted(h.connections, key=lambda c: -c.packets)[:100]:
                    conns.append({
                        "dst": c.dst,
                        "dport": c.dport,
                        "proto": c.proto,
                        "packets": c.packets,
                        "bytes_out": c.bytes_out,
                        "bytes_in": c.bytes_in,
                        "first_ts": c.first_ts,
                        "last_ts": c.last_ts,
                        "cats": sorted(c.cats),
                    })
                timeline = [[b * 10 + (self.start_ts or 0), v[1]]
                            for b, v in sorted(h.buckets.items()) if v[1] > 0]
                detail[ip] = {
                    "connections": conns,
                    "dns_domains": sorted(h.dns_domains)[:50],
                    "timeline": timeline,
                    "alerts": [a for a in alerts if a["host"] == ip],
                }

            categories = Counter(a["category"] for a in alerts)
            top_talkers = sorted(
                ({"ip": ip, "bytes": h.bytes_out + h.bytes_in}
                 for ip, h in self.hosts.items() if h.packets),
                key=lambda x: -x["bytes"])[:10]

            timeline = [[b * 10 + (self.start_ts or 0), cnt]
                        for b, cnt in sorted(self.alert_buckets.items())]

            return {
                "meta": {
                    "packets": self.packets,
                    "bytes": self.bytes_total,
                    "start_ts": self.start_ts,
                    "end_ts": self.end_ts,
                    "duration": ((self.end_ts - self.start_ts)
                                 if self.start_ts and self.end_ts else 0),
                },
                "stats": {
                    "protos": dict(self.proto_counts),
                    "categories": dict(categories),
                    "alerts_timeline": timeline,
                    "top_talkers": top_talkers,
                    "hosts_count": len(hosts_out),
                    "alerts_count": len(alerts),
                    "critical_count": sum(
                        1 for a in alerts if a["severity"] == SEVERITY_CRITICAL),
                },
                "hosts": hosts_out,
                "alerts": alerts,
                "detail": detail,
            }
