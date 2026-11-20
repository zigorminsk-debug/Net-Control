# -*- coding: utf-8 -*-
"""Живой захват трафика (только Windows с Npcap).

Использует DLL wpcap.dll / Packet.dll через ctypes — без внешних
зависимостей. На других платформах выдаёт понятную ошибку.
"""
from __future__ import annotations

import ctypes
import platform
import queue
import threading
import time

IS_WINDOWS = platform.system() == "Windows"


class CaptureError(Exception):
    pass


_lib = None
_pcap_if = None


def _load():
    global _lib, _pcap_if
    if _lib is not None:
        return _lib
    if not IS_WINDOWS:
        raise CaptureError("Живой захват поддерживается только на Windows "
                           "(требуется Npcap). На других платформах используйте "
                           "анализ pcap-файлов или демо-анализ.")
    for name in ("wpcap.dll", "Packet.dll"):
        try:
            lib = ctypes.WinDLL(name)
            break
        except OSError as e:
            raise CaptureError(
                "Не найдена Npcap. Установите Npcap "
                "(https://npcap.com) с галочкой «Install Npcap in WinPcap "
                "API-compatible Mode».") from e
    else:
        raise CaptureError("Не найдена wpcap.dll / Packet.dll (Npcap).")

    class pcap_if(ctypes.Structure):
        pass
    pcap_if._fields_ = [
        ("addresses", ctypes.c_void_p),
        ("flags", ctypes.c_uint),
        ("name", ctypes.c_char_p),
        ("description", ctypes.c_char_p),
        ("next", ctypes.POINTER(pcap_if)),
    ]
    _pcap_if = pcap_if

    lib.pcap_findalldevs.restype = ctypes.c_int
    lib.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(pcap_if))]
    lib.pcap_open_live.restype = ctypes.c_void_p
    lib.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int,
                                   ctypes.c_int, ctypes.c_int,
                                   ctypes.c_char_p]
    lib.pcap_close.argtypes = [ctypes.c_void_p]
    lib.pcap_dispatch.restype = ctypes.c_int
    lib.pcap_dispatch.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                  ctypes.c_void_p, ctypes.c_void_p]
    lib.pcap_geterr.restype = ctypes.c_char_p
    lib.pcap_geterr.argtypes = [ctypes.c_void_p]
    lib.pcap_statustostr.restype = ctypes.c_char_p
    lib.pcap_statustostr.argtypes = [ctypes.c_int]
    _lib = lib
    return lib


def get_interfaces() -> list:
    """Список сетевых интерфейсов (только Windows с Npcap)."""
    lib = _load()
    head = ctypes.POINTER(_pcap_if)()
    rc = lib.pcap_findalldevs(ctypes.byref(head))
    if rc != 0:
        raise CaptureError("Не удалось получить список интерфейсов Npcap.")
    names = []
    cur = head
    try:
        while cur:
            inst = ctypes.cast(cur, ctypes.POINTER(_pcap_if)).contents
            if inst.name:
                names.append(inst.name.decode("utf-8", "ignore"))
            cur = inst.next
    finally:
        lib.pcap_freealldevs(head)
    return names


_CBPACKET = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p,
                             ctypes.c_void_p, ctypes.c_void_p)


def _packet_cb(user, pkt_ptr, hdr_ptr):
    try:
        # pcap_pkthdr: tv_sec, tv_usec, caplen, len (8 + 4 + 4 на Windows)
        caplen = ctypes.c_uint.from_address(
            ctypes.cast(hdr_ptr, ctypes.c_void_p)
            + ctypes.sizeof(ctypes.c_long) * 2).value
        if caplen <= 0 or caplen > 0x4000000:
            return 0
        data = ctypes.string_at(pkt_ptr, caplen)
        _CAPTURE_QUEUE.put_nowait((time.time(), data))
    except Exception:
        pass
    return 0


_CAPTURE_QUEUE: "queue.Queue" = queue.Queue(maxsize=5000)


class CaptureManager:
    """Фоновый захват пакетов с интерфейса Npcap."""

    def __init__(self, on_packet, on_tick=None):
        self.on_packet = on_packet
        self.on_tick = on_tick
        self._handle = None
        self._thread = None
        self._stop = threading.Event()
        self._cb = _CBPACKET(_packet_cb)
        self.linktype = 1  # Ethernet
        self.count = 0
        self.last_error = ""

    def start(self, interface: str) -> None:
        if self._thread is not None and self._thread.is_alive():
            raise CaptureError("Захват уже запущен.")
        lib = _load()
        err = ctypes.create_string_buffer(256)
        name = interface.encode("utf-8")
        self._handle = lib.pcap_open_live(name, 65536, 1, 1000, err)
        if not self._handle:
            msg = err.value.decode("utf-8", "ignore")
            self.last_error = msg
            raise CaptureError(f"Не удалось открыть интерфейс «{interface}»: {msg}")
        self._stop.clear()
        self.count = 0
        _CAPTURE_QUEUE.queue.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        lib = _lib
        try:
            while not self._stop.is_set():
                rc = lib.pcap_dispatch(self._handle, -1,
                                       ctypes.cast(self._cb, ctypes.c_void_p),
                                       None)
                if rc < 0:
                    self.last_error = lib.pcap_geterr(self._handle).decode(
                        "utf-8", "ignore")
                    raise CaptureError(f"Ошибка захвата: {self.last_error}")
                # выкачиваем очередь пакетов
                drained = 0
                while drained < 200:
                    try:
                        ts, data = _CAPTURE_QUEUE.get_nowait()
                    except queue.Empty:
                        break
                    pkt = parse_record_local(data, self.linktype, ts)
                    if pkt is not None:
                        self.on_packet(pkt)
                    drained += 1
                self.count += drained
                if drained and self.on_tick:
                    self.on_tick(drained)
        except CaptureError as e:
            self.last_error = str(e)
            if self.on_tick:
                self.on_tick(-1)
        finally:
            try:
                lib.pcap_close(self._handle)
            except Exception:
                pass
            self._handle = None

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()


def parse_record_local(data: bytes, linktype: int, ts: float):
    """Альтернатива import'у analyzer — чтобы не циклически зависеть."""
    from .analyzer import parse_record
    return parse_record(data, linktype, ts)
