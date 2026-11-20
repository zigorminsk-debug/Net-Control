# -*- coding: utf-8 -*-
"""HTTP-сервер Net-Control: статический HTML-интерфейс + REST-API.

API:
  GET  /api/status          — состояние приложения
  GET  /api/stats           — сводка по текущему результату
  GET  /api/hosts           — список хостов
  GET  /api/hosts/<ip>      — детали хоста
  GET  /api/alerts          — список тревог (?category=&severity=&host=)
  GET  /api/settings        — текущие настройки порогов
  POST /api/settings        — обновить настройки
  GET  /api/signatures      — используемые сигнатуры
  GET  /api/interfaces      — список интерфейсов (Windows + Npcap)
  POST /api/analyze         — загрузить pcap-файл (raw body)
  POST /api/demo            — демо-анализ
  POST /api/capture/start   — начать живой захват {"interface": "..."}
  POST /api/capture/stop    — остановить захват
"""
from __future__ import annotations

import json
import mimetypes
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .analyzer import AnalysisEngine, parse_pcap_bytes
from .capture import CaptureManager, CaptureError, get_interfaces, IS_WINDOWS
from .demo_gen import build_demo_pcap
from .signatures import DEFAULT_SETTINGS
from .storage import save_result, load_result

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")


class NetControlApp:
    def __init__(self):
        self.engine = AnalysisEngine()
        self.result: dict | None = None
        self.mode = "idle"          # idle | file | demo | capture
        self.capture = CaptureManager(
            on_packet=self._on_capture_packet,
            on_tick=self._on_capture_tick)
        self.settings = dict(DEFAULT_SETTINGS)
        self.capture_count = 0
        self.capture_error = ""
        self._finalize_accum = 0
        self._load_saved()

    # ------------------------------------------------------------------
    def _load_saved(self):
        saved = load_result()
        if saved:
            self.result = saved
            self.mode = saved.get("meta", {}).get("mode", "file")

    # ------------------------------------------------------------------
    def _on_capture_packet(self, pkt):
        self.engine.process_packet(pkt)

    def _on_capture_tick(self, n):
        if n < 0:
            self.capture_error = self.capture.last_error
            self.mode = "idle"
            self._stop_capture_locked()
            return
        self.capture_count += n
        self._finalize_accum += n
        if self._finalize_accum >= 300:
            self.engine.finalize()
            self._finalize_accum = 0

    # ------------------------------------------------------------------
    def _stop_capture_locked(self):
        if self.capture.is_running():
            self.capture.stop()

    # ------------------------------------------------------------------
    def _analyze_bytes(self, data: bytes, mode: str) -> dict:
        self.engine.reset()
        self.engine.settings.update(self.settings)
        for pkt in parse_pcap_bytes(data):
            self.engine.process_packet(pkt)
        self.engine.finalize()
        result = self.engine.build_result()
        result["meta"]["mode"] = mode
        self.result = result
        self.mode = mode
        self.capture_count = 0
        save_result(result)
        return result

    def analyze_file(self, data: bytes) -> dict:
        if len(data) == 0:
            raise ValueError("Загруженный файл пуст.")
        return self._analyze_bytes(data, "file")

    def analyze_demo(self) -> dict:
        return self._analyze_bytes(build_demo_pcap(), "demo")

    def start_capture(self, interface: str) -> dict:
        if self.capture.is_running():
            self._stop_capture_locked()
        self.engine.reset()
        self.engine.settings.update(self.settings)
        self.capture.start(interface)
        self.mode = "capture"
        self.capture_count = 0
        self.capture_error = ""
        self.result = None
        return {"ok": True, "interface": interface}

    def stop_capture(self) -> dict:
        self._stop_capture_locked()
        if self.mode == "capture":
            self.engine.finalize()
            if self.engine.packets:
                self.result = self.engine.build_result()
                self.result["meta"]["mode"] = "capture"
                save_result(self.result)
        self.mode = "idle"
        return {"ok": True, "captured": self.capture_count}

    # ------------------------------------------------------------------
    def status(self) -> dict:
        stats = self.result.get("stats", {}) if self.result else {}
        return {
            "mode": self.mode,
            "running": self.capture.is_running(),
            "capture_count": self.capture_count,
            "capture_error": self.capture_error,
            "has_result": self.result is not None,
            "packets": stats.get("hosts_count", 0),
            "alerts": stats.get("alerts_count", 0),
            "windows_capture": IS_WINDOWS,
        }


def _make_handler(app: NetControlApp):
    class Handler(BaseHTTPRequestHandler):
        server_version = "NetControl/1.0"

        # -- вспомогательные методы --------------------------------
        def _send_json(self, obj, code=200):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _send_error_json(self, msg, code=400):
            self._send_json({"error": msg}, code)

        def _send_file(self, path: str):
            try:
                with open(path, "rb") as f:
                    body = f.read()
            except OSError:
                self._send_error_json("Файл не найден: " + path, 404)
                return
            ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript",):
                ctype += "; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _read_body(self) -> bytes:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > 1024 * 1024 * 1024:
                return b""
            return self.rfile.read(length)

        def log_message(self, fmt, *args):  # подавляем шум логов
            pass

        # -- маршрутизация -----------------------------------------
        def do_GET(self):
            path = self.path.split("?", 1)[0]
            try:
                if path == "/" or path == "/index.html":
                    self._send_file(os.path.join(WEB_DIR, "index.html"))
                elif path == "/api/status":
                    self._send_json(app.status())
                elif path == "/api/stats":
                    if not app.result:
                        self._send_json({"meta": {"mode": app.mode}})
                        return
                    self._send_json({
                        "meta": app.result["meta"],
                        "stats": app.result["stats"],
                    })
                elif path == "/api/hosts":
                    if not app.result:
                        self._send_json({"hosts": []})
                        return
                    self._send_json({"hosts": app.result["hosts"]})
                elif path.startswith("/api/hosts/"):
                    if not app.result:
                        self._send_error_json("Нет данных анализа", 404)
                        return
                    ip = path[len("/api/hosts/"):]
                    detail = app.result["detail"].get(ip)
                    if detail is None:
                        self._send_error_json("Хост не найден: " + ip, 404)
                        return
                    self._send_json({"ip": ip, "detail": detail})
                elif path == "/api/alerts":
                    if not app.result:
                        self._send_json({"alerts": []})
                        return
                    q = {}
                    if "?" in self.path:
                        for pair in self.path.split("?", 1)[1].split("&"):
                            if "=" in pair:
                                k, v = pair.split("=", 1)
                                q[k] = v
                    alerts = app.result["alerts"]
                    if q.get("category"):
                        alerts = [a for a in alerts
                                  if a["category"] == q["category"]]
                    if q.get("severity"):
                        alerts = [a for a in alerts
                                  if a["severity"] == q["severity"]]
                    if q.get("host"):
                        alerts = [a for a in alerts if a["host"] == q["host"]]
                    self._send_json({"alerts": alerts})
                elif path == "/api/settings":
                    self._send_json({"settings": app.settings})
                elif path == "/api/signatures":
                    from .analyzer import (ALERT_TEXTS, DEFAULT_SEVERITY,
                                           WEIGHTS)
                    self._send_json({
                        "alert_texts": ALERT_TEXTS,
                        "weights": WEIGHTS,
                        "default_severity": DEFAULT_SEVERITY,
                    })
                elif path == "/api/interfaces":
                    try:
                        names = get_interfaces()
                        self._send_json({"interfaces": names, "ok": True})
                    except CaptureError as e:
                        self._send_json({"interfaces": [],
                                         "ok": False, "error": str(e)})
                else:
                    self._send_error_json("Неизвестный путь: " + path, 404)
            except (ValueError, OSError) as e:
                self._send_error_json(str(e), 400)

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            try:
                if path == "/api/analyze":
                    body = self._read_body()
                    result = app.analyze_file(body)
                    self._send_json({"ok": True,
                                     "meta": result["meta"],
                                     "stats": result["stats"]})
                elif path == "/api/demo":
                    result = app.analyze_demo()
                    self._send_json({"ok": True,
                                     "meta": result["meta"],
                                     "stats": result["stats"]})
                elif path == "/api/capture/start":
                    data = json.loads(self._read_body() or b"{}")
                    interface = str(data.get("interface", "")).strip()
                    if not interface:
                        self._send_error_json("Не выбран интерфейс захвата.")
                        return
                    try:
                        app.start_capture(interface)
                        self._send_json({"ok": True, "interface": interface})
                    except CaptureError as e:
                        self._send_error_json(str(e), 400)
                elif path == "/api/capture/stop":
                    self._send_json(app.stop_capture())
                elif path == "/api/settings":
                    data = json.loads(self._read_body() or b"{}")
                    for k, v in data.items():
                        if k in app.settings:
                            try:
                                app.settings[k] = int(v)
                            except (TypeError, ValueError):
                                pass
                    app.engine.settings.update(app.settings)
                    self._send_json({"ok": True, "settings": app.settings})
                else:
                    self._send_error_json("Неизвестный путь: " + path, 404)
            except ValueError as e:
                self._send_error_json(str(e), 400)
            except Exception as e:
                self._send_error_json(f"Внутренняя ошибка: {e}", 500)

    return Handler


def create_server(host: str = "127.0.0.1", port: int = 8123):
    """Создать и запустить сервер в отдельном потоке.

    Вернуть (server, actual_port). Если порт занят — пробуем +1..+20.
    """
    app = NetControlApp()
    for try_port in range(port, port + 21):
        try:
            server = ThreadingHTTPServer((host, try_port),
                                         _make_handler(app))
        except OSError:
            continue
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        server.app = app
        return server, try_port
    raise OSError(f"Не удалось занять порт на основе {port} (все заняты).")
