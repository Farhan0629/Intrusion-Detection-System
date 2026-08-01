"""
Capture Engine.

Wraps Scapy's sniff() in a controllable, restartable object that dispatches
normalized PacketData to any number of registered PacketHandlers. This is the
only file in the module that touches a live interface — everything else
(parsing, models, config) is pure and independently testable.

Windows note: requires Npcap installed (https://npcap.com/) with
"WinPcap API-compatible mode" checked. Run as Administrator to capture.
"""

from __future__ import annotations

import threading
from typing import Optional

import sys

from scapy.all import sniff  # noqa: E402  (Scapy's import side-effects are heavy; kept local to this module)
from scapy.packet import Packet

from .config import CaptureConfig
from .interfaces import PacketHandler
from .logger import get_logger
from .packet_parser import parse_packet

logger = get_logger(__name__)


class CaptureEngine:
    """Starts/stops a packet capture session and fans out parsed packets."""

    def __init__(self, config: Optional[CaptureConfig] = None) -> None:
        self.config = config or CaptureConfig()
        self._handlers: list[PacketHandler] = []
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._packets_seen = 0
        self._packets_parsed = 0

    def register_handler(self, handler: PacketHandler) -> None:
        """Attach a downstream consumer (Rule Engine, Flow Analyzer, DB writer, ...)."""
        self._handlers.append(handler)
        logger.info("Registered handler: %s", type(handler).__name__)

    def _on_packet(self, pkt: Packet) -> None:
        self._packets_seen += 1
        try:
            data = parse_packet(pkt, store_raw_summary=self.config.store_raw_summary)
        except Exception:
            logger.exception("Failed to parse a captured packet; skipping it")
            return

        if data is None:
            return

        if data.protocol.value not in self.config.protocols_enabled:
            return

        self._packets_parsed += 1
        for handler in self._handlers:
            try:
                handler.handle(data)
            except Exception:
                logger.exception("Handler %s raised while processing a packet", type(handler).__name__)

    def _stop_filter(self, _pkt: Packet) -> bool:
        # Scapy calls this after every packet; returning True stops the sniff loop.
        return self._stop_event.is_set()

    def start(self, blocking: bool = True) -> None:
        """
        Start capturing. If blocking=False, capture runs on a background
        thread and start() returns immediately; call stop() to end it.
        """
        if self._thread is not None and self._thread.is_alive():
            logger.warning("Capture already running; ignoring start() call")
            return

        self._stop_event.clear()
        logger.info(
            "Starting capture | interface=%s filter='%s' count=%s timeout=%s",
            self.config.interface or "<default>",
            self.config.bpf_filter,
            self.config.packet_count or "unlimited",
            self.config.timeout or "none",
        )

        def _run() -> None:
            # On Windows + Npcap, the loopback adapter (127.0.0.1 <-> 127.0.0.1)
            # doesn't show up in get_if_list() until route_add_loopback() is
            # called. Without it, sniff() silently sees zero packets on a
            # localhost-only IDS test. This is the documented Scapy
            # workaround; on non-Windows platforms it's a no-op.
            # See: https://scapy.readthedocs.io/en/latest/troubleshooting.html
            if sys.platform == "win32":
                try:
                    from scapy.all import route_add_loopback
                    route_add_loopback()
                except Exception:
                    logger.debug("route_add_loopback() unavailable; skipping", exc_info=True)

            sniff(
                iface=self.config.interface,
                filter=self.config.bpf_filter,
                prn=self._on_packet,
                store=False,
                count=self.config.packet_count or 0,
                timeout=self.config.timeout,
                stop_filter=self._stop_filter,
            )
            logger.info(
                "Capture stopped | packets_seen=%d packets_parsed=%d",
                self._packets_seen,
                self._packets_parsed,
            )

        if blocking:
            _run()
        else:
            self._thread = threading.Thread(target=_run, daemon=True, name="ids-capture-thread")
            self._thread.start()

    def stop(self) -> None:
        """Signal the capture loop to stop. Safe to call even if not running."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        logger.info("Stop requested")

    @property
    def stats(self) -> dict:
        return {"packets_seen": self._packets_seen, "packets_parsed": self._packets_parsed}
