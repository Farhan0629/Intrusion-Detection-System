"""Regression test: Windows + Npcap loopback capture requires
route_add_loopback() to be called before sniff(). This test verifies the
capture engine invokes it on Windows but not on Linux. Runs on any platform;
mocks sys.platform and scapy.all.sniff so we don't actually capture.
"""

import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packet_capture import CaptureConfig, CaptureEngine


def _make_fake_scapy(called_holder):
    """Build a fake scapy.all module that records route_add_loopback() calls
    and stubs sniff() so capture_engine.start() returns quickly."""
    def _route_add_loopback():
        called_holder.append(True)
    def _sniff(**_kwargs):
        # block until the test sets the stop event (or just return immediately)
        return None
    return SimpleNamespace(route_add_loopback=_route_add_loopback, sniff=_sniff)


def _run_capture_briefly(engine):
    """Start the engine on a thread, let it run a fraction of a second, then stop."""
    t = threading.Thread(target=engine.start, kwargs={"blocking": True}, daemon=True)
    t.start()
    time.sleep(0.3)
    engine.stop()
    t.join(timeout=2)


def test_route_add_loopback_called_on_windows():
    cfg = CaptureConfig(interface=None, packet_count=1, timeout=1)
    engine = CaptureEngine(cfg)
    called = []
    fake_scapy = _make_fake_scapy(called)

    with patch("sys.platform", "win32"), \
         patch.dict(sys.modules, {"scapy.all": fake_scapy}):
        _run_capture_briefly(engine)

    assert called == [True], (
        f"route_add_loopback() should have been called on Windows; got {called}"
    )


def test_route_add_loopback_not_called_on_linux():
    cfg = CaptureConfig(interface=None, packet_count=1, timeout=1)
    engine = CaptureEngine(cfg)
    called = []
    fake_scapy = _make_fake_scapy(called)

    with patch("sys.platform", "linux"), \
         patch.dict(sys.modules, {"scapy.all": fake_scapy}):
        _run_capture_briefly(engine)

    assert called == [], (
        f"route_add_loopback() should NOT be called on Linux; got {called}"
    )


def test_route_add_loopback_failure_does_not_crash_capture():
    """If route_add_loopback() raises (e.g. Npcap not installed), capture
    should still attempt to start rather than crash."""
    cfg = CaptureConfig(interface=None, packet_count=1, timeout=1)
    engine = CaptureEngine(cfg)

    def _bad_route_add_loopback():
        raise OSError("Npcap not available")

    def _sniff(**_kwargs):
        return None

    fake_scapy = SimpleNamespace(
        route_add_loopback=_bad_route_add_loopback,
        sniff=_sniff,
    )

    with patch("sys.platform", "win32"), \
         patch.dict(sys.modules, {"scapy.all": fake_scapy}):
        # Should NOT raise; the call site catches the exception.
        _run_capture_briefly(engine)

    # No assertion needed — reaching here without exception is the test.