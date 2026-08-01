"""
Interfaces for the Rule Engine.

Mirrors packet_capture.interfaces.PacketHandler: future stages (Alert Engine,
Notification System, Database Layer) implement AlertHandler and register with
the RuleEngine, without the RuleEngine ever needing to know what happens to
an Alert after it's raised.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from .models import Alert


class AlertHandler(ABC):
    """Anything that wants to receive raised alerts implements this."""

    @abstractmethod
    def handle(self, alert: Alert) -> None:
        raise NotImplementedError
