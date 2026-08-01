"""
Interfaces for the Flow Analyzer.

Same pattern as packet_capture.PacketHandler and rule_engine.AlertHandler:
future stages (Detection Engine, Database Layer, Dashboard) implement
FlowEventHandler and register with the FlowAnalyzer, without the analyzer
needing to know what happens to a FlowAnomaly afterwards.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from .models import FlowAnomaly


class FlowEventHandler(ABC):
    @abstractmethod
    def handle(self, anomaly: FlowAnomaly) -> None:
        raise NotImplementedError
