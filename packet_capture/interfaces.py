"""
Interfaces (abstract contracts) for the Packet Capture Engine.

Future modules — Rule Engine, Flow Analyzer, Database Layer — will implement
PacketHandler and register themselves with the CaptureEngine. The capture
engine never needs to know what a handler does with a packet; this is what
keeps the module boundary clean (dependency inversion).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from .models import PacketData


class PacketHandler(ABC):
    """Anything that wants to receive parsed packets implements this."""

    @abstractmethod
    def handle(self, packet: PacketData) -> None:
        """Called once per captured, parsed packet."""
        raise NotImplementedError
