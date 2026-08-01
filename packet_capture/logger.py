"""Centralized logger setup for the Packet Capture Engine."""

from __future__ import annotations

import logging
import sys


def get_logger(name: str = "ids.packet_capture") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        # Avoid duplicate handlers if get_logger() is called more than once
        return logger

    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger
