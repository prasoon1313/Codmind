"""Small, clean helpers."""
from __future__ import annotations


def clamp(value: float, low: float, high: float) -> float:
    """Limit value to [low, high]."""
    return max(low, min(high, value))
