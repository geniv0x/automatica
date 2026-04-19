"""Base class for all recon modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.target import Target

from core.logger import Logger


class BaseModule(ABC):
    """
    Every module inherits from this.
    Implement run() with your logic.
    """

    def __init__(self):
        self.log = Logger()

    @property
    @abstractmethod
    def name(self) -> str:
        """Module name for logging."""
        ...

    @abstractmethod
    def run(self, target: Target) -> None:
        """Execute module logic against target."""
        ...
