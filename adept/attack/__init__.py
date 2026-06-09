"""Attack-simulation package: Atomic Red Team (propose-only) and Caldera.

ADEPT proposes (never executes) Atomic Red Team tests and may launch Caldera
operations only behind the agent's human-approval gate. Heavy parsing and HTTP
work lives in :mod:`adept.attack.atomic` and :mod:`adept.attack.caldera`.
"""

from __future__ import annotations

from adept.attack.atomic import AtomicLibrary
from adept.attack.caldera import CalderaClient
from adept.attack.models import (
    AtomicArgument,
    AtomicExecutor,
    AtomicListing,
    AtomicTestPlan,
    AtomicTestSummary,
    CalderaAdversary,
    CalderaAgent,
    CalderaOperationReport,
    CalderaOperationSummary,
)
from adept.attack.service import AttackService

__all__ = [
    "AtomicArgument",
    "AtomicExecutor",
    "AtomicLibrary",
    "AtomicListing",
    "AtomicTestPlan",
    "AtomicTestSummary",
    "AttackService",
    "CalderaAdversary",
    "CalderaAgent",
    "CalderaClient",
    "CalderaOperationReport",
    "CalderaOperationSummary",
]
