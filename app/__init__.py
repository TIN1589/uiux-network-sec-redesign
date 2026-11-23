"""Lazy public package interface for the SOC Command Center backend.

Keeping ``app.main`` lazy lets account-management tooling import the auth store
without booting the web application or requiring the web process secret.
"""

from importlib import import_module
from typing import Any

__all__ = [
    "AUDIT_LOGS",
    "NETWORK_MITRE_TECHNIQUES",
    "alert_observed_to_utc_iso",
    "alerts_store",
    "app",
    "compute_overview_stats",
    "deduplicate_composite_alerts",
    "filter_alerts",
    "get_incident_timeline",
    "scenarios_store",
]


def __getattr__(name: str) -> Any:
    """Load web application exports only when a caller actually requests one."""
    if name not in __all__:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    main_module = import_module(".main", __name__)
    value = getattr(main_module, name)
    globals()[name] = value
    return value
