"""
Cisco Catalyst Center Health Monitor Package

A modular package for monitoring and reporting on Cisco Catalyst Center health.
"""

from .client import CatalystCenterClient
from .ai_analyzer import AIHealthAnalyzer
from .webex_notifier import WebexNotifier
from .report_generator import HealthReportGenerator
from .config import (
    CATALYST_CENTER_CONFIG,
    AI_CONFIG,
    API_ENDPOINTS,
    HEALTH_FILTERS,
    validate_config,
    load_configuration
)
from .utils import categorize_health
from .api_adapter import APIFieldAdapter

__version__ = "1.0.0"
__all__ = [
    "CatalystCenterClient",
    "AIHealthAnalyzer",
    "WebexNotifier",
    "HealthReportGenerator",
    "CATALYST_CENTER_CONFIG",
    "AI_CONFIG",
    "API_ENDPOINTS",
    "HEALTH_FILTERS",
    "validate_config",
    "load_configuration",
    "categorize_health",
    "APIFieldAdapter",
]
