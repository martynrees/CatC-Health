"""
Configuration module for Catalyst Center Health Monitor

This module handles all configuration loading, validation, and management.
"""

import os
import logging
from typing import Dict, List, Tuple, Any
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration
CATALYST_CENTER_CONFIG = {
    "base_url": os.getenv("CATALYST_CENTER_URL", "https://your-catalyst-center.example.com"),
    "username": os.getenv("CATALYST_CENTER_USERNAME", "your_username"),
    "password": os.getenv("CATALYST_CENTER_PASSWORD", "your_password"),
    "verify_ssl": os.getenv("VERIFY_SSL", "false").lower() == "true",
    "timeout": int(os.getenv("REQUEST_TIMEOUT", "30"))
}

# AI and Webex Configuration
AI_CONFIG = {
    "openai_api_key": os.getenv("OPENAI_API_KEY"),
    "webex_token": os.getenv("WEBEX_BOT_TOKEN"),
    "webex_space_id": os.getenv("WEBEX_SPACE_ID"),
    "model_name": "gpt-4o-mini",
    "system_prompt": """You are a network operations manager reviewing daily infrastructure health. Create a summary that serves both technical teams and leadership:

**🚨 URGENT ISSUES (Next 4 Hours):**
List critical problems with immediate business impact, specific devices affected, and initial response actions.

**⚠️ OPERATIONAL CONCERNS (Today/This Week):**
Performance degradation, trending issues, and proactive maintenance needs with priority levels.

**📊 INFRASTRUCTURE HEALTH:**
Overall network stability, key metrics trends, and capacity utilization summary.

**💼 BUSINESS IMPACT:**
How current issues affect user experience, application performance, and operational efficiency.

**🔧 RECOMMENDED ACTIONS:**
Prioritized action items with owners, timeframes, and success criteria. Focus on both immediate fixes and longer-term improvements."""
}

# API Endpoints
API_ENDPOINTS = {
    "auth": "/dna/system/api/v1/auth/token",
    "device_health": "/dna/intent/api/v1/device-health",
    "network_devices": "/dna/data/api/v1/networkDevices",
    "assurance_issues": "/dna/data/api/v1/assuranceIssues",
    "intent_issues": "/dna/intent/api/v1/issues",
    "sites": "/dna/intent/api/v1/sites",
    "fabric_sites": "/dna/intent/api/v1/sda/fabricSites",
    "fabric_site_health": "/dna/data/api/v1/fabricSiteHealthSummaries",
    "application_health": "/dna/intent/api/v1/application-health",
    "network_applications": "/dna/data/api/v1/networkApplications",
    "client_health": "/dna/intent/api/v1/client-health",
    "clients": "/dna/data/api/v1/clients",
    # Internal API Endpoints
    "ise_health": "/api/v1/system/health/cisco-ise",
    "maglev_services": "/api/system/v1/maglev/services/summary",
    "system_backup": "/api/system/v1/maglev/backup",
    "backup_history": "/api/system/v1/maglev/backup/history",
    "system_updates": "/api/system/v1/systemupdater/common/availabe_update_info"
}

# Health score mapping for filtering
HEALTH_FILTERS = {
    "poor": "POOR",
    "fair": "FAIR",
    "good": "GOOD"
}


def validate_config() -> Tuple[bool, List[str]]:
    """Validate configuration before running the health monitor
    
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []
    
    # Check if .env file exists
    if not os.path.exists('.env'):
        errors.append("Configuration Error: .env file not found")
        errors.append("Please copy .env.example to .env and configure your settings")
        return False, errors
    
    # Validate required Catalyst Center configuration
    required_fields = [
        ("CATALYST_CENTER_URL", CATALYST_CENTER_CONFIG["base_url"], "https://your-catalyst-center.example.com"),
        ("CATALYST_CENTER_USERNAME", CATALYST_CENTER_CONFIG["username"], "your_username"),
        ("CATALYST_CENTER_PASSWORD", CATALYST_CENTER_CONFIG["password"], "your_password")
    ]
    
    for field_name, field_value, default_value in required_fields:
        if not field_value or field_value == default_value:
            errors.append(f"Missing or invalid configuration: {field_name}")
    
    # Validate AI configuration if AI features are requested
    # (Will be checked in main() based on --ai-summary flag)
    
    # Validate URL format
    if CATALYST_CENTER_CONFIG["base_url"] and not CATALYST_CENTER_CONFIG["base_url"].startswith(("http://", "https://")):
        errors.append("CATALYST_CENTER_URL must start with http:// or https://")
    
    # Validate timeout is a positive number
    if CATALYST_CENTER_CONFIG["timeout"] <= 0:
        errors.append("REQUEST_TIMEOUT must be a positive number")
    
    if errors:
        return False, errors
    
    return True, []


def load_configuration() -> Dict[str, Any]:
    """Load and return all configuration
    
    Returns:
        Dictionary containing all configuration data
    """
    return {
        "catalyst_center": CATALYST_CENTER_CONFIG,
        "ai": AI_CONFIG,
        "api_endpoints": API_ENDPOINTS,
        "health_filters": HEALTH_FILTERS
    }
